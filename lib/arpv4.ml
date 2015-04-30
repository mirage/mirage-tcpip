(*
 * Copyright (c) 2010-2011 Anil Madhavapeddy <anil@recoil.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *)

open Lwt
open Printf

module Make (Ethif : V1_LWT.ETHIF) (Clock : V1.CLOCK) (Time : V1_LWT.TIME) = struct

  type arp = {
    op: [ `Request |`Reply |`Unknown of int ];
    sha: Macaddr.t;
    spa: Ipaddr.V4.t;
    tha: Macaddr.t;
    tpa: Ipaddr.V4.t;
  }

  (* TODO implement the full ARP state machine (pending, failed, timer thread, etc) *)

  type result = [ `Ok of Macaddr.t | `Timeout ]

  type entry =
    | Pending of result Lwt.t * result Lwt.u
    | Confirmed of float * Macaddr.t

  type t = {
    ethif : Ethif.t;
    cache: (Ipaddr.V4.t, entry) Hashtbl.t;
    mutable bound_ips: Ipaddr.V4.t list;
  }

  cstruct arp {
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t ethertype;
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t op;
    uint8_t sha[6];
    uint32_t spa;
    uint8_t tha[6];
    uint32_t tpa
  } as big_endian

  cenum op {
    Op_request = 1;
    Op_reply
  } as uint16_t

  let arp_timeout = 60. (* age entries out of cache after this many seconds *)
  let probe_repeat_delay = 1.5 (* per rfc5227, 2s >= probe_repeat_delay >= 1s *)
  let probe_num = 3 (* how many probes to send before giving up *)

  let rec tick t () =
    let now = Clock.time () in
    let expired = Hashtbl.fold (fun ip entry expired ->
        match entry with
        | Pending _ -> expired
        | Confirmed (t, _) -> if t >= now then ip :: expired else expired) t.cache []
    in
    List.iter (fun ip -> printf "ARP: timeout %s\n%!" (Ipaddr.V4.to_string ip)) expired;
    List.iter (Hashtbl.remove t.cache) expired;
    Time.sleep arp_timeout >>= tick t

  (* Prettyprint cache contents *)
  let prettyprint t =
    printf "ARP info:\n";
    Hashtbl.iter (fun ip entry ->
        printf "%s -> %s\n%!"
          (Ipaddr.V4.to_string ip)
          (match entry with
           | Pending _ -> "I"
           | Confirmed (_, mac) -> sprintf "V(%s)" (Macaddr.to_string mac)
          )
      ) t.cache

  let notify t ip mac =
    let now = Clock.time () in
    let expire = now +. arp_timeout in
    try
      match Hashtbl.find t.cache ip with
      | Pending (_, w) ->
        Hashtbl.replace t.cache ip (Confirmed (expire, mac));
        Lwt.wakeup w (`Ok mac)
      | Confirmed _ ->
        Hashtbl.replace t.cache ip (Confirmed (expire, mac))
    with
    | Not_found ->
      Hashtbl.replace t.cache ip (Confirmed (expire, mac))

  let add t ip mac = notify t ip mac

  (* Input handler for an ARP packet, registered through attach() *)
  let rec input t frame =
    MProf.Trace.label "arpv4.input";
    match get_arp_op frame with
    |1 -> (* Request *)
      (* Received ARP request, check if we can satisfy it from
         our own IPv4 list *)
      let req_ipv4 = Ipaddr.V4.of_int32 (get_arp_tpa frame) in
      (* printf "ARP: who-has %s?\n%!" (Ipaddr.V4.to_string req_ipv4); *)
      if List.mem req_ipv4 t.bound_ips then begin
        printf "ARP responding to: who-has %s?\n%!" (Ipaddr.V4.to_string req_ipv4);
        (* We own this IP, so reply with our MAC *)
        let sha = Ethif.mac t.ethif in
        let tha = Macaddr.of_bytes_exn (copy_arp_sha frame) in
        let spa = Ipaddr.V4.of_int32 (get_arp_tpa frame) in (* the requested address *)
        let tpa = Ipaddr.V4.of_int32 (get_arp_spa frame) in (* the requesting host IPv4 *)
        output t { op=`Reply; sha; tha; spa; tpa }
      end else return_unit
    |2 -> (* Reply *)
      let spa = Ipaddr.V4.of_int32 (get_arp_spa frame) in
      let sha = Macaddr.of_bytes_exn (copy_arp_sha frame) in
      printf "ARP: updating %s -> %s\n%!"
        (Ipaddr.V4.to_string spa) (Macaddr.to_string sha);
      (* If we have pending entry, notify the waiters that answer is ready *)
      notify t spa sha;
      return_unit
    |n ->
      printf "ARP: Unknown message %d ignored\n%!" n;
      return_unit

  and output t arp =
    (* Obtain a buffer to write into *)
    let buf = Io_page.to_cstruct (Io_page.get 1) in
    (* Write the ARP packet *)
    let dmac = Macaddr.to_bytes arp.tha in
    let smac = Macaddr.to_bytes arp.sha in
    let spa = Ipaddr.V4.to_int32 arp.spa in
    let tpa = Ipaddr.V4.to_int32 arp.tpa in
    let op =
      match arp.op with
      |`Request -> 1
      |`Reply -> 2
      |`Unknown n -> n
    in
    set_arp_dst dmac 0 buf;
    set_arp_src smac 0 buf;
    set_arp_ethertype buf 0x0806; (* ARP *)
    set_arp_htype buf 1;
    set_arp_ptype buf 0x0800; (* IPv4 *)
    set_arp_hlen buf 6; (* ethernet mac size *)
    set_arp_plen buf 4; (* ipv4 size *)
    set_arp_op buf op;
    set_arp_sha smac 0 buf;
    set_arp_spa buf spa;
    set_arp_tha dmac 0 buf;
    set_arp_tpa buf tpa;
    (* Resize buffer to sizeof arp packet *)
    let buf = Cstruct.sub buf 0 sizeof_arp in
    Ethif.write t.ethif buf

  (* Send a gratuitous ARP for our IP addresses *)
  let output_garp t =
    let tha = Macaddr.broadcast in
    let sha = Ethif.mac t.ethif in
    let tpa = Ipaddr.V4.any in
    Lwt_list.iter_s (fun spa ->
        printf "ARP: sending gratuitous from %s\n%!" (Ipaddr.V4.to_string spa);
        output t { op=`Reply; tha; sha; tpa; spa }
      ) t.bound_ips

  (* Send a query for a particular IP *)
  let output_probe t tpa =
    printf "ARP: transmitting probe -> %s\n%!" (Ipaddr.V4.to_string tpa);
    let tha = Macaddr.broadcast in
    let sha = Ethif.mac t.ethif in
    (* Source protocol address, pick one of our IP addresses *)
    let spa = match t.bound_ips with
      | hd::_ -> hd | [] -> Ipaddr.V4.any in
    output t { op=`Request; tha; sha; tpa; spa }

  let get_ips t = t.bound_ips

  (* Set the bound IP address list, which will xmit a GARP packet also *)
  let set_ips t ips =
    t.bound_ips <- ips;
    output_garp t

  let add_ip t ip =
    if not (List.mem ip t.bound_ips) then
      set_ips t (ip :: t.bound_ips)
    else return_unit

  let remove_ip t ip =
    if List.mem ip t.bound_ips then
      set_ips t (List.filter ((<>) ip) t.bound_ips)
    else return_unit

  (* Query the cache for an ARP entry, which may result in the sender sleeping
     waiting for a response *)
  let query t ip =
    try match Hashtbl.find t.cache ip with
      | Pending (t, _) ->
        t
      | Confirmed (_, mac) ->
        Lwt.return (`Ok mac)
    with
    | Not_found ->
      let response, waker = MProf.Trace.named_wait "ARP response" in
      (* printf "ARP query: %s -> [probe]\n%!" (Ipaddr.V4.to_string ip); *)
      Hashtbl.add t.cache ip (Pending (response, waker));
      let rec retry n () =
        (* First request, so send a query packet *)
        output_probe t ip >>= fun () ->
        Lwt.choose [ (response >>= fun _ -> Lwt.return `Ok);
                     (Time.sleep probe_repeat_delay >>= fun () -> Lwt.return `Timeout) ] >>= function
        | `Ok -> Lwt.return_unit
        | `Timeout ->
          if n < probe_num then begin
            let n = n+1 in
            printf "ARP: retrying %s (n=%d)\n%!" (Ipaddr.V4.to_string ip) n;
            retry n ()
          end else begin
            Hashtbl.remove t.cache ip;
            Lwt.wakeup waker `Timeout;
            Lwt.return_unit
          end
      in
      Lwt.async (retry 0);
      response

  let create ethif =
    let cache = Hashtbl.create 7 in
    let bound_ips = [] in
    let t = { ethif; cache; bound_ips } in
    Lwt.async (tick t);
    t
end
