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

open Lwt.Infix
open Printf

module Make (Ethif : V1_LWT.ETHIF) (Clock : V1.CLOCK) (Time : V1_LWT.TIME) = struct

  type result = [ `Ok of Macaddr.t | `Timeout ]

  type entry =
    | Pending of result Lwt.t * result Lwt.u
    | Confirmed of float * Macaddr.t

  type t = {
    ethif : Ethif.t;
    cache: (Ipaddr.V4.t, entry) Hashtbl.t;
    mutable bound_ips: Ipaddr.V4.t list;
  }

  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t
  type ipaddr = Ipaddr.V4.t
  type macaddr = Macaddr.t
  type ethif = Ethif.t
  type repr = string
  type id = t
  type error

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

  let to_repr t =
    let print ip entry acc =
      let key = Ipaddr.V4.to_string ip in
      match entry with
       | Pending _ -> acc ^ "\n" ^ key ^ " -> " ^ "Pending" 
       | Confirmed (time, mac) -> Printf.sprintf "%s\n%s -> Confirmed (%s) (expires %f)\n%!" 
                                    acc key (Macaddr.to_string mac) time
    in
    Lwt.return (Hashtbl.fold print t.cache "")

  let pp fmt repr =
    Format.fprintf fmt "%s" repr

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

  let output t arp =
    let open Arpv4_parse in
    let open Ethif_wire in
    (* Obtain a buffer to write into *)
    let buf = Io_page.(get 1 |> to_cstruct) in
    (* Write the ARP packet *)
    match Arpv4_print.print_arpv4_header ~buf:(Cstruct.shift buf sizeof_ethernet)
      ~src_ip:arp.spa ~dst_ip:arp.tpa ~src_mac:arp.sha ~dst_mac:arp.tha
      ~op:arp.op with
    | Result.Error s -> (* TODO: log an error *) Lwt.return_unit
    | Result.Ok () ->
      set_ethernet_dst (Macaddr.to_bytes arp.tha) 0 buf;
      set_ethernet_src (Macaddr.to_bytes arp.sha) 0 buf;
      set_ethernet_ethertype buf (ethertype_to_int ARP);
      (* Resize buffer to sizeof arp packet *)
      let buf = Cstruct.set_len buf (Arpv4_wire.sizeof_arp + sizeof_ethernet) in
      Ethif.write t.ethif buf

  (* Input handler for an ARP packet *)
  let input t frame =
    let open Arpv4_wire in
    MProf.Trace.label "arpv4.input";
    match Arpv4_parse.parse_arpv4_header frame with
    | Result.Error _ -> (* TODO: log an error *) Lwt.return_unit
    | Result.Ok arp ->
      match arp.op with
      | Reply -> (* Reply *)
        (* If we have pending entry, notify the waiters that answer is ready *)
        notify t arp.spa arp.sha;
        Lwt.return_unit
      | Request ->
        (* Received ARP request, check if we can satisfy it from
           our own IPv4 list *)
        match List.mem arp.tpa t.bound_ips with
        | true ->
          let open Arpv4_parse in
          (* We own this IP, so reply with our MAC *)
          let sha = Ethif.mac t.ethif in
          let tha = arp.sha in
          let spa = arp.tpa in (* the requested address *)
          let tpa = arp.spa in (* the requesting host IPv4 *)
          output t (Arpv4_wire.{ op=Reply; sha; tha; spa; tpa })
        | false -> Lwt.return_unit

  (* Send a gratuitous ARP for our IP addresses *)
  let output_garp t =
    let tha = Macaddr.broadcast in
    let sha = Ethif.mac t.ethif in
    let tpa = Ipaddr.V4.any in
    Lwt_list.iter_s (fun spa ->
        output t Arpv4_wire.({ op=Reply; tha; sha; tpa; spa })
      ) t.bound_ips

  (* Send a query for a particular IP *)
  let output_probe t tpa =
    printf "ARP: transmitting probe -> %s\n%!" (Ipaddr.V4.to_string tpa);
    let tha = Macaddr.broadcast in
    let sha = Ethif.mac t.ethif in
    (* Source protocol address, pick one of our IP addresses *)
    (* that's garbage! pick the one most likely to be on the same subnet as the
       tpa *)
    let spa = match t.bound_ips with
      | hd::_ -> hd | [] -> Ipaddr.V4.any in
    output t Arpv4_wire.({ op=Request; tha; sha; tpa; spa })

  let get_ips t = t.bound_ips

  (* Set the bound IP address list, which will xmit a GARP packet also *)
  let set_ips t ips =
    t.bound_ips <- ips;
    output_garp t

  let add_ip t ip =
    if not (List.mem ip t.bound_ips) then
      set_ips t (ip :: t.bound_ips)
    else Lwt.return_unit

  let remove_ip t ip =
    if List.mem ip t.bound_ips then
      set_ips t (List.filter ((<>) ip) t.bound_ips)
    else Lwt.return_unit

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

  let connect ethif =
    let cache = Hashtbl.create 7 in
    let bound_ips = [] in
    let t = { ethif; cache; bound_ips } in
    Lwt.async (tick t);
    Lwt.return (`Ok t)

  let disconnect t = Lwt.return_unit (* TODO: should kill tick *)
end
