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
open Result

let src = Logs.Src.create "arpv4" ~doc:"Mirage ARP module"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (Ethif : Mirage_protocols_lwt.ETHIF)
  (Clock : Mirage_clock.MCLOCK)
  (Time : Mirage_time_lwt.S) = struct

  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t
  type ipaddr = Ipaddr.V4.t
  type macaddr = Macaddr.t
  type ethif = Ethif.t
  type repr = string
  type error = Mirage_protocols.Arp.error
  let pp_error = Mirage_protocols.Arp.pp_error

  type entry =
    | Pending of (macaddr, error) result Lwt.t * (macaddr, error) result Lwt.u
    | Confirmed of int64 * Macaddr.t

  type t = {
    ethif : Ethif.t;
    clock : Clock.t;
    cache: (Ipaddr.V4.t, entry) Hashtbl.t;
    mutable bound_ips: Ipaddr.V4.t list;
  }

  let report_ethif_error s e =
    Logs.debug (fun f ->
        f "error on underlying ethernet interface when attempting to %s : %a"
          s Ethif.pp_error e)

  let arp_timeout = Duration.of_sec 60 (* age entries out of cache after this many seconds *)
  let probe_repeat_delay = Duration.of_ms 1500 (* per rfc5227, 2s >= probe_repeat_delay >= 1s *)
  let probe_num = 3 (* how many probes to send before giving up *)

  let rec tick t () =
    let now = Clock.elapsed_ns t.clock in
    let expired = Hashtbl.fold (fun ip entry expired ->
        match entry with
        | Pending _ -> expired
        | Confirmed (t, _) ->
          if Int64.compare t now > -1 then
            expired
          else begin
            Log.info (fun f -> f "ARP: timeout %a" Ipaddr.V4.pp_hum ip);
            ip :: expired
          end)
        t.cache []
    in
    List.iter (fun ip ->
        Log.info (fun f -> f "ARP: timeout %a" Ipaddr.V4.pp_hum ip);
        Hashtbl.remove t.cache ip)
      expired;
    Time.sleep_ns arp_timeout >>= tick t

  let to_repr t =
    let print ip entry acc =
      let key = Ipaddr.V4.to_string ip in
      match entry with
       | Pending _ -> acc ^ "\n" ^ key ^ " -> " ^ "Pending"
       | Confirmed (time, mac) -> Printf.sprintf "%s\n%s -> Confirmed (%s) (expires %Lu)\n%!"
                                    acc key (Macaddr.to_string mac) time
    in
    Lwt.return (Hashtbl.fold print t.cache "")

  let pp fmt repr =
    Format.fprintf fmt "%s" repr

  let notify t ip mac =
    Log.debug (fun f -> f "notifying: %a -> %s" Ipaddr.V4.pp_hum ip (Macaddr.to_string mac));
    match Ipaddr.V4.is_multicast ip || (Ipaddr.V4.compare ip Ipaddr.V4.any = 0) with
    | true -> Log.debug (fun f -> f "Ignoring ARP notification request for IP %a" Ipaddr.V4.pp_hum ip)
    | false ->
      let now = Clock.elapsed_ns t.clock in
      let expire = Int64.add now arp_timeout in
      try
        match Hashtbl.find t.cache ip with
        | Pending (_, w) ->
          Hashtbl.replace t.cache ip (Confirmed (expire, mac));
          Lwt.wakeup w (Ok mac)
        | Confirmed _ ->
          Hashtbl.replace t.cache ip (Confirmed (expire, mac))
      with
      | Not_found ->
        Hashtbl.replace t.cache ip (Confirmed (expire, mac))

  let output t ~source ~destination arp =
    let payload = Arpv4_packet.Marshal.make_cstruct arp in
    let ethif_packet = Ethif_packet.(Marshal.make_cstruct {
        source;
        destination;
        ethertype = Ethif_wire.ARP;
      }) in
    Ethif.writev t.ethif [ethif_packet ; payload] >>= fun e ->
    Lwt.return @@ Rresult.R.ignore_error ~use:(report_ethif_error "write") e

  (* Input handler for an ARP packet *)
  let input t frame =
    let open Arpv4_packet in
    MProf.Trace.label "arpv4.input";
    match Unmarshal.of_cstruct frame with
    | Result.Error s ->
      Log.debug (fun f -> f "Failed to parse arpv4 header: %a (buffer: %S)"
                   Unmarshal.pp_error s (Cstruct.to_string frame));
      Lwt.return_unit
    | Result.Ok arp ->
      notify t arp.spa arp.sha; (* cache the sender's mapping. this will get GARPs too *)
      match arp.op with
      | Arpv4_wire.Reply -> Lwt.return_unit
      | Arpv4_wire.Request ->
        (* Received ARP request, check if we can satisfy it from
           our own IPv4 list *)
        match List.mem arp.tpa t.bound_ips with
        | false -> Lwt.return_unit
        | true ->
          (* We own this IP, so reply with our MAC *)
          let sha = Ethif.mac t.ethif in
          let tha = arp.sha in
          let spa = arp.tpa in (* the requested address *)
          let tpa = arp.spa in (* the requesting host IPv4 *)
          output t ~source:sha ~destination:tha (Arpv4_wire.{ op=Reply; sha; tha; spa; tpa })

  (* Send a gratuitous ARP for our IP addresses *)
  let output_garp t =
    let sha = Ethif.mac t.ethif in
    let tha = Macaddr.broadcast in
    Lwt_list.iter_s (fun spa ->
        let tpa = spa in
        let arp = Arpv4_packet.({ op=Arpv4_wire.Request; tha; sha; tpa; spa }) in
        Log.debug (fun f -> f "ARP: sending gratuitous from %a" Arpv4_packet.pp arp);
        output t ~source:(Ethif.mac t.ethif) ~destination:Macaddr.broadcast arp
      ) t.bound_ips

  (* Send a query for a particular IP *)
  let output_probe t tpa =
    Log.debug (fun f -> f "ARP: transmitting probe -> %a" Ipaddr.V4.pp_hum tpa);
    let tha = Macaddr.broadcast in
    let sha = Ethif.mac t.ethif in
    (* Source protocol address, pick one of our IP addresses *)
    let spa = match t.bound_ips with
      | hd::_ -> hd | [] -> Ipaddr.V4.any in
    let arp = Arpv4_packet.({ op=Arpv4_wire.Request; tha; sha; tpa; spa }) in
    Logs.debug (fun f -> f "ARP: transmitting probe: %a" Arpv4_packet.pp arp);
    output t ~source:sha ~destination:tha arp

  let get_ips t = t.bound_ips

  (* Set the bound IP address list, which will xmit GARP packets also *)
  let set_ips t ips =
    t.bound_ips <- (List.sort_uniq Ipaddr.V4.compare ips);
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
      | Pending (t, _) -> t
      | Confirmed (_, mac) -> Lwt.return (Ok mac)
    with
    | Not_found ->
      let response, waker = MProf.Trace.named_wait "ARP response" in
      Hashtbl.add t.cache ip (Pending (response, waker));
      let rec retry n () =
        (* First request, so send a query packet *)
        output_probe t ip >>= fun () ->
        Lwt.choose [
          response ;
          (Time.sleep_ns probe_repeat_delay >|= fun () -> Error `Timeout)
        ] >>= function
        | Ok _mac -> Lwt.return_unit
        | Error `Timeout ->
          if n < probe_num then begin
            let n = n+1 in
            Log.info (fun f -> f "ARP: retrying %a (n=%d)" Ipaddr.V4.pp_hum ip n);
            retry n ()
          end else begin
            Hashtbl.remove t.cache ip;
            Log.info (fun f -> f "ARP: giving up on resolution of %a after %d attempts"
                               Ipaddr.V4.pp_hum ip n);
            Lwt.wakeup waker (Error `Timeout);
            Lwt.return_unit
          end
      in
      Lwt.async (retry 0);
      response

  let connect ethif clock =
    let cache = Hashtbl.create 7 in
    let bound_ips = [] in
    let t = { clock; ethif; cache; bound_ips } in
    Lwt.async (tick t);
    Log.info (fun f -> f "Connected arpv4 device on %s" (Macaddr.to_string (
               Ethif.mac t.ethif)));
    Lwt.return t

  let disconnect t =
    Log.info (fun f -> f "Disconnected arpv4 device on %s" (Macaddr.to_string (
               Ethif.mac t.ethif)));
    Lwt.return_unit (* TODO: should kill tick *)
end
