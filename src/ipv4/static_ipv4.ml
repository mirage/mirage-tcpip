(*
 * Copyright (c) 2010-2011 Anil Madhavapeddy <anil@recoil.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS l SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

open Lwt.Infix

let src = Logs.Src.create "ipv4" ~doc:"Mirage IPv4"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (R: Mirage_random.C) (C: Mirage_clock.MCLOCK) (Ethernet: Mirage_protocols_lwt.ETHERNET) (Arpv4 : Mirage_protocols_lwt.ARP) = struct
  module Routing = Routing.Make(Log)(Arpv4)

  (** IO operation errors *)
  type error = [ Mirage_protocols.Ip.error | `Ethernet of Ethernet.error ]
  let pp_error ppf = function
  | #Mirage_protocols.Ip.error as e -> Mirage_protocols.Ip.pp_error ppf e
  | `Ethernet e -> Ethernet.pp_error ppf e

  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t
  type ipaddr = Ipaddr.V4.t
  type callback = src:ipaddr -> dst:ipaddr -> buffer -> unit Lwt.t

  module M = Map.Make(Mirage_protocols.Ip.Proto)

  type t = {
    ethernet : Ethernet.t;
    arp : Arpv4.t;
    clock : C.t;
    mutable ip: Ipaddr.V4.t;
    network: Ipaddr.V4.Prefix.t;
    mutable gateway: Ipaddr.V4.t option;
    mutable cache: Fragments.Cache.t;
    mutable callbacks: callback M.t
  }

  let register t proto callback =
    match M.find_opt proto t.callbacks with
    | None ->
      Log.info (fun m -> m "registering %a on IPv4" Mirage_protocols.Ip.Proto.pp proto) ;
      t.callbacks <- M.add proto callback t.callbacks ;
      Ok ()
    | Some _ ->
      Log.err (fun m -> m "conflict, protocol %a is already registered" Mirage_protocols.Ip.Proto.pp proto);
      Error `Conflict

  let adjust_output_header ~tlen =
    Ipv4_common.adjust_output_header ~rng:R.generate ~tlen

  let allocate_frame t ~(dst:ipaddr) ~(proto : Mirage_protocols.Ip.Proto.t) : (buffer * int) =
    let src = t.ip in
    let frame, off = Ethernet.allocate_frame t.ethernet in
    let buf = Cstruct.shift frame off in
    (* TODO: why 38 for TTL? *)
    let ipv4_header = Ipv4_packet.({options = Cstruct.create 0;
                                    src; dst; ttl = 38;
                                    off = 0 ; id = 0x0000 ;
                                    proto = Ipv4_packet.Marshal.protocol_to_int proto; }) in
    (* set the payload_len to 0, since we don't know what it'll be yet *)
    (* the caller needs to then use [writev] or [write] to output the buffer;
       otherwise length, id, and checksum won't be set properly *)
    match Ipv4_packet.Marshal.into_cstruct ~payload_len:0 ipv4_header buf with
    | Error _s ->
      raise (Invalid_argument "writing ipv4 header to ipv4.allocate_frame failed")
    | Ok () ->
      (frame, off + Ipv4_wire.sizeof_ipv4)

  let writev t frame bufs : (unit, error) result Lwt.t =
    (* TODO check whether we need to fragment! *)
    let v4_frame = Cstruct.sub frame (Ethernet.header_size t.ethernet) Ipv4_wire.sizeof_ipv4 in
    let dst = Ipaddr.V4.of_int32 (Ipv4_wire.get_ipv4_dst v4_frame) in
    Routing.destination_mac t.network t.gateway t.arp dst >>= function
    | Error `Local ->
      Log.warn (fun f -> f "Could not find %a on the local network" Ipaddr.V4.pp_hum dst);
      Lwt.return @@ Error (`No_route "no response for IP on local network")
    | Error `Gateway when t.gateway = None ->
      Log.warn (fun f -> f "Write to %a would require an external route, which was not provided" Ipaddr.V4.pp_hum dst);
      Lwt.return @@ Ok ()
    | Error `Gateway ->
      Log.warn (fun f -> f "Write to %a requires an external route, and the provided %a was not reachable" Ipaddr.V4.pp_hum dst (Fmt.option Ipaddr.V4.pp_hum) t.gateway);
      (* when a gateway is specified the user likely expects their traffic to be passed to it *)
      Lwt.return @@ Error (`No_route "no route to default gateway to outside world")
    | Ok mac ->
      let tlen = Cstruct.len frame + Cstruct.lenv bufs - (Ethernet.header_size t.ethernet) in
      adjust_output_header ~tlen v4_frame;
      Ethernet.write t.ethernet `IPv4 mac (Cstruct.concat (frame :: bufs)) >|= function
      | Error e ->
        Log.warn (fun f -> f "Error sending Ethernet frame: %a" Ethernet.pp_error e);
        Error (`Ethernet e)
      | Ok () -> Ok ()

  let write t frame buf =
    writev t frame [buf]

  let process t buf =
    match Ipv4_packet.Unmarshal.of_cstruct buf with
    | Error s ->
      Log.info (fun m -> m "error %s while parsing IPv4 frame %a" s Cstruct.hexdump_pp buf);
      None
    | Ok (packet, payload) ->
      if Cstruct.len payload = 0 then
        (Log.info (fun m -> m "dropping zero length IPv4 frame %a" Ipv4_packet.pp packet);
         None)
      else
        let ts = C.elapsed_ns t.clock in
        let cache, res = Fragments.process t.cache ts packet payload in
        t.cache <- cache ;
        res

  let decode_proto packet =
    match Ipv4_packet.Unmarshal.int_to_protocol packet.Ipv4_packet.proto with
    | None ->
      Log.warn (fun m -> m "unknown protocol %02X" packet.Ipv4_packet.proto);
      None
    | Some proto -> Some proto

  (* TODO: ought we to check to make sure the destination is relevant here?  currently we'll process all incoming packets, regardless of destination address *)
  let input t fn buf =
    match process t buf with
    | None -> Lwt.return_unit
    | Some (packet, payload) -> match decode_proto packet with
      | None -> Lwt.return_unit
      | Some proto ->
          let src, dst = packet.src, packet.dst in
          fn proto ~src ~dst payload

  let receive t ~source:_ _destination buf =
    match process t buf with
    | None -> Lwt.return_unit
    | Some (packet, payload) -> match decode_proto packet with
      | None -> Lwt.return_unit
      | Some proto -> match M.find_opt proto t.callbacks with
        | None ->
          Log.warn (fun m -> m "no listener for protocol %a" Mirage_protocols.Ip.Proto.pp proto);
          Lwt.return_unit
        | Some f ->
          let src, dst = packet.src, packet.dst in
          f ~src ~dst payload

  let connect ?ip ?gateway clock ethernet arp =
    match ip with
    | None ->
      Log.warn (fun f -> f "IPv4: no ip provided");
      Lwt.fail_with "given IP is not in the network provided"
    | Some (network, ip) ->
      Arpv4.set_ips arp [ip] >>= fun () ->
      (* TODO currently hardcoded to 256KB, should be configurable
         and maybe limited per-src/dst-ip as well? *)
      let cache = Fragments.Cache.empty (1024 * 256) in
      let t = { ethernet; arp; ip; clock; network; gateway ; cache ; callbacks = M.empty } in
      (match Ethernet.register ethernet `IPv4 (receive t) with
       | Ok () -> Lwt.return_unit
       | Error `Conflict -> Lwt.fail_with "conflict ipv4") >>= fun () ->
      Lwt.return t

  let disconnect _ = Lwt.return_unit

  let set_ip t ip =
    t.ip <- ip;
    (* Inform ARP layer of new IP *)
    Arpv4.set_ips t.arp [ip]

  let get_ip t = [t.ip]

  let pseudoheader t ~dst ~proto len =
    Ipv4_packet.Marshal.pseudoheader ~src:t.ip ~dst ~proto len

  let src t ~dst:_ =
    t.ip

  type uipaddr = Ipaddr.t
  let to_uipaddr ip = Ipaddr.V4 ip
  let of_uipaddr = Ipaddr.to_v4

  let mtu t = Ethernet.mtu t.ethernet - Ipv4_wire.sizeof_ipv4

end
