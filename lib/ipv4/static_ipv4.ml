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
open Result

let src = Logs.Src.create "ipv4" ~doc:"Mirage IPv4"
module Log = (val Logs.src_log src : Logs.LOG)

module Make(Ethif: Mirage_protocols_lwt.ETHIF) (Arpv4 : Mirage_protocols_lwt.ARP) = struct
  module Routing = Routing.Make(Log)(Arpv4)

  (** IO operation errors *)
  type error = [ Mirage_protocols.Ip.error | `Ethif of Ethif.error ]
  let pp_error ppf = function
  | #Mirage_protocols.Ip.error as e -> Mirage_protocols.Ip.pp_error ppf e
  | `Ethif e -> Ethif.pp_error ppf e

  type ethif = Ethif.t
  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t
  type ipaddr = Ipaddr.V4.t
  type prefix = Ipaddr.V4.Prefix.t
  type callback = src:ipaddr -> dst:ipaddr -> buffer -> unit Lwt.t

  type t = {
    ethif : Ethif.t;
    arp : Arpv4.t;
    mutable ip: Ipaddr.V4.t;
    network: Ipaddr.V4.Prefix.t;
    mutable gateway: Ipaddr.V4.t option;
  }

  let adjust_output_header = Ipv4_common.adjust_output_header

  let allocate_frame t ~(dst:ipaddr) ~(proto : [`ICMP | `TCP | `UDP]) : (buffer * int) =
    Ipv4_common.allocate_frame ~src:t.ip ~source:(Ethif.mac t.ethif) ~dst ~proto

  let writev t frame bufs : (unit, error) result Lwt.t =
    let v4_frame = Cstruct.shift frame Ethif_wire.sizeof_ethernet in
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
      let dmac = Macaddr.to_bytes mac in
      let tlen = Cstruct.len frame + Cstruct.lenv bufs - Ethif_wire.sizeof_ethernet in
      adjust_output_header ~dmac ~tlen frame;
      Ethif.writev t.ethif (frame :: bufs) >|= function
      | Error e ->
        Log.warn (fun f -> f "Error sending Ethernet frame: %a" Ethif.pp_error e);
        Error (`Ethif e)
      | Ok () -> Ok ()

  let write t frame buf =
    writev t frame [buf]

  (* TODO: ought we to check to make sure the destination is relevant here?  currently we'll process all incoming packets, regardless of destination address *)
  let input _t ~tcp ~udp ~default buf =
    let open Ipv4_packet in
    match Unmarshal.of_cstruct buf with
    | Error s ->
      Log.info (fun f -> f "IP.input: unparseable header (%s): %S" s (Cstruct.to_string buf));
      Lwt.return_unit
    | Ok (packet, payload) ->
      match Unmarshal.int_to_protocol packet.proto, Cstruct.len payload with
      | Some _, 0 ->
        (* Don't pass on empty buffers as payloads to known protocols, as they have no relevant headers *)
        Lwt.return_unit
      | None, 0 -> (* we don't know anything about the protocol; an empty
                      payload may be meaningful somehow? *)
        default ~proto:packet.proto ~src:packet.src ~dst:packet.dst payload
      | Some `TCP, _ -> tcp ~src:packet.src ~dst:packet.dst payload
      | Some `UDP, _ -> udp ~src:packet.src ~dst:packet.dst payload
      | Some `ICMP, _ | None, _ ->
        default ~proto:packet.proto ~src:packet.src ~dst:packet.dst payload

  let connect
      ?(ip=Ipaddr.V4.any)
      ?(network=Ipaddr.V4.Prefix.make 0 Ipaddr.V4.any)
      ?(gateway=None) ethif arp =
    match Ipaddr.V4.Prefix.mem ip network with
    | false ->
      Log.warn (fun f -> f "IPv4: ip %a is not in the prefix %a" Ipaddr.V4.pp_hum ip Ipaddr.V4.Prefix.pp_hum network);
      Lwt.fail_with "given IP is not in the network provided"
    | true ->
      Arpv4.set_ips arp [ip] >>= fun () ->
      let t = { ethif; arp; ip; network; gateway } in
      Lwt.return t

  let disconnect _ = Lwt.return_unit

  let set_ip t ip =
    t.ip <- ip;
    (* Inform ARP layer of new IP *)
    Arpv4.set_ips t.arp [ip]

  let get_ip t = [t.ip]

  let pseudoheader t ~dst ~proto len =
    Ipv4_packet.Marshal.pseudoheader ~src:t.ip ~dst ~proto len

  let checksum = Ipv4_common.checksum

  let src t ~dst:_ =
    t.ip

  type uipaddr = Ipaddr.t
  let to_uipaddr ip = Ipaddr.V4 ip
  let of_uipaddr = Ipaddr.to_v4

  let mtu t = Ethif.mtu t.ethif - Ipv4_wire.sizeof_ipv4

end
