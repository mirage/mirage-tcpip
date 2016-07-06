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

module Make(Ethif: V1_LWT.ETHIF) (Arpv4 : V1_LWT.ARP) = struct

  (** IO operation errors *)
  type error = [
    | `Unknown of string (** an undiagnosed error *)
    | `Unimplemented     (** operation not yet implemented in the code *)
  ]

  type ethif = Ethif.t
  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t
  type ipaddr = Ipaddr.V4.t
  type prefix = Ipaddr.V4.t
  type callback = src:ipaddr -> dst:ipaddr -> buffer -> unit Lwt.t

  type t = {
    ethif : Ethif.t;
    arp : Arpv4.t;
    mutable ip: Ipaddr.V4.t;
    mutable netmask: Ipaddr.V4.t;
    mutable gateways: Ipaddr.V4.t list;
  }

  module Routing = struct

    exception No_route_to_destination_address of Ipaddr.V4.t

    let is_local t ip =
      let ipand a b = Int32.logand (Ipaddr.V4.to_int32 a) (Ipaddr.V4.to_int32 b) in
      (ipand t.ip t.netmask) = (ipand ip t.netmask)

    (* RFC 1112: 01-00-5E-00-00-00 ORed with lower 23 bits of the ip address *)
    let mac_of_multicast ip =
      let ipb = Ipaddr.V4.to_bytes ip in
      let macb = Bytes.create 6 in
      Bytes.set macb 0 (Char.chr 0x01);
      Bytes.set macb 1 (Char.chr 0x00);
      Bytes.set macb 2 (Char.chr 0x5E);
      Bytes.set macb 3 (Char.chr ((Char.code ipb.[1]) land 0x7F));
      Bytes.set macb 4 (Bytes.get ipb 2);
      Bytes.set macb 5 (Bytes.get ipb 3);
      Macaddr.of_bytes_exn macb

    let destination_mac t =
      function
      |ip when ip = Ipaddr.V4.broadcast || ip = Ipaddr.V4.any -> (* Broadcast *)
        Lwt.return Macaddr.broadcast
      |ip when is_local t ip -> (* Local *)
        Arpv4.query t.arp ip >>= begin function
          | `Ok mac -> Lwt.return mac
          | `Timeout -> Lwt.fail (No_route_to_destination_address ip)
        end
      |ip when Ipaddr.V4.is_multicast ip ->
        Lwt.return (mac_of_multicast ip)
      |ip -> begin (* Gateway *)
          match t.gateways with
          |hd::_ ->
            Arpv4.query t.arp hd >>= begin function
              | `Ok mac -> Lwt.return mac
              | `Timeout ->
                Log.info (fun f -> f "IP.output: could not send to %a: failed to contact gateway %a"
                             Ipaddr.V4.pp_hum ip Ipaddr.V4.pp_hum hd);
                Lwt.fail (No_route_to_destination_address ip)
            end
          |[] ->
            Log.info (fun f -> f "IP.output: no route to %a (no default gateway is configured)" Ipaddr.V4.pp_hum ip);
            Lwt.fail (No_route_to_destination_address ip)
        end
  end

  let adjust_output_header ~dmac ~tlen frame =
    let open Ipv4_wire in
    Ethif_wire.set_ethernet_dst dmac 0 frame;
    let buf = Cstruct.sub frame Ethif_wire.sizeof_ethernet sizeof_ipv4 in
    (* Set the mutable values in the ipv4 header *)
    set_ipv4_len buf tlen;
    set_ipv4_id buf (Random.int 65535); (* TODO *)
    set_ipv4_csum buf 0;
    let checksum = Tcpip_checksum.ones_complement buf in
    set_ipv4_csum buf checksum

  let allocate_frame t ~(dst:ipaddr) ~(proto : [`ICMP | `TCP | `UDP]) : (buffer * int) =
    let open Ipv4_wire in
    let ethernet_frame = Io_page.to_cstruct (Io_page.get 1) in
    let len = Ethif_wire.sizeof_ethernet + sizeof_ipv4 in
    let eth_header = Ethif_packet.({ethertype = Ethif_wire.IPv4;
                                    source = Ethif.mac t.ethif;
                                    destination = Macaddr.broadcast}) in
    match Ethif_packet.Marshal.into_cstruct eth_header ethernet_frame with
    | Error s -> 
      Log.info (fun f -> f "IP.allocate_frame: could not print ethernet header: %s" s);
      raise (Invalid_argument "writing ethif header to ipv4.allocate_frame failed")
    | Ok () ->
      let buf = Cstruct.shift ethernet_frame Ethif_wire.sizeof_ethernet in
      (* TODO: why 38 for TTL? *)
      let ipv4_header = Ipv4_packet.({options = Cstruct.create 0;
                                      src = t.ip; dst; ttl = 38; 
                                      proto = Ipv4_packet.Marshal.protocol_to_int proto; }) in
      (* set the payload to 0, since we don't know what it'll be yet *)
      (* the caller needs to then use [writev] or [write] to output the buffer;
         otherwise length, id, and checksum won't be set properly *)
      match Ipv4_packet.Marshal.into_cstruct ~payload:(Cstruct.create 0) ipv4_header buf with
      | Error s ->
        Log.info (fun f -> f "IP.allocate_frame: could not print IPv4 header: %s" s);
        raise (Invalid_argument "writing ipv4 header to ipv4.allocate_frame failed")
      | Ok () ->
        (ethernet_frame, len)

  let writev t frame bufs =
    let v4_frame = Cstruct.shift frame Ethif_wire.sizeof_ethernet in
    let dst = Ipaddr.V4.of_int32 (Ipv4_wire.get_ipv4_dst v4_frame) in
    (* Something of a layer violation here, but ARP is awkward *)
    Routing.destination_mac t dst >|= Macaddr.to_bytes >>= fun dmac ->
    let tlen = Cstruct.len frame + Cstruct.lenv bufs - Ethif_wire.sizeof_ethernet in
    adjust_output_header ~dmac ~tlen frame;
    Ethif.writev t.ethif (frame :: bufs)

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
      ?(netmask=Ipaddr.V4.any)
      ?(gateways=[]) ethif arp =
    let t = { ethif; arp; ip; netmask; gateways } in
    Lwt.return (`Ok t)

  let disconnect _ = Lwt.return_unit

  let set_ip t ip =
    t.ip <- ip;
    (* Inform ARP layer of new IP *)
    Arpv4.add_ip t.arp ip

  let get_ip t = [t.ip]

  let set_ip_netmask t netmask =
    t.netmask <- netmask;
    Lwt.return_unit

  let get_ip_netmasks t = [t.netmask]

  let set_ip_gateways t gateways =
    t.gateways <- gateways;
    Lwt.return_unit

  let get_ip_gateways { gateways; _ } = gateways

  let pseudoheader t ~dst ~proto len =
    Ipv4_packet.Marshal.pseudoheader ~src:t.ip ~dst ~proto len

  let checksum frame bufs =
    let packet = Cstruct.shift frame Ethif_wire.sizeof_ethernet in
    Ipv4_wire.set_ipv4_csum packet 0;
    Tcpip_checksum.ones_complement_list (packet :: bufs)

  let src t ~dst:_ =
    t.ip

  type uipaddr = Ipaddr.t
  let to_uipaddr ip = Ipaddr.V4 ip
  let of_uipaddr = Ipaddr.to_v4

end
