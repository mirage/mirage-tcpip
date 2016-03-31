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
  type macaddr = Ethif.macaddr

  type t = {
    ethif : Ethif.t;
    arp : Arpv4.t;
    mutable ip: Ipaddr.V4.t;
    mutable netmask: Ipaddr.V4.t;
    mutable gateways: Ipaddr.V4.t list;
  }

  let input_arpv4 t buf =
    Arpv4.input t.arp buf

  let id { ethif; _ } = ethif

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
          let out = Ipaddr.V4.to_string in
          match t.gateways with
          |hd::_ ->
            Arpv4.query t.arp hd >>= begin function
              | `Ok mac -> Lwt.return mac
              | `Timeout ->
                Printf.printf "IP.output: could not send to %s: failed to contact gateway %s\n%!"
                  (out ip) (out hd) ;
                Lwt.fail (No_route_to_destination_address ip)
            end
          |[] ->
            Printf.printf "IP.output: no route to %s (no default gateway is configured)\n%!"
              (out ip);
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

  let allocate_frame t ~dst ~proto =
    let open Ipv4_wire in
    let ethernet_frame = Io_page.to_cstruct (Io_page.get 1) in
    let smac = Macaddr.to_bytes (Ethif.mac t.ethif) in
    Ethif_wire.set_ethernet_src smac 0 ethernet_frame;
    Ethif_wire.set_ethernet_ethertype ethernet_frame 0x0800;
    let buf = Cstruct.shift ethernet_frame Ethif_wire.sizeof_ethernet in
    (* Write the constant IPv4 header fields *)
    set_ipv4_hlen_version buf ((4 lsl 4) + (5)); (* TODO options *)
    set_ipv4_tos buf 0;
    set_ipv4_off buf 0; (* TODO fragmentation *)
    set_ipv4_ttl buf 38; (* TODO *)
    let proto = Ipv4_print.protocol_to_int proto in
    set_ipv4_proto buf proto;
    set_ipv4_src buf (Ipaddr.V4.to_int32 t.ip);
    set_ipv4_dst buf (Ipaddr.V4.to_int32 dst);
    let len = Ethif_wire.sizeof_ethernet + sizeof_ipv4 in
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

  let input t ~tcp ~udp ~default buf =
    (* buf pointers to start of IPv4 header here *)
    let open Ipv4_parse in
    match parse_ipv4_header buf with
    | Error _ -> (* TODO: log an error on high debug level *) Lwt.return_unit
    | Ok packet ->
      match int_to_protocol packet.proto, packet.payload with
      (* Don't pass on empty buffers as payloads to known protocols
         -- they have no relevant headers *)
      | Some _, None -> Lwt.return_unit
      | Some `TCP, Some payload -> tcp ~src:packet.src ~dst:packet.dst payload
      | Some `UDP, Some payload -> udp ~src:packet.src ~dst:packet.dst payload
      | Some `ICMP, Some payload | None, Some payload ->
        default ~proto:packet.proto ~src:packet.src ~dst:packet.dst payload
      | None, None -> (* we don't know anything about the handler -- it may know
                         what to do with an empty payload *)
        default ~proto:packet.proto ~src:packet.src ~dst:packet.dst (Cstruct.create 0)

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
    Ipv4_print.pseudoheader ~src:t.ip ~dst ~proto len

  let checksum frame bufs =
    let packet = Cstruct.shift frame Ethif_wire.sizeof_ethernet in
    Ipv4_wire.set_ipv4_csum packet 0;
    Tcpip_checksum.ones_complement_list (packet :: bufs)

  let get_source t ~dst:_ =
    t.ip

  type uipaddr = Ipaddr.t
  let to_uipaddr ip = Ipaddr.V4 ip
  let of_uipaddr = Ipaddr.to_v4

end
