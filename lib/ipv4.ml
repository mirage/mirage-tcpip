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
open Printf

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
          match t.gateways with
          |hd::_ ->
            Arpv4.query t.arp hd >>= begin function
              | `Ok mac -> Lwt.return mac
              | `Timeout ->
                printf "IP.output: arp timeout to gw %s\n%!" (Ipaddr.V4.to_string ip);
                Lwt.fail (No_route_to_destination_address ip)
            end
          |[] ->
            printf "IP.output: no route to %s\n%!" (Ipaddr.V4.to_string ip);
            Lwt.fail (No_route_to_destination_address ip)
        end
  end

  let adjust_output_header ~dmac ~tlen frame =
    Wire_structs.set_ethernet_dst dmac 0 frame;
    let buf = Cstruct.sub frame Wire_structs.sizeof_ethernet Wire_structs.Ipv4_wire.sizeof_ipv4 in
    (* Set the mutable values in the ipv4 header *)
    Wire_structs.Ipv4_wire.set_ipv4_len buf tlen;
    Wire_structs.Ipv4_wire.set_ipv4_id buf (Random.int 65535); (* TODO *)
    Wire_structs.Ipv4_wire.set_ipv4_csum buf 0;
    let checksum = Tcpip_checksum.ones_complement buf in
    Wire_structs.Ipv4_wire.set_ipv4_csum buf checksum

  let allocate_frame t ~dst ~proto =
    let ethernet_frame = Io_page.to_cstruct (Io_page.get 1) in
    let smac = Macaddr.to_bytes (Ethif.mac t.ethif) in
    Wire_structs.set_ethernet_src smac 0 ethernet_frame;
    Wire_structs.set_ethernet_ethertype ethernet_frame 0x0800;
    let buf = Cstruct.shift ethernet_frame Wire_structs.sizeof_ethernet in
    (* Write the constant IPv4 header fields *)
    Wire_structs.Ipv4_wire.set_ipv4_hlen_version buf ((4 lsl 4) + (5)); (* TODO options *)
    Wire_structs.Ipv4_wire.set_ipv4_tos buf 0;
    Wire_structs.Ipv4_wire.set_ipv4_off buf 0; (* TODO fragmentation *)
    Wire_structs.Ipv4_wire.set_ipv4_ttl buf 38; (* TODO *)
    let proto = Wire_structs.Ipv4_wire.protocol_to_int proto in
    Wire_structs.Ipv4_wire.set_ipv4_proto buf proto;
    Wire_structs.Ipv4_wire.set_ipv4_src buf (Ipaddr.V4.to_int32 t.ip);
    Wire_structs.Ipv4_wire.set_ipv4_dst buf (Ipaddr.V4.to_int32 dst);
    let len = Wire_structs.sizeof_ethernet + Wire_structs.Ipv4_wire.sizeof_ipv4 in
    (ethernet_frame, len)

  let writev t frame bufs =
    let v4_frame = Cstruct.shift frame Wire_structs.sizeof_ethernet in
    let dst = Ipaddr.V4.of_int32 (Wire_structs.Ipv4_wire.get_ipv4_dst v4_frame) in
    (* Something of a layer violation here, but ARP is awkward *)
    Routing.destination_mac t dst >|= Macaddr.to_bytes >>= fun dmac ->
    let tlen = Cstruct.len frame + Cstruct.lenv bufs - Wire_structs.sizeof_ethernet in
    adjust_output_header ~dmac ~tlen frame;
    Ethif.writev t.ethif (frame :: bufs)

  let write t frame buf =
    writev t frame [buf]

  let icmp_dst_unreachable buf =
    let descr =
      match Wire_structs.Ipv4_wire.get_icmpv4_code buf with
      | 0  -> "Destination network unreachable"
      | 1  -> "Destination host unreachable"
      | 2  -> "Destination protocol unreachable"
      | 3  -> "Destination port unreachable"
      | 4  -> "Fragmentation required, and DF flag set"
      | 5  -> "Source route failed"
      | 6  -> "Destination network unknown"
      | 7  -> "Destination host unknown"
      | 8  -> "Source host isolated"
      | 9  -> "Network administratively prohibited"
      | 10 -> "Host administratively prohibited"
      | 11 -> "Network unreachable for TOS"
      | 12 -> "Host unreachable for TOS"
      | 13 -> "Communication administratively prohibited"
      | 14 -> "Host Precedence Violation"
      | 15 -> "Precedence cutoff in effect"
      | code -> Printf.sprintf "Unknown code: %d" code in
    printf "ICMP Destination Unreachable: %s\n%!" descr;
    Lwt.return_unit

  let icmp_input t src _hdr buf =
    MProf.Trace.label "icmp_input";
    match Wire_structs.Ipv4_wire.get_icmpv4_ty buf with
    |0 -> (* echo reply *)
      printf "ICMP: discarding echo reply\n%!";
      Lwt.return_unit
    |3 -> icmp_dst_unreachable buf
    |8 -> (* echo request *)
      (* convert the echo request into an echo reply *)
      let csum =
        let orig_csum = Wire_structs.Ipv4_wire.get_icmpv4_csum buf in
        let shift = if orig_csum > 0xffff -0x0800 then 0x0801 else 0x0800 in
        (orig_csum + shift) land 0xffff in
      Wire_structs.Ipv4_wire.set_icmpv4_ty buf 0;
      Wire_structs.Ipv4_wire.set_icmpv4_csum buf csum;
      (* stick an IPv4 header on the front and transmit *)
      let frame, header_len = allocate_frame t ~dst:src ~proto:`ICMP in
      let frame = Cstruct.set_len frame header_len in
      write t frame buf
    |ty ->
      printf "ICMP unknown ty %d\n" ty;
      Lwt.return_unit

  let input t ~tcp ~udp ~default buf =
    (* buf pointers to start of IPv4 header here *)
    let ihl = (Wire_structs.Ipv4_wire.get_ipv4_hlen_version buf land 0xf) * 4 in
    let src = Ipaddr.V4.of_int32 (Wire_structs.Ipv4_wire.get_ipv4_src buf) in
    let dst = Ipaddr.V4.of_int32 (Wire_structs.Ipv4_wire.get_ipv4_dst buf) in
    let payload_len = Wire_structs.Ipv4_wire.get_ipv4_len buf - ihl in
    let hdr, data = Cstruct.split buf ihl in
    if Cstruct.len data >= payload_len then begin
      (* Strip trailing bytes. See: https://github.com/mirage/mirage-net-xen/issues/24 *)
      let data = Cstruct.sub data 0 payload_len in
      let proto = Wire_structs.Ipv4_wire.get_ipv4_proto buf in
      match Wire_structs.Ipv4_wire.int_to_protocol proto with
      | Some `ICMP -> icmp_input t src hdr data
      | Some `TCP  -> tcp ~src ~dst data
      | Some `UDP  -> udp ~src ~dst data
      | None       -> default ~proto ~src ~dst data
    end else Lwt.return_unit

  let connect ethif arp =
    let ip = Ipaddr.V4.any in
    let netmask = Ipaddr.V4.any in
    let gateways = [] in
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

  let checksum =
    let pbuf = Io_page.to_cstruct (Io_page.get 1) in
    let pbuf = Cstruct.set_len pbuf 4 in
    Cstruct.set_uint8 pbuf 0 0;
    fun frame bufs ->
      let frame = Cstruct.shift frame Wire_structs.sizeof_ethernet in
      Cstruct.set_uint8 pbuf 1 (Wire_structs.Ipv4_wire.get_ipv4_proto frame);
      Cstruct.BE.set_uint16 pbuf 2 (Cstruct.lenv bufs);
      let src_dst = Cstruct.sub frame 12 (2 * 4) in
      Tcpip_checksum.ones_complement_list (src_dst :: pbuf :: bufs)

  let get_source t ~dst:_ =
    t.ip

  type uipaddr = Ipaddr.t
  let to_uipaddr ip = Ipaddr.V4 ip
  let of_uipaddr = Ipaddr.to_v4

end
