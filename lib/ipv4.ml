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

open Lwt
open Printf

module Make(Ethif : V1_LWT.ETHIF) = struct

  (** IO operation errors *)
  type error = [
    | `Unknown of string (** an undiagnosed error *)
    | `Unimplemented     (** operation not yet implemented in the code *)
  ]

  type ethif = Ethif.t
  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t
  type ipv4addr = Ipaddr.V4.t
  type callback = src:ipv4addr -> dst:ipv4addr -> buffer -> unit Lwt.t

  type t = {
    ethif: Ethif.t;
    mutable ip: Ipaddr.V4.t;
    mutable netmask: Ipaddr.V4.t;
    mutable gateways: Ipaddr.V4.t list;
  }

  let id { ethif; _ } = ethif

  module Routing = struct

    exception No_route_to_destination_address of Ipaddr.V4.t

    let is_local t ip =
      let ipand a b = Int32.logand (Ipaddr.V4.to_int32 a) (Ipaddr.V4.to_int32 b) in
      (ipand t.ip t.netmask) = (ipand ip t.netmask)

    (* RFC 1112: 01-00-5E-00-00-00 ORed with lower 23 bits of the ip address *)
    let mac_of_multicast ip =
      let ipb = Ipaddr.V4.to_bytes ip in
      let macb = String.create 6 in
      macb.[0] <- Char.chr 0x01;
      macb.[1] <- Char.chr 0x00;
      macb.[2] <- Char.chr 0x5E;
      macb.[3] <- Char.chr ((Char.code ipb.[1]) land 0x7F);
      macb.[4] <- ipb.[2];
      macb.[5] <- ipb.[3];
      Macaddr.of_bytes_exn macb

    let destination_mac t =
      function
      |ip when ip = Ipaddr.V4.broadcast || ip = Ipaddr.V4.any -> (* Broadcast *)
        return Macaddr.broadcast
      |ip when is_local t ip -> (* Local *)
        Ethif.query_arpv4 t.ethif ip
      |ip when Ipaddr.V4.is_multicast ip ->
        return (mac_of_multicast ip)
      |ip -> begin (* Gateway *)
          match t.gateways with
          |hd::_ -> Ethif.query_arpv4 t.ethif hd
          |[] ->
            printf "IP.output: no route to %s\n%!" (Ipaddr.V4.to_string ip);
            fail (No_route_to_destination_address ip)
        end
  end

  let allocate_frame ~proto ~dest_ip t =
    let ethernet_frame = Io_page.to_cstruct (Io_page.get 1) in
    (* Something of a layer violation here, but ARP is awkward *)
    Routing.destination_mac t dest_ip >|= Macaddr.to_bytes >>= fun dmac ->
    let smac = Macaddr.to_bytes (Ethif.mac t.ethif) in
    Wire_structs.set_ethernet_dst dmac 0 ethernet_frame;
    Wire_structs.set_ethernet_src smac 0 ethernet_frame;
    Wire_structs.set_ethernet_ethertype ethernet_frame 0x0800;
    let buf = Cstruct.shift ethernet_frame Wire_structs.sizeof_ethernet in
    (* Write the constant IPv4 header fields *)
    Wire_structs.set_ipv4_hlen_version buf ((4 lsl 4) + (5)); (* TODO options *)
    Wire_structs.set_ipv4_tos buf 0;
    Wire_structs.set_ipv4_off buf 0; (* TODO fragmentation *)
    Wire_structs.set_ipv4_ttl buf 38; (* TODO *)
    let proto = match proto with |`ICMP -> 1 |`TCP -> 6 |`UDP -> 17 in
    Wire_structs.set_ipv4_proto buf proto;
    Wire_structs.set_ipv4_src buf (Ipaddr.V4.to_int32 t.ip);
    Wire_structs.set_ipv4_dst buf (Ipaddr.V4.to_int32 dest_ip);
    let len = Wire_structs.sizeof_ethernet + Wire_structs.sizeof_ipv4 in
    return (ethernet_frame, len)

  let adjust_output_header ~tlen frame =
    let buf =
      Cstruct.sub frame Wire_structs.sizeof_ethernet Wire_structs.sizeof_ipv4
    in
    (* Set the mutable values in the ipv4 header *)
    Wire_structs.set_ipv4_len buf tlen;
    Wire_structs.set_ipv4_id buf (Random.int 65535); (* TODO *)
    Wire_structs.set_ipv4_csum buf 0;
    let checksum =
      Tcpip_checksum.ones_complement
        (Cstruct.sub buf 0 Wire_structs.sizeof_ipv4)
    in
    Wire_structs.set_ipv4_csum buf checksum

  (* We write a whole frame, truncated from the right where the
   * packet data stops.
  *)
  let write t frame data =
    let ihl = 5 in (* TODO options *)
    let tlen = (ihl * 4) + (Cstruct.len data) in
    adjust_output_header ~tlen frame;
    Ethif.writev t.ethif [frame;data]

  let writev t ethernet_frame bufs =
    let tlen =
      Cstruct.len ethernet_frame
      - Wire_structs.sizeof_ethernet
      + Cstruct.lenv bufs
    in
    adjust_output_header ~tlen ethernet_frame;
    Ethif.writev t.ethif (ethernet_frame::bufs)

  let icmp_input t src _hdr buf =
    MProf.Trace.label "icmp_input";
    match Wire_structs.get_icmpv4_ty buf with
    |0 -> (* echo reply *)
      return (printf "ICMP: discarding echo reply\n%!")
    |8 -> (* echo request *)
      (* convert the echo request into an echo reply *)
      let csum =
        let orig_csum = Wire_structs.get_icmpv4_csum buf in
        let shift = if orig_csum > 0xffff -0x0800 then 0x0801 else 0x0800 in
        (orig_csum + shift) land 0xffff in
      Wire_structs.set_icmpv4_ty buf 0;
      Wire_structs.set_icmpv4_csum buf csum;
      (* stick an IPv4 header on the front and transmit *)
      allocate_frame ~proto:`ICMP ~dest_ip:src t >>= fun (ipv4_frame, ipv4_len) ->
      let ipv4_frame = Cstruct.set_len ipv4_frame ipv4_len in
      write t ipv4_frame buf
    |ty ->
      printf "ICMP unknown ty %d\n" ty;
      return_unit

  let input ~tcp ~udp ~default t buf =
    (* buf pointers to to start of IPv4 header here *)
    let ihl = (Wire_structs.get_ipv4_hlen_version buf land 0xf) * 4 in
    let src = Ipaddr.V4.of_int32 (Wire_structs.get_ipv4_src buf) in
    let dst = Ipaddr.V4.of_int32 (Wire_structs.get_ipv4_dst buf) in
    let payload_len = Wire_structs.get_ipv4_len buf - ihl in
    (* XXX this will raise exception for 0-length payload *)
    let hdr = Cstruct.sub buf 0 ihl in
    let data = Cstruct.sub buf ihl payload_len in
    match Wire_structs.get_ipv4_proto buf with
    | 1 -> (* ICMP *)
      icmp_input t src hdr data
    | 6 -> (* TCP *)
      tcp ~src ~dst data
    | 17 -> (* UDP *)
      udp ~src ~dst data
    | proto ->
      default ~proto ~src ~dst data

  let connect ethif =
    let ip = Ipaddr.V4.any in
    let netmask = Ipaddr.V4.any in
    let gateways = [] in
    let t = { ethif; ip; netmask; gateways } in
    return (`Ok t)

  let disconnect _ = return_unit

  let set_ipv4 t ip =
    t.ip <- ip;
    (* Inform ARP layer of new IP *)
    Ethif.add_ipv4 t.ethif ip

  let get_ipv4 t = t.ip

  let set_ipv4_netmask t netmask =
    t.netmask <- netmask;
    return_unit

  let get_ipv4_netmask t = t.netmask

  let set_ipv4_gateways t gateways =
    t.gateways <- gateways;
    return_unit

  let get_ipv4_gateways { gateways; _ } = gateways

end
