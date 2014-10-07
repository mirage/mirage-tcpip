(*
 * Copyright (c) 2014 Nicolas Ojeda Bar <n.oje.bar@gmail.com>
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

(*
- Transmission of IPv6 packets over Ethernet networks
 http://tools.ietf.org/html/rfc2464

- IPv6 Stateless Address Autoconfiguration
 https://tools.ietf.org/html/rfc2462

- Neighbor Discovery for IP Version 6 (IPv6)
 https://tools.ietf.org/html/rfc2461

- Internet Control Message Protocol (ICMPv6) for the Internet Protocol Version 6 (IPv6) Specification
 http://tools.ietf.org/html/rfc2463

- IPv6 Node Requirements
 http://tools.ietf.org/html/rfc6434
*)

(* This is temporary. See https://github.com/mirage/ocaml-ipaddr/pull/36 *)
module Ipaddr = struct
  module V6 = struct
    include Ipaddr.V6
    let of_cstruct cs =
      let hihi = Cstruct.BE.get_uint32 cs 0 in
      let hilo = Cstruct.BE.get_uint32 cs 4 in
      let lohi = Cstruct.BE.get_uint32 cs 8 in
      let lolo = Cstruct.BE.get_uint32 cs 12 in
      of_int32 (hihi, hilo, lohi, lolo)
    let to_cstruct_raw i cs off =
      let a, b, c, d = to_int32 i in
      Cstruct.BE.set_uint32 cs (0 + off) a;
      Cstruct.BE.set_uint32 cs (4 + off) b;
      Cstruct.BE.set_uint32 cs (8 + off) c;
      Cstruct.BE.set_uint32 cs (12 + off) d
    let to_cstruct ?(allocator = Cstruct.create) i =
      let cs = allocator 16 in
      to_cstruct_raw i cs 0;
      cs
  end
end
module Macaddr = struct
  include Macaddr
  let to_cstruct_raw x cs off =
    Cstruct.blit_from_string (to_bytes x) 0 cs off 6
  let of_cstruct cs =
    if Cstruct.len cs <> 6
    then raise (Parse_error ("MAC is exactly 6 bytes", Cstruct.to_string cs))
    else match of_bytes (Cstruct.to_string cs) with Some x -> x | None -> assert false
end

let (>>=) = Lwt.(>>=)

module Make (Ethif : V1_LWT.ETHIF) = struct
  type ethif = Ethif.t
  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t
  type ipv6addr = Ipaddr.V6.t
  type callback = src:ipv6addr -> dst:ipv6addr -> buffer -> unit Lwt.t

  (* This will have to be moved somewhere else later, since the same computation
     is needed for UDP, TCP, ICMP, etc. over IPv6. Also, [Tcpip_checksum] is a
     bad name since it is used for other protocols as well. *)
  let pbuf =
    Cstruct.of_bigarray (Io_page.get 1)

  (* buf : beginning of ipv6 packet
     off : beginning of higher-layer protocol packet *)
  let cksum ~src ~dst ~proto data =
    Ipaddr.V6.to_cstruct_raw src pbuf 0;
    Ipaddr.V6.to_cstruct_raw dst pbuf 16;
    Cstruct.BE.set_uint32 pbuf 32 (Int32.of_int (Cstruct.lenv data));
    let proto = match proto with `ICMP -> 58 | `TCP -> 6 | `UDP -> 17 in
    Cstruct.BE.set_uint32 pbuf 36 (Int32.of_int proto);
    Tcpip_checksum.ones_complement_list (pbuf :: data)

  type entry =
    | Incomplete of Macaddr.t Lwt_condition.t
    | Verified of Macaddr.t

  type t = {
    ethif : Ethif.t;
    cache: (Ipaddr.V6.t, entry) Hashtbl.t;
    mutable bound_ips : Ipaddr.V6.t list;
    mutable ip : Ipaddr.V6.t;
    mutable netmask : int;
    mutable gateways : Ipaddr.V6.t list
  }

  let solicited_node_prefix =
    Ipaddr.V6.(Prefix.make 104 (of_int16 (0xff02, 0, 0, 0, 0, 1, 0xff00, 0)))

  exception No_route_to_destination_address of Ipaddr.V6.t

  let is_local t ip =
    Ipaddr.V6.Prefix.(mem ip (make t.netmask t.ip))

  let multicast_mac =
    let pbuf = Cstruct.create 6 in
    Cstruct.BE.set_uint16 pbuf 0 0x3333;
    fun ip ->
      let _, _, _, n = Ipaddr.V6.to_int32 ip in
      Cstruct.BE.set_uint32 pbuf 2 n;
      Macaddr.of_cstruct pbuf

  cstruct ns {
      uint32_t reserved;
      uint8_t  target[16];
      uint8_t  opt_ty;
      uint8_t  opt_len;
      uint8_t  mac[6]
    } as big_endian

  (* Stateless Autoconfiguration *)

  let link_local_addr mac =
    let bmac = Macaddr.to_bytes mac in
    let c i = Char.code (Bytes.get bmac i) in
    Ipaddr.V6.make
      0xfe80 0 0 0
      ((c 0 lxor 2) lsl 8 + c 1)
      (c 2 lsl 8 + 0xff)
      (0xfe00 + c 3)
      (c 4 lsl 8 + c 5)

  (* buf points to the ipv6 packet,
     off points to the icmpv6 packet *)
  let nd_na_input t ~src icmpbuf =
    let nsbuf = Cstruct.shift icmpbuf Wire_structs.sizeof_icmpv6 in
    let ip = Ipaddr.V6.of_cstruct (get_ns_target nsbuf) in
    (* if Wire_structs.get_ipv6.hlim buf <> 255 then *)
    (*   Lwt.return_unit *)
    (* else if Wire_structs.get_icmpv6_csum icmpbuf <> checksum buf ~proto:58 off then *)
    (*   Lwt.return_unit *)
    (* else if Wire_structs.get_icmpv6_code icmpbuf <> 0 then *)
    (*   Lwt.return_unit *)
    (* else if Cstruct.len icmpbuf < 24 then *)
    (*   Lwt.return_unit *)
    (* else if Ipaddr.V6.Prefix (mem target multicast) then *)
    (*   Lwt.return_unit *)
    (* else *)
    let mac = Macaddr.of_cstruct (get_ns_mac nsbuf) in
    Printf.printf "NA: updating %s -> %s\n%!" (Ipaddr.V6.to_string ip) (Macaddr.to_string mac);
    if Hashtbl.mem t.cache ip then begin
      match Hashtbl.find t.cache ip with
      | Incomplete cond -> Lwt_condition.broadcast cond mac
      | Verified _ -> ()
    end;
    Hashtbl.replace t.cache ip (Verified mac);
    Lwt.return_unit

  let adjust_length ~tlen buf =
    let buf = Cstruct.shift buf Wire_structs.sizeof_ethernet in
    Wire_structs.set_ipv6_len buf tlen

  let write t frame data =
    adjust_length ~tlen:(Cstruct.len data) frame;
    Ethif.writev t.ethif [ frame; data ]

  let writev t frame data =
    let tlen = Cstruct.lenv data in
    adjust_length ~tlen frame;
    Ethif.writev t.ethif (frame :: data)

  let rec nd_ns_output t ip =
    let solicited_node_ip = Ipaddr.V6.Prefix.network_address solicited_node_prefix ip in
    Printf.printf "NS: who-has %s (-> %s)\n%!" (Ipaddr.V6.to_string ip) (Ipaddr.V6.to_string solicited_node_ip);
    allocate_frame ~proto:`ICMP ~dest_ip:solicited_node_ip t >>= fun buf ->
    (* Fill IPv6 Header *)
    let ipbuf = Cstruct.shift buf Wire_structs.sizeof_ethernet in
    Wire_structs.set_ipv6_hlim ipbuf 255; (* hop limit *)
    let icmpbuf = Cstruct.shift ipbuf Wire_structs.sizeof_ipv6 in
    (* Fill ICMPv6 Header *)
    Wire_structs.set_icmpv6_ty icmpbuf 135; (* NS *)
    Wire_structs.set_icmpv6_code icmpbuf 0;
    let nsbuf = Cstruct.shift icmpbuf Wire_structs.sizeof_icmpv6 in
    (* Fill ICMPv6 Payload *)
    set_ns_reserved nsbuf 0l;
    Ipaddr.V6.to_cstruct_raw ip (get_ns_target nsbuf) 0;
    set_ns_opt_ty nsbuf 1;
    set_ns_opt_len nsbuf 1;
    Macaddr.to_cstruct_raw (Ethif.mac t.ethif) (get_ns_mac nsbuf) 0;
    (* Fill ICMPv6 Checksum *)
    let csum = cksum ~src:t.ip ~dst:solicited_node_ip ~proto:`ICMP [ icmpbuf ] in
    Wire_structs.set_icmpv6_csum icmpbuf csum;

    let buf, data = Cstruct.split buf (Wire_structs.sizeof_ethernet + Wire_structs.sizeof_ipv6) in
    let data = Cstruct.sub data 0 (Wire_structs.sizeof_icmpv6 + sizeof_ns) in
    Cstruct.hexdump buf;
    write t buf data

  and nd_query t ip =
    if Hashtbl.mem t.cache ip then begin
      match Hashtbl.find t.cache ip with
      | Incomplete cond ->
        Printf.printf "NDP6 query: %s -> [incomplete]\n%!" (Ipaddr.V6.to_string ip);
        Lwt_condition.wait cond
      | Verified mac ->
        Lwt.return mac
    end else begin
      let cond = Lwt_condition.create () in
      Printf.printf "NDP6 query: %s -> [probe]\n%!" (Ipaddr.V6.to_string ip);
      Hashtbl.add t.cache ip (Incomplete cond);
      nd_ns_output t ip >>= fun () ->
      Lwt_condition.wait cond
    end

  and destination_mac t = function
    | ip when Ipaddr.V6.is_multicast ip ->
      Lwt.return (multicast_mac ip)
    | ip when is_local t ip ->
      nd_query t ip
    | ip ->
      begin
        match t.gateways with
        | hd :: _ -> nd_query t hd
        | [] ->
          Printf.printf "IP6: no route to %s\n%!" (Ipaddr.V6.to_string ip);
          Lwt.fail (No_route_to_destination_address ip)
      end

  (* Allocate a new IPv4 frame. Returns the frame with the first
     [Wire_structs.sizeof_ethernet + Wire_structs.sizeof_ipv6] bytes filled
     out. It is the caller's responsability to adjust the [ipv6_len] field/
     restrict the view and add a payload prior to sending. *)
  and allocate_frame ~proto ~dest_ip t =
    let ethernet_frame = Io_page.to_cstruct (Io_page.get 1) in
    destination_mac t dest_ip >>= fun dmac ->
    Macaddr.to_cstruct_raw dmac (Wire_structs.get_ethernet_dst ethernet_frame) 0;
    Macaddr.to_cstruct_raw (Ethif.mac t.ethif) (Wire_structs.get_ethernet_src ethernet_frame) 0;
    Wire_structs.set_ethernet_ethertype ethernet_frame 0x86dd;
    let buf = Cstruct.shift ethernet_frame Wire_structs.sizeof_ethernet in
    (* Write the constant IPv6 header fields *)
    Wire_structs.set_ipv6_version_flow buf 0x60000000l; (* IPv6 *)
    let proto = match proto with `ICMP -> 58 | `TCP -> 6 | `UDP -> 17 in
    Wire_structs.set_ipv6_nhdr buf proto; (* ICMP *)
    Wire_structs.set_ipv6_hlim buf 64; (* Same as IPv4 TTL ? TODO *)
    Ipaddr.V6.to_cstruct_raw t.ip (Wire_structs.get_ipv6_src buf) 0;
    Ipaddr.V6.to_cstruct_raw dest_ip (Wire_structs.get_ipv6_dst buf) 0;
    Lwt.return ethernet_frame

    (* buf : full ipv6 packet
       off : offset of the start of icmpv6 packet *)
  let icmp_input t ~src ~dst buf =
    (* let icmp6 = Cstruct.shift buf off in *)
    let csum = cksum ~src ~dst ~proto:`ICMP [ buf ] in
    if not (csum = 0) then begin
      Printf.printf "ICMP6 checksum error (0x%x)\n%!" csum;
      Lwt.return_unit (* checksum does not match, drop packet *)
    end else begin
      Printf.printf "ICMP6 checksum correct!\n%!";
      match Wire_structs.get_icmpv6_ty buf with
      | 128 (* TODO Echo request *) ->
        Printf.printf "Got ICMP6 Echo Request\n%!";
        Wire_structs.set_icmpv6_ty buf 129;
        Wire_structs.set_icmpv6_code buf 0;
        allocate_frame ~proto:`ICMP ~dest_ip:src t >>= fun ipbuf ->
        let ipbuf = Cstruct.set_len ipbuf (Wire_structs.sizeof_ethernet + Wire_structs.sizeof_ipv6) in
        Wire_structs.set_icmpv6_csum buf 0;
        Wire_structs.set_icmpv6_csum buf (cksum ~src:t.ip ~dst:src ~proto:`ICMP [ buf ]);
        write t ipbuf buf
      | 129 (* Echo reply *) ->
        Printf.printf "ICMP6: discarding echo reply\n%!";
        Lwt.return_unit
      | 135 (* NS *) ->
        if Wire_structs.get_ipv6_hlim buf <> 255 then
          (* off-link sender spoofing local icmpv6 messages:
             drop packet *)
          Lwt.return_unit
        else
          Lwt.return_unit (* TODO *)
      | 136 (* NA *) ->
        nd_na_input t ~src buf
      | n ->
        Printf.printf "ICMP6: unrecognized type (%d)\n%!" n;
        Lwt.return_unit (* TODO *)
    end

  let input ~tcp ~udp ~default _t buf =
    (* let buf = Cstruct.sub buf 0 (Wire_structs.get_ipv6_len buf + Wire_structs.sizeof_ipv6) in *)
    (* Cstruct.hexdump buf; *)
    let src = Ipaddr.V6.of_cstruct (Wire_structs.get_ipv6_src buf) in
    let dst = Ipaddr.V6.of_cstruct (Wire_structs.get_ipv6_dst buf) in
    Printf.printf "Got IPv6 Packet (proto:%d) %s -> %s\n%!"
      (Wire_structs.get_ipv6_nhdr buf)
      (Ipaddr.V6.to_string src) (Ipaddr.V6.to_string dst);
    (* See http://en.wikipedia.org/wiki/List_of_IP_protocol_numbers *)
    let rec loop first hdr off =
      match hdr with
      | 0 when first -> (* HOPOPT *)
        loop false (Cstruct.get_uint8 buf 0) (8 + 8 * Cstruct.get_uint8 buf 1)
      | 0 ->
        (* HOPOPT should only appear in first position. So we drop this packet. *)
        Lwt.return_unit
      | 60 -> (* TODO IPv6-Opts *)
        Lwt.return_unit
      | 43 -> (* TODO IPv6-Route *)
        Lwt.return_unit
      | 44 (* TODO IPv6-Frag *)
      | 50 (* TODO ESP *)
      | 51 (* TODO AH *)
      | 135 -> (* TODO Mobility Header *)
        Lwt.return_unit
      | 59 (* NO NEXT HEADER *) ->
        Lwt.return_unit
      | 58 (* ICMP *) ->
        icmp_input _t ~src ~dst (Cstruct.shift buf Wire_structs.sizeof_ipv6)
      | 17 (* UDP *) ->
        udp (Cstruct.shift buf off)
      | 6 (* TCP *) ->
        tcp (Cstruct.shift buf off)
      | n when 143 <= n && n <= 255 ->
        (* UNASSIGNED, EXPERIMENTAL & RESERVED *)
        Lwt.return_unit
      | n ->
        (* let src = Ipaddr.V6.of_cstruct src in *)
        (* let dst = Ipaddr.V6.of_cstruct dst in *)
        default ~proto:n ~src ~dst buf
    in
    loop true (Wire_structs.get_ipv6_nhdr buf) Wire_structs.sizeof_ipv6

  let connect e =
    let i = Ipaddr.V6.of_string_exn in
    Lwt.return (`Ok { ethif = e;
                      cache = Hashtbl.create 0;
                      bound_ips = [ i "::ffff:10.0.0.2" ];
                      ip = i "::ffff:10.0.0.2";
                      netmask = 120;
                      gateways = [ i "::ffff:10.0.0.1" ] })
end
