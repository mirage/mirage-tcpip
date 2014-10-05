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
  let to_cstruct_raw cs off x =
    Cstruct.blit_from_string (to_bytes x) 0 cs off 6
end

let (>>=) = Lwt.(>>=)

module Make (Ethif : V1_LWT.ETHIF) = struct
  type ethif = Ethif.t
  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t
  type ipv6addr = Ipaddr.V6.t
  type callback = src:ipv6addr -> dst:ipv6addr -> buffer -> unit Lwt.t

  type t = {
    ethif : Ethif.t
  }

  (* This will have to be moved somewhere else later, since the same computation
     is needed for UDP, TCP, ICMP, etc. over IPv6. Also, [Tcpip_checksum] is a
     bad name since it is used for other protocols as well. *)
  let pbuf =
     Cstruct.sub (Cstruct.of_bigarray (Io_page.get 1)) 0 8

  (* buf : beginning of ipv6 packet
     off : beginning of higher-layer protocol packet *)
  let cksum buf ~proto off =
    let buf1 = Cstruct.shift buf off in
    Cstruct.BE.set_uint32 pbuf 0 (Int32.of_int (Cstruct.len buf1));
    Cstruct.BE.set_uint32 pbuf 4 (Int32.of_int proto);
    Tcpip_checksum.ones_complement_list
      [ Wire_structs.get_ipv6_src buf;
        Wire_structs.get_ipv6_dst buf;
        pbuf; buf1 ]

  (* let output t buf = *)

  module Icmpv6 = struct

    (* reflect the ip6 packet back to the source. [buf] points to the ip6 packet,
       [off] points to the icmp6 packet. *)
    let reflect nip6 nicmp6 data =
      (* TODO *)
      Lwt.return_unit

    (* buf : full ipv6 packet
       off : offset of the start of icmpv6 packet *)
    let input t buf off =
      let icmp6 = Cstruct.shift buf off in
      let csum = Wire_structs.get_icmpv6_csum icmp6 in
      if csum != cksum buf ~proto:58 off then begin
        Printf.printf "ICMP6 checksum error\n%!";
        Lwt.return_unit (* checksum does not match, drop packet *)
      end else
        match Wire_structs.get_icmpv6_ty icmp6 with
        | 128 (* TODO Echo request *) ->
          let nip6 = Cstruct.create Wire_structs.sizeof_ipv6 in (* FIXME alloc *)
          let nicmp6 = Cstruct.create Wire_structs.sizeof_icmpv6 in (* FIXME alloc *)
          Cstruct.blit buf 0 nip6 0 Wire_structs.sizeof_ipv6;
          Cstruct.blit buf off nicmp6 0 Wire_structs.sizeof_icmpv6;
          let data = Cstruct.shift buf (off + Wire_structs.sizeof_icmpv6) in
          Wire_structs.set_icmpv6_ty nicmp6 129;
          Wire_structs.set_icmpv6_code nicmp6 0;
          reflect nip6 nicmp6 data
        | 129 (* Echo reply *) ->
          Lwt.return (Printf.printf "ICMP6: discarding echo reply\n%!")
        | 135 (* NS/NA *) ->
          if Wire_structs.get_ipv6_hlim buf <> 255 then
            (* off-link sender spoofing local icmpv6 messages:
               drop packet *)
            Lwt.return_unit
          else
            Lwt.return_unit (* TODO *)
        | _ ->
          Lwt.return_unit (* TODO *)
  end

  module Ndv6 = struct
    type entry =
      | Incomplete of Macaddr.t Lwt_condition.t
      | Verified of Macaddr.t

    type t = {
      cache: (Ipaddr.V6.t, entry) Hashtbl.t;
      mutable bound_ips : Ipaddr.V6.t list;
      get_ipv6buf : unit -> Cstruct.t Lwt.t;
      output : Cstruct.t -> unit Lwt.t;
      get_mac : unit -> Macaddr.t;
      get_ip : unit -> Ipaddr.V6.t
    }

    let solicited_node_multicast_addr =
      Ipaddr.V6.(to_cstruct (match of_string "ff02::1:ff00:0" with Some x -> x | None -> assert false))

    cstruct ns {
        uint32_t reserved;
        uint8_t  target[16];
        uint8_t  opt_ty;
        uint8_t  opt_len;
        uint8_t  mac[6]
      } as big_endian

    let ns_output t ip =
      t.get_ipv6buf () >>= fun buf ->
      Wire_structs.set_ipv6_version_flow buf 0x06000000l; (* IPv6 *)
      Wire_structs.set_ipv6_nhdr buf 58; (* ICMP *)
      Wire_structs.set_ipv6_hlim buf 255; (* hop limit *)
      Ipaddr.V6.to_cstruct_raw (t.get_ip ()) (Wire_structs.get_ipv6_src buf) 0;
      Ipaddr.V6.to_cstruct_raw ip (Wire_structs.get_ipv6_dst buf) 0;
      Cstruct.blit solicited_node_multicast_addr 0 (Wire_structs.get_ipv6_dst buf) 0 13;
      let icmpbuf = Cstruct.shift buf Wire_structs.sizeof_ipv6 in
      Wire_structs.set_icmpv6_ty icmpbuf 135; (* NS *)
      Wire_structs.set_icmpv6_code icmpbuf 0;
      let nsbuf = Cstruct.shift icmpbuf Wire_structs.sizeof_icmpv6 in
      set_ns_reserved nsbuf 0l;
      Ipaddr.V6.to_cstruct_raw ip (get_ns_target nsbuf) 0;
      set_ns_opt_ty nsbuf 1;
      set_ns_opt_len nsbuf 1;
      Macaddr.to_cstruct_raw (get_ns_mac nsbuf) 0 (t.get_mac ());
      let buf = Cstruct.sub buf 0 (Wire_structs.sizeof_ipv6 + Wire_structs.sizeof_icmpv6 + sizeof_ns) in
      let csum = cksum buf ~proto:58 Wire_structs.sizeof_icmpv6 in (* ICMP Checksum *)
      Wire_structs.set_icmpv6_csum icmpbuf csum;
      Wire_structs.set_ipv6_len buf (Wire_structs.sizeof_icmpv6 + sizeof_ns); (* FIXME set in Ipv6.output ? *)
      t.output buf

    let na_input t buf =
      Lwt.return_unit (* TODO *)

    let query t ip =
      if Hashtbl.mem t.cache ip then begin
        match Hashtbl.find t.cache ip with
        | Incomplete cond ->
          Printf.printf "ICMP6 query: %s -> [incomplete]\n%!" (Ipaddr.V6.to_string ip);
          Lwt_condition.wait cond
        | Verified mac ->
          Lwt.return mac
      end else begin
        let cond = Lwt_condition.create () in
        Printf.printf "ICMP6 query: %s -> [proble]\n%!" (Ipaddr.V6.to_string ip);
        Hashtbl.add t.cache ip (Incomplete cond);
        ns_output t ip >>= fun () ->
        Lwt_condition.wait cond
      end
  end

  let input ~tcp ~udp ~default _t buf =
    let src = Wire_structs.get_ipv6_src buf in
    let dst = Wire_structs.get_ipv6_dst buf in
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
        Icmpv6.input _t buf off
      | 17 (* UDP *) ->
        udp (Cstruct.shift buf off)
      | 6 (* TCP *) ->
        tcp (Cstruct.shift buf off)
      | n when 143 <= n && n <= 255 ->
        (* UNASSIGNED, EXPERIMENTAL & RESERVED *)
        Lwt.return_unit
      | n ->
        let src = Ipaddr.V6.of_cstruct src in
        let dst = Ipaddr.V6.of_cstruct dst in
        default ~proto:n ~src ~dst buf
    in
    loop true (Wire_structs.get_ipv6_nhdr buf) Wire_structs.sizeof_ipv6
end
