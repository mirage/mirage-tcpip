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

- Multicast Listener Discovery Version 2 (MLDv2) for IPv6
 http://tools.ietf.org/html/rfc3810
*)

(* This is temporary. See https://github.com/mirage/ocaml-ipaddr/pull/36 *)

open Ndpv6

module List = struct
  include List
  let rec fmap f = function
    | [] -> []
    | x :: xs ->
      match f x with
      | None -> fmap f xs
      | Some x -> x :: fmap f xs
  let rec find_map f = function
    | [] -> raise Not_found
    | x :: xs ->
      match f x with
      | None -> find_map f xs
      | Some y -> y
end

module Ipv6_wire = Wire_structs.Ipv6_wire

module Ipaddr = struct
  include Ipaddr
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

module Macaddr = struct
  include Macaddr
  let to_cstruct_raw x cs off =
    Cstruct.blit_from_string (to_bytes x) 0 cs off 6
  let of_cstruct cs =
    if Cstruct.len cs <> 6
    then raise (Parse_error ("MAC is exactly 6 bytes", Cstruct.to_string cs))
    else match of_bytes (Cstruct.to_string cs) with Some x -> x | None -> assert false
end

let interface_addr mac =
  let bmac = Macaddr.to_bytes mac in
  let c i = Char.code (Bytes.get bmac i) in
  Ipaddr.make
    0 0 0 0
    ((c 0 lxor 2) lsl 8 + c 1)
    (c 2 lsl 8 + 0xff)
    (0xfe00 + c 3)
    (c 4 lsl 8 + c 5)

let link_local_addr mac =
  Ipaddr.(Prefix.network_address Prefix.link (interface_addr mac))

let multicast_mac =
  let pbuf = Cstruct.create 6 in
  Cstruct.BE.set_uint16 pbuf 0 0x3333;
  fun ip ->
    let _, _, _, n = Ipaddr.to_int32 ip in
    Cstruct.BE.set_uint32 pbuf 2 n;
    Macaddr.of_bytes_exn (Cstruct.to_string pbuf)

let float_of_uint32 n = Uint32.to_float @@ Uint32.of_int32 n

module Defaults = struct
  let min_random_factor          = 0.5
  let max_random_factor          = 1.5
  let reachable_time             = 30.0
  let retrans_timer              = 1.0

  let link_mtu     = 1500 (* RFC 2464, 2. *)
  let min_link_mtu = 1280
end

let compute_reachable_time dt =
  let r = Defaults.(min_random_factor +. Random.float (max_random_factor -. min_random_factor)) in
  r *. dt

let cksum_buf =
  let pbuf = Io_page.to_cstruct (Io_page.get 1) in
  Cstruct.set_len pbuf 8

let checksum' ~proto frame bufs =
  Cstruct.BE.set_uint32 cksum_buf 0 (Int32.of_int (Cstruct.lenv bufs));
  Cstruct.BE.set_uint32 cksum_buf 4 (Int32.of_int proto);
  let src_dst = Cstruct.sub frame 8 (2 * 16) in
  Tcpip_checksum.ones_complement_list (src_dst :: cksum_buf :: bufs)

let checksum frame bufs =
  let frame = Cstruct.shift frame Wire_structs.sizeof_ethernet in
  let proto = Ipv6_wire.get_ipv6_nhdr frame in
  checksum' ~proto frame bufs

module Allocate = struct
  let frame ~mac ~hlim ~src ~dst ~proto () =
    let ethernet_frame = Io_page.to_cstruct (Io_page.get 1) in
    let ipbuf = Cstruct.shift ethernet_frame Wire_structs.sizeof_ethernet in
    Macaddr.to_cstruct_raw mac (Wire_structs.get_ethernet_src ethernet_frame) 0;
    Wire_structs.set_ethernet_ethertype ethernet_frame 0x86dd; (* IPv6 *)
    Ipv6_wire.set_ipv6_version_flow ipbuf 0x60000000l; (* IPv6 *)
    Ipaddr.to_cstruct_raw src (Ipv6_wire.get_ipv6_src ipbuf) 0;
    Ipaddr.to_cstruct_raw dst (Ipv6_wire.get_ipv6_dst ipbuf) 0;
    Ipv6_wire.set_ipv6_hlim ipbuf hlim;
    Ipv6_wire.set_ipv6_nhdr ipbuf proto;
    let header_len = Wire_structs.sizeof_ethernet + Ipv6_wire.sizeof_ipv6 in
    (ethernet_frame, header_len)

  let error ~mac ~src ~dst ~ty ~code ?(reserved = 0l) buf =
    let eth_frame, header_len = frame ~mac ~src ~dst ~hlim:255 ~proto:58 () in
    let eth_frame = Cstruct.set_len eth_frame (header_len + Ipv6_wire.sizeof_icmpv6) in
    let maxbuf = Defaults.min_link_mtu - (header_len + Ipv6_wire.sizeof_icmpv6) in
    (* FIXME ? hlim = 255 *)
    let buf = Cstruct.sub buf 0 (min (Cstruct.len buf) maxbuf) in
    let icmpbuf = Cstruct.set_len eth_frame Ipv6_wire.sizeof_icmpv6 in
    Ipv6_wire.set_icmpv6_ty icmpbuf ty;
    Ipv6_wire.set_icmpv6_code icmpbuf code;
    Ipv6_wire.set_icmpv6_reserved icmpbuf reserved;
    Ipv6_wire.set_icmpv6_csum icmpbuf 0;
    Ipv6_wire.set_icmpv6_csum icmpbuf @@ checksum eth_frame [ icmpbuf; buf ];
    (eth_frame, buf :: [])

  let ns ~mac ~src ~dst ~tgt =
    let eth_frame, header_len = frame ~mac ~src ~dst ~hlim:255 ~proto:58 () in
    let eth_frame = Cstruct.set_len eth_frame (header_len + Ipv6_wire.sizeof_ns + Ipv6_wire.sizeof_llopt) in
    let icmpbuf = Cstruct.shift eth_frame header_len in
    let optbuf  = Cstruct.shift icmpbuf Ipv6_wire.sizeof_ns in
    Ipv6_wire.set_ns_ty icmpbuf 135; (* NS *)
    Ipv6_wire.set_ns_code icmpbuf 0;
    Ipv6_wire.set_ns_reserved icmpbuf 0l;
    Ipaddr.to_cstruct_raw tgt (Ipv6_wire.get_ns_target icmpbuf) 0;
    Ipv6_wire.set_llopt_ty optbuf  1;
    Ipv6_wire.set_llopt_len optbuf  1;
    Macaddr.to_cstruct_raw mac optbuf 2;
    Ipv6_wire.set_icmpv6_csum icmpbuf 0;
    Ipv6_wire.set_icmpv6_csum icmpbuf @@ checksum eth_frame [ icmpbuf ];
    eth_frame

  let na ~mac ~src ~dst ~tgt ~sol =
    let eth_frame, header_len = frame ~mac ~src ~dst ~hlim:255 ~proto:58 () in
    let eth_frame = Cstruct.set_len eth_frame (header_len + Ipv6_wire.sizeof_na + Ipv6_wire.sizeof_llopt) in
    let icmpbuf = Cstruct.shift eth_frame header_len in
    let optbuf  = Cstruct.shift icmpbuf Ipv6_wire.sizeof_na in
    Ipv6_wire.set_na_ty icmpbuf 136; (* NA *)
    Ipv6_wire.set_na_code icmpbuf 0;
    Ipv6_wire.set_na_reserved icmpbuf (if sol then 0x60000000l else 0x20000000l);
    Ipaddr.to_cstruct_raw tgt (Ipv6_wire.get_na_target icmpbuf) 0;
    Ipv6_wire.set_llopt_ty optbuf 2;
    Ipv6_wire.set_llopt_len optbuf 1;
    Macaddr.to_cstruct_raw mac optbuf 2;
    Ipv6_wire.set_icmpv6_csum icmpbuf 0;
    Ipv6_wire.set_icmpv6_csum icmpbuf @@ checksum eth_frame [ icmpbuf ];
    eth_frame

  let rs ~mac select_source =
    let dst = Ipaddr.link_routers in
    let src = select_source ~dst in
    let eth_frame, header_len = frame ~mac ~src ~dst ~hlim:255 ~proto:58 () in
    let include_slla = Ipaddr.(compare src unspecified) != 0 in
    let eth_frame =
      Cstruct.set_len eth_frame
        (header_len + Ipv6_wire.sizeof_rs + if include_slla then Ipv6_wire.sizeof_llopt else 0)
    in
    let icmpbuf = Cstruct.shift eth_frame header_len in
    Ipv6_wire.set_rs_ty icmpbuf 133;
    Ipv6_wire.set_rs_code icmpbuf 0;
    Ipv6_wire.set_rs_reserved icmpbuf 0l;
    if include_slla then begin
      let optbuf = Cstruct.shift icmpbuf Ipv6_wire.sizeof_rs in
      Macaddr.to_cstruct_raw mac optbuf 2
    end;
    Ipv6_wire.set_icmpv6_csum icmpbuf 0;
    Ipv6_wire.set_icmpv6_csum icmpbuf @@ checksum eth_frame [ icmpbuf ];
    eth_frame

  let pong ~mac ~src ~dst ~id ~seq ~data =
    let eth_frame, header_len = frame ~mac ~src ~dst ~hlim:255 ~proto:58 () in
    let eth_frame = Cstruct.set_len eth_frame (header_len + Ipv6_wire.sizeof_pingv6) in
    let icmpbuf = Cstruct.shift eth_frame header_len in
    Ipv6_wire.set_pingv6_ty icmpbuf 129; (* ECHO REPLY *)
    Ipv6_wire.set_pingv6_code icmpbuf 0;
    Ipv6_wire.set_pingv6_id icmpbuf id;
    Ipv6_wire.set_pingv6_seq icmpbuf seq;
    Ipv6_wire.set_pingv6_csum icmpbuf 0;
    Ipv6_wire.set_pingv6_csum icmpbuf @@ checksum eth_frame (icmpbuf :: data :: []);
    (eth_frame, data :: [])
end

module Packet = struct
  module NS = struct
    type t =
      { target : Ipaddr.t;
        slla   : Macaddr.t option }
  end
  module RA = struct
    type prefix =
      { on_link            : bool;
        autonomous         : bool;
        valid_lifetime     : float option;
        preferred_lifetime : float option;
        prefix             : Ipaddr.Prefix.t }
    type t =
      { cur_hop_limit   : int;
        router_lifetime : float;
        reachable_time  : float option;
        retrans_timer   : float option;
        slla            : Macaddr.t option;
        ra_prefix       : prefix list }
  end
  module NA = struct
    type t =
      { router    : bool;
        solicited : bool;
        override  : bool;
        target    : Ipaddr.t;
        tlla      : Macaddr.t option }
  end
end

module BoundedMap (K : Map.OrderedType) : sig
  type 'a t
  val empty: int -> 'a t
  val push: K.t -> 'a -> 'a t -> 'a t
  val pop: K.t -> 'a t -> 'a list * 'a t
end = struct
  module M = Map.Make (K)
  type 'a t = 'a list M.t * int
  let empty n = M.empty, n
  let push k d (m, n) =
    let l = try M.find k m with Not_found -> [] in
    match l, List.length l >= n with
    | _, false ->
      M.add k (d :: l) m, n
    | _ :: l, true ->
      M.add k (d :: l) m, n
    | [], true ->
      m, n
  let pop k (m, n) =
    let l = try M.find k m with Not_found -> [] in
    l, (M.remove k m, n)
end

module PacketQueue = BoundedMap (Ipaddr)

let float_of_uint32 n =
  Uint32.to_float (Uint32.of_int32 n)

type ndp_option =
  | SLLA of Macaddr.t
  | TLLA of Macaddr.t
  | MTU of int
  | PREFIX of Packet.RA.prefix

module Parser : sig
  type result =
    | Drop
    | DropWithError of int * int * int
    | NA of Ipaddr.t * Ipaddr.t * Packet.NA.t
    | NS of Ipaddr.t * Ipaddr.t * Packet.NS.t
    | RA of Ipaddr.t * Ipaddr.t * Packet.RA.t
    | Ping of Ipaddr.t * Ipaddr.t * int * int * Cstruct.t
    | Pong of Cstruct.t
    | Udp of Ipaddr.t * Ipaddr.t * Cstruct.t
    | Tcp of Ipaddr.t * Ipaddr.t * Cstruct.t
    | Default of int * Ipaddr.t * Ipaddr.t * Cstruct.t

  val packet : (Ipaddr.t -> bool) -> Cstruct.t -> result
end = struct

  type result =
    | Drop
    | DropWithError of int * int * int
    | NA of Ipaddr.t * Ipaddr.t * Packet.NA.t
    | NS of Ipaddr.t * Ipaddr.t * Packet.NS.t
    | RA of Ipaddr.t * Ipaddr.t * Packet.RA.t
    | Ping of Ipaddr.t * Ipaddr.t * int * int * Cstruct.t
    | Pong of Cstruct.t
    | Udp of Ipaddr.t * Ipaddr.t * Cstruct.t
    | Tcp of Ipaddr.t * Ipaddr.t * Cstruct.t
    | Default of int * Ipaddr.t * Ipaddr.t * Cstruct.t

  let rec fold_options f i opts =
    if Cstruct.len opts >= Ipv6_wire.sizeof_opt then
      (* TODO check for invalid len == 0 *)
      let opt, opts = Cstruct.split opts (Ipv6_wire.get_opt_len opts * 8) in
      match Ipv6_wire.get_opt_ty opt, Ipv6_wire.get_opt_len opt with
      | 1, 1 ->
        let o = SLLA (Macaddr.of_cstruct (Ipv6_wire.get_llopt_addr opt)) in
        fold_options f (f i o) opts
      | 2, 1 ->
        let o = TLLA (Macaddr.of_cstruct (Ipv6_wire.get_llopt_addr opt)) in
        fold_options f (f i o) opts
      | 5, 1 ->
        let o = MTU (Int32.to_int (Cstruct.BE.get_uint32 opt 4)) in
        fold_options f (f i o) opts
      | 3, 4 ->
        let prefix =
          Ipaddr.Prefix.make
            (Ipv6_wire.get_opt_prefix_prefix_len opt)
            (Ipaddr.of_cstruct (Ipv6_wire.get_opt_prefix_prefix opt)) in
        let on_link = Ipv6_wire.get_opt_prefix_on_link opt in
        let autonomous = Ipv6_wire.get_opt_prefix_autonomous opt in
        let valid_lifetime =
          let n = Ipv6_wire.get_opt_prefix_valid_lifetime opt in
          match n with
          | 0xffffffffl -> None
          | n -> Some (float_of_uint32 n)
        in
        let preferred_lifetime =
          let n = Ipv6_wire.get_opt_prefix_preferred_lifetime opt in
          match n with
          | 0xffffffffl -> None
          | n -> Some (float_of_uint32 n)
        in
        let pfx = {Packet.RA.on_link; autonomous; valid_lifetime; preferred_lifetime; prefix} in
        let o = PREFIX pfx in
        fold_options f (f i o) opts
      | ty, len ->
        Printf.printf "ND: Unsupported ND option in RA (ty=%d,len=%d)\n%!" ty len;
        fold_options f i opts
    else
      i

  let parse_ra buf =
    let cur_hop_limit = Ipv6_wire.get_ra_cur_hop_limit buf in
    let router_lifetime =
      float_of_int (Ipv6_wire.get_ra_router_lifetime buf)
    in
    let reachable_time =
      let n = Ipv6_wire.get_ra_reachable_time buf in
      if n = 0l then None
      else
        let dt = (float_of_uint32 n) /. 1000.0 in
        Some dt
    in
    let retrans_timer =
      let n = Ipv6_wire.get_ra_retrans_timer buf in
      if n = 0l then None
      else
        let dt = (float_of_uint32 n) /. 1000.0 in
        Some dt
    in
    let opts = Cstruct.shift buf Ipv6_wire.sizeof_ra in
    let slla, ra_prefix =
      fold_options begin fun ra opt ->
        match opt with
        | SLLA slla     -> let _, pfxs = ra in Some slla, pfxs
        | PREFIX pfx -> let slla, pfxs = ra in slla, (pfx :: pfxs)
        | _ -> ra
      end (None, []) opts
    in
    {Packet.RA.cur_hop_limit; router_lifetime; reachable_time; retrans_timer; slla; ra_prefix}

  let parse_ns buf =
    (* FIXME check code = 0 or drop *)
    let target = Ipaddr.of_cstruct (Ipv6_wire.get_ns_target buf) in
    let opts = Cstruct.shift buf Ipv6_wire.sizeof_ns in
    let slla =
      fold_options begin fun ns opt ->
        match opt with
        | SLLA slla -> Some slla
        | _ -> ns
      end None opts
    in
    {Packet.NS.target; slla}

  let parse_na buf =
    (* FIXME check code = 0 or drop *)
    let router    = Ipv6_wire.get_na_router buf in
    let solicited = Ipv6_wire.get_na_solicited buf in
    let override  = Ipv6_wire.get_na_override buf in
    let target    = Ipaddr.of_cstruct (Ipv6_wire.get_na_target buf) in
    let opts      = Cstruct.shift buf Ipv6_wire.sizeof_na in
    let tlla      =
      fold_options begin fun na opt ->
        match opt with
        | TLLA tlla -> Some tlla
        | _ -> na
      end None opts
    in
    {Packet.NA.router; solicited; override; target; tlla}

  (* buf : icmp packet with ipv6 header *)
  let parse_icmp ~src ~dst buf poff =
    let icmpbuf  = Cstruct.shift buf poff in
    let csum = checksum' ~proto:58 buf [ icmpbuf ] in
    if csum != 0 then begin
      Printf.printf "ICMP6: Checksum error (0x%x), dropping packet\n%!" csum;
      Drop
    end else
      match Ipv6_wire.get_icmpv6_ty icmpbuf with
      | 128 -> (* Echo request *)
        let id = Cstruct.BE.get_uint16 icmpbuf 4 in
        let seq = Cstruct.BE.get_uint16 icmpbuf 6 in
        Ping (src, dst, id, seq, Cstruct.shift icmpbuf 8)
      | 129 (* Echo reply *) ->
        Pong (Cstruct.shift buf poff)
      (* Printf.printf "ICMP6: Discarding Echo Reply\n%!"; *)
      | 133 (* RS *) ->
        (* RFC 4861, 2.6.2 *)
        Drop
      | 134 (* RA *) ->
        if Ipv6_wire.get_ipv6_hlim buf <> 255 then
          Drop
        else
          RA (src, dst, parse_ra icmpbuf)
      | 135 (* NS *) ->
        if Ipv6_wire.get_ipv6_hlim buf <> 255 then
          Drop
        else
          let ns = parse_ns icmpbuf in
          if Ipaddr.is_multicast ns.Packet.NS.target then
            Drop
          else
            NS (src, dst, ns)
      | 136 (* NA *) ->
        if Ipv6_wire.get_ipv6_hlim buf <> 255 then
          Drop
        else
          let na = parse_na icmpbuf in
          if Ipaddr.is_multicast na.Packet.NA.target || (na.Packet.NA.solicited && Ipaddr.is_multicast dst) then
            Drop
          else
            NA (src, dst, na)
      | n ->
        Printf.printf "ICMP6: Unknown packet type (%d)\n%!" n;
        Drop

  let packet is_my_addr buf =
    let src = Ipaddr.of_cstruct (Ipv6_wire.get_ipv6_src buf) in
    let dst = Ipaddr.of_cstruct (Ipv6_wire.get_ipv6_dst buf) in

    (* TODO check version = 6 *)

    (* Printf.printf "IPv6 packet received from %s to %s\n%!" *)
    (* (Ipaddr.to_string src) (Ipaddr.to_string dst); *)

    let rec parse_extension first hdr poff =
      match hdr with
      | 0 (* HOPTOPT *) when first ->
        Printf.printf "Processing HOPOPT header\n%!";
        parse_options poff
      | 0 ->
        Drop
      | 60 (* IPv6-Opts *) ->
        Printf.printf "Processing DESTOPT header\n%!";
        parse_options poff
      | 43 (* IPv6-Route *) | 44 (* IPv6-Frag *) | 50 (* ESP *) | 51 (* AH *) | 135 (* Mobility Header *)
      | 59 (* NO NEXT HEADER *) ->
        Drop
      | 58 (* ICMP *) ->
        parse_icmp ~src ~dst buf poff
      | 17 (* UDP *) ->
        Udp (src, dst, Cstruct.shift buf poff)
      | 6 (* TCP *) ->
        Tcp (src, dst, Cstruct.shift buf poff)
      | n when 143 <= n && n <= 255 ->
        (* UNASSIGNED, EXPERIMENTAL & RESERVED *)
        Drop
      | n ->
        Default (n, src, dst, Cstruct.shift buf poff)

    and parse_options poff =
      let pbuf = Cstruct.shift buf poff in
      let nhdr = Ipv6_wire.get_opt_ty pbuf in
      let olen = Ipv6_wire.get_opt_len pbuf * 8 + 8 in
      let oend = olen + poff in
      let rec loop ooff =
        if ooff < oend then
          let obuf = Cstruct.shift buf ooff in
          match Ipv6_wire.get_opt_ty obuf with
          | 0 ->
            Printf.printf "Processing PAD1 option\n%!";
            loop (ooff+1)
          | 1 ->
            Printf.printf "Processing PADN option\n%!";
            let len = Ipv6_wire.get_opt_len obuf in
            loop (ooff+len+2)
          | _ as n ->
            Printf.printf "Processing unknown option, MSB %x\n%!" n;
            let len = Ipv6_wire.get_opt_len obuf in
            match n land 0xc0 with
            | 0x00 ->
              loop (ooff+len+2)
            | 0x40 ->
              (* discard the packet *)
              Drop
            | 0x80 ->
              (* discard, send icmp error *)
              DropWithError (4, 2, ooff)
            | 0xc0 ->
              (* discard, send icmp error if dest is not mcast *)
              if Ipaddr.is_multicast dst then
                Drop
              else
                DropWithError (4, 2, ooff)
            | _ ->
              assert false
        else
          parse_extension false nhdr oend
      in
      loop (poff+2)

    in

    if Ipaddr.Prefix.(mem src multicast) then begin
      Printf.printf "Dropping packet, src is mcast\n%!";
      Drop
    end else if not (is_my_addr dst || Ipaddr.Prefix.(mem dst multicast)) then begin
      Printf.printf "Dropping packet, not for me\n%!";
      Drop
    end else
      parse_extension true (Ipv6_wire.get_ipv6_nhdr buf) Ipv6_wire.sizeof_ipv6

end

(* TODO add destination cache *)
type state = {
  neighbor_cache      : NeighborCache.t;
  prefix_list         : PrefixList.t;
  router_list         : RouterList.t;
  mac                 : Macaddr.t;
  address_list        : AddressList.t;
  link_mtu            : int;
  cur_hop_limit       : int;
  base_reachable_time : float;
  reachable_time      : float;
  retrans_timer       : float;
  packet_queue        : (Macaddr.t -> Cstruct.t list) PacketQueue.t
}

type action =
  | Send  of Cstruct.t list
  | Sleep of float

let next_hop state ip =

  (* RFC 2461, 5.2.

     Next-hop determination for a given unicast destination operates as follows.  The
     sender performs a longest prefix match against the Prefix List to determine
     whether the packet's destination is on- or off-link.  If the destination is
     on-link, the next-hop address is the same as the packet's destination
     address.  Otherwise, the sender selects a router from the Default Router
     List (following the rules described in Section 6.3.6).  If the Default
     Router List is empty, the sender assumes that the destination is
     on-link. *)

  if PrefixList.is_local state.prefix_list ip then
    ip, state
  else
    let ip, router_list = RouterList.select state.router_list (NeighborCache.reachable state.neighbor_cache) ip in
    ip, {state with router_list}

let rec run ~now ~state acts =
  let rec loop state acts = function
    | Action.Sleep dt :: rest ->
      Printf.printf "Sleeping for %.1fs\n%!" (dt :> float);
      loop state (Sleep dt :: acts) rest
    | Action.SendNS (unspec, dst, tgt) :: rest ->
      let src = match unspec with
        | Action.Unspecified -> Ipaddr.unspecified
        | Action.Specified -> AddressList.select_source state.address_list ~dst
      in
      Printf.printf "ND6: Sending NS src = %s dst = %s tgt = %s\n%!"
        (Ipaddr.to_string src) (Ipaddr.to_string dst) (Ipaddr.to_string tgt);
      let frame = Allocate.ns ~mac:state.mac ~src ~dst ~tgt in
      let state, acts' = output ~now ~state ~dst frame [] in
      loop state (acts' @ acts) rest
    | Action.SendNA (src, dst, tgt, sol) :: rest ->
      let sol = match sol with Action.Solicited -> true | Action.Unsolicited -> false in
      Printf.printf "ND6: Sending NA src = %s dst = %s tgt = %s sol = %B\n%!"
        (Ipaddr.to_string src) (Ipaddr.to_string dst) (Ipaddr.to_string tgt) sol;
      let frame = Allocate.na ~mac:state.mac ~src ~dst ~tgt ~sol in
      let state, acts' = output ~now ~state ~dst frame [] in
      loop state (acts' @ acts) rest
    | Action.SendRS :: rest ->
      Printf.printf "Sending RS\n%!";
      let frame = Allocate.rs ~mac:state.mac (AddressList.select_source state.address_list) in
      let dst = Ipaddr.link_routers in
      let state, acts' = output ~now ~state ~dst frame [] in
      loop state (acts' @ acts) rest
    | Action.SendQueued (ip, dmac) :: rest ->
      Printf.printf "Sending queued packets to %s (%s)\n%!" (Ipaddr.to_string ip) (Macaddr.to_string dmac);
      let pkts, packet_queue = PacketQueue.pop ip state.packet_queue in
      let pkts = List.map (fun datav -> Send (datav dmac)) pkts in
      loop {state with packet_queue} (pkts @ acts) rest
    | Action.CancelQueued ip :: rest ->
      Printf.printf "Cancelling packets to %s\n%!" (Ipaddr.to_string ip);
      let _, packet_queue = PacketQueue.pop ip state.packet_queue in
      loop {state with packet_queue} acts rest
    | [] ->
      state, acts
  in
  loop state [] acts

and output ~now ~state ~dst frame datav =
  let datav dmac =
    Ipv6_wire.set_ipv6_len (Cstruct.shift frame Wire_structs.sizeof_ethernet)
      (Cstruct.lenv datav + Cstruct.len frame - Wire_structs.sizeof_ethernet - Ipv6_wire.sizeof_ipv6);
    Macaddr.to_cstruct_raw dmac (Wire_structs.get_ethernet_dst frame) 0;
    frame :: datav
  in
  match Ipaddr.is_multicast dst with
  | true ->
    state, [Send (datav (multicast_mac dst))]
  | false ->
    let ip, state = next_hop state dst in
    let nc, mac, acts =
      NeighborCache.query state.neighbor_cache ~now ~reachable_time:state.reachable_time ip in
    let state = {state with neighbor_cache = nc} in
    match mac with
    | Some dmac ->
      Printf.printf "Sending packet to %s (%s)\n%!" (Ipaddr.to_string dst) (Macaddr.to_string dmac);
      let state, acts = run ~now ~state acts in
      state, Send (datav dmac) :: acts
    | None ->
      Printf.printf "Queueing packet to %s\n%!" (Ipaddr.to_string dst);
      let packet_queue = PacketQueue.push ip datav state.packet_queue in
      let state = {state with packet_queue} in
      run ~now ~state acts

let input_ra ~state ~now src dst ra =
  let open Packet in
  Printf.printf "ND: Received RA src = %s dst = %s\n%!" (Ipaddr.to_string src) (Ipaddr.to_string dst);
  let state =
    if ra.RA.cur_hop_limit <> 0 then {state with cur_hop_limit = ra.RA.cur_hop_limit} else state
  in
  let state = match ra.RA.reachable_time with
    | None -> state
    | Some rt ->
      if state.base_reachable_time <> rt then
        {state with base_reachable_time = rt; reachable_time = compute_reachable_time rt}
      else
        state
  in
  let state = match ra.RA.retrans_timer with
    | None -> state
    | Some rt ->
      {state with retrans_timer = rt}
  in
  let state, acts =
    match ra.RA.slla with
    | Some new_mac ->
      let nc, acts = NeighborCache.handle_ra state.neighbor_cache ~src new_mac in
      {state with neighbor_cache = nc}, acts
    | None ->
      state, []
  in
  let state, acts' =
    List.fold_left
      (fun (state, acts) pfx ->
         let vlft = pfx.RA.valid_lifetime in
         let prefix_list, acts = PrefixList.handle_ra state.prefix_list ~now ~vlft pfx.RA.prefix in
         match pfx.RA.autonomous, vlft with
         | _, Some 0.0 ->
           {state with prefix_list}, acts
         | true, Some _ ->
           let plft = pfx.RA.preferred_lifetime in
           let lft = match plft with
             | None -> None
             | Some plft -> Some (plft, vlft)
           in
           let address_list, acts' = (* FIXME *)
             AddressList.configure state.address_list ~now ~retrans_timer:state.retrans_timer
               ~lft state.mac pfx.RA.prefix
           in
           {state with address_list; prefix_list}, acts @ acts'
         | _ ->
           {state with prefix_list}, acts) (state, acts) ra.RA.ra_prefix
  in
  let router_list, acts'' = RouterList.handle_ra state.router_list ~now ~src ~lft:ra.RA.router_lifetime in
  {state with router_list}, acts @ acts' @ acts''

let input_ns state ~now:_ src dst ns =
  let open Packet in
  Printf.printf "ND: Received NS src = %s dst = %s tgt = %s\n%!"
    (Ipaddr.to_string src) (Ipaddr.to_string dst) (Ipaddr.to_string ns.NS.target);
  (* TODO check hlim = 255, target not mcast, code = 0 *)
  let state, acts = match ns.NS.slla with
    | Some new_mac ->
      let nc, acts = NeighborCache.handle_ns state.neighbor_cache ~src new_mac in
      {state with neighbor_cache = nc}, acts
      (* handle_ns_slla ~state ~src new_mac *)
    | None ->
      state, []
  in
  if AddressList.is_my_addr state.address_list ns.NS.target then
    let src = ns.NS.target and dst = src in
(*     (\* Printf.printf "Sending NA to %s from %s with target address %s\n%!" *\) *)
(*       (\* (Ipaddr.to_string dst) (Ipaddr.to_string src) (Ipaddr.to_string target); *\) *)
    state, Action.SendNA (src, dst, ns.NS.target, Action.Solicited) :: acts
  else
    state, acts

let input_na state ~now ~src ~dst na =
  let open Packet in
  Printf.printf "ND: Received NA src = %s dst = %s tgt = %s\n%!"
    (Ipaddr.to_string src) (Ipaddr.to_string dst) (Ipaddr.to_string na.NA.target);

  (* TODO Handle case when na.target is one of my bound IPs. *)

  (* If my_ip is TENTATIVE then fail DAD. *)
  let address_list = AddressList.handle_na state.address_list na.NA.target in
  let nc, acts =
    NeighborCache.handle_na state.neighbor_cache
      ~now ~reachable_time:state.reachable_time
      ~rtr:na.NA.router ~sol:na.NA.solicited ~ovr:na.NA.override ~tgt:na.NA.target
      ~lladdr:na.NA.tlla
  in
  {state with neighbor_cache = nc; address_list}, acts

let input ~now state buf =
  let open Parser in
  match packet (AddressList.is_my_addr state.address_list) buf with
  | Drop ->
    `Drop
  | RA (src, dst, ra) ->
    let state, acts = input_ra ~state ~now src dst ra in
    let state, acts = run ~now ~state acts in
    `Act (state, acts)
  | NS (src, dst, ns) ->
    let state, acts = input_ns state ~now src dst ns in
    let state, acts = run ~now ~state acts in
    `Act (state, acts)
  | NA (src, dst, na) ->
    let state, acts = input_na state ~now ~src ~dst na in
    let state, acts = run ~now ~state acts in
    `Act (state, acts)
  | Default (proto, src, dst, pkt) ->
    `Default (proto, src, dst, pkt)
  | DropWithError (ty, code, off) ->
    `Drop (* TODO *)
  | Ping (src, dst, id, seq, data) ->
    Printf.printf "ICMP6: Received PING src = %s dst = %s id = %d seq = %d\n%!" (Ipaddr.to_string src)
      (Ipaddr.to_string dst) id seq;
    let dst = src
    and src = if Ipaddr.is_multicast dst then AddressList.select_source state.address_list dst else dst in
    let frame, bufs = Allocate.pong ~mac:state.mac ~src ~dst ~id ~seq ~data in
    let state, acts = output ~now ~state ~dst frame bufs in
    `Act (state, acts)
  | Pong buf ->
    `Drop
  | Tcp (src, dst, pkt) ->
    `Tcp (src, dst, pkt)
  | Udp (src, dst, pkt) ->
    `Udp (src, dst, pkt)

let tick ~now state =
  let retrans_timer = state.retrans_timer in
  let address_list, acts = AddressList.tick state.address_list ~now ~retrans_timer in
  let prefix_list = PrefixList.tick state.prefix_list ~now in
  let neighbor_cache, acts' = NeighborCache.tick state.neighbor_cache ~now ~retrans_timer in
  let router_list = RouterList.tick state.router_list ~now in
  let state = {state with address_list; prefix_list; neighbor_cache; router_list} in
  let acts = acts @ acts' in
  run ~now ~state acts

let create ~now mac =
  let state =
    { neighbor_cache       = NeighborCache.empty;
      prefix_list          = PrefixList.link_local;
      router_list          = RouterList.empty;
      mac                  = mac;
      address_list         = AddressList.empty;
      link_mtu             = Defaults.link_mtu;
      cur_hop_limit        = 64; (* TODO *)
      base_reachable_time  = Defaults.reachable_time;
      reachable_time       = compute_reachable_time Defaults.reachable_time;
      retrans_timer        = Defaults.retrans_timer;
      packet_queue         = PacketQueue.empty 3 }
  in
  let ip = link_local_addr mac in
  let address_list, acts =
    AddressList.add state.address_list ~now ~retrans_timer:state.retrans_timer ~lft:None ip
  in
  let state, acts = {state with address_list}, Action.SendRS :: acts in
  run ~now ~state acts

let add_ip ~now state ip =
  let address_list, acts =
    AddressList.add state.address_list ~now ~retrans_timer:state.retrans_timer ~lft:None ip
  in
  let state = {state with address_list} in
  run ~now ~state acts

let get_ip state =
  AddressList.to_list state.address_list

let add_prefix ~now state pfx =
  let prefix_list = PrefixList.add state.prefix_list ~now pfx ~vlft:None in
  {state with prefix_list}

let get_prefix state =
  PrefixList.to_list state.prefix_list

let add_routers ~now state ips =
  let router_list = List.fold_left (RouterList.add ~now) state.router_list ips in
  {state with router_list}

let get_routers state =
  RouterList.to_list state.router_list

let (>>=) = Lwt.(>>=)
let (>|=) = Lwt.(>|=)

module Make (E : V1_LWT.ETHIF) (T : V1_LWT.TIME) (C : V1.CLOCK) = struct
  type ethif    = E.t
  type 'a io    = 'a Lwt.t
  type buffer   = Cstruct.t
  type ipaddr   = Ipaddr.t
  type callback = src:ipaddr -> dst:ipaddr -> buffer -> unit Lwt.t
  type prefix   = Ipaddr.Prefix.t

  type t =
    { ethif : E.t;
      mutable state : state }

  type error =
    [ `Unimplemented
    | `Unknown of string ]

  let id { ethif } = ethif

  let rec run_tick t =
    let now = C.time () in
    let state, acts = tick ~now t.state in
    t.state <- state;
    run t acts

  and run t acts =
    Lwt_list.iter_s begin function
      | Sleep dt ->
        Lwt.ignore_result (T.sleep (dt :> float) >>= fun () -> run_tick t);
        Lwt.return_unit
      | Send pkt ->
        E.writev t.ethif pkt
    end acts

  let allocate_frame t ~dst ~proto =
    let proto = match proto with `ICMP -> 58 | `UDP -> 17 | `TCP -> 6 in
    let src = AddressList.select_source t.state.address_list dst in
    Allocate.frame ~mac:t.state.mac ~src ~hlim:t.state.cur_hop_limit ~dst ~proto ()

  let writev t frame bufs =
    let now = C.time () in
    let dst = Ipaddr.of_cstruct (Ipv6_wire.get_ipv6_dst (Cstruct.shift frame Wire_structs.sizeof_ethernet)) in
    let state, acts = output ~now ~state:t.state ~dst frame bufs in
    t.state <- state;
    run t acts

  let write t frame buf =
    writev t frame [buf]

  let input t ~tcp ~udp ~default buf =
    let now = C.time () in
    match input ~now t.state buf with
    | `Act (st, acts)                 -> t.state <- st; run t acts
    | `Drop                           -> Lwt.return_unit
    | `Tcp (src, dst, pkt)            -> tcp ~src ~dst pkt
    | `Udp (src, dst, pkt)            -> udp ~src ~dst pkt
    | `Default (proto, src, dst, pkt) -> default ~proto ~src ~dst pkt

  let connect ethif =
    Printf.printf "IP6: Starting\n%!";
    let now = C.time () in
    let state, acts = create ~now (E.mac ethif) in
    let t = {state; ethif} in
    run t acts >>= fun () ->
    Lwt.return (`Ok t)

  let disconnect _ = (* TODO *)
    Lwt.return_unit

  let checksum = checksum

  let get_source t ~dst =
    AddressList.select_source t.state.address_list dst

  let set_ip t ip =
    let now = C.time () in
    let state, acts = add_ip ~now t.state ip in
    t.state <- state;
    run t acts

  let get_ip t =
    get_ip t.state

  let set_ip_gateways t ips =
    let now = C.time () in
    let state = add_routers ~now t.state ips in
    t.state <- state;
    Lwt.return_unit

  let get_ip_gateways t =
    get_routers t.state

  let get_ip_netmasks t =
    get_prefix t.state

  let set_ip_netmask t pfx =
    let now = C.time () in
    let state = add_prefix ~now t.state pfx in
    t.state <- state;
    run t []
end
