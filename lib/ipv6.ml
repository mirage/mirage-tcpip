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

module Ipv6_wire = Wire_structs.Ipv6_wire

module Defaults = struct
  let link_mtu     = 1500 (* RFC 2464, 2. *)
  let min_link_mtu = 1280
end

module IntMap = Map.Make (struct type t = int let compare n m = n - m end)

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

let allocate_frame state
    ?(src = Ndpv6.select_source_address state) ~dst
    ?(hlim = Ndpv6.cur_hop_limit state) ~proto () =
  let smac = Ndpv6.mac state in
  let ethernet_frame = Io_page.to_cstruct (Io_page.get 1) in
  let ipbuf          = Cstruct.shift ethernet_frame Wire_structs.sizeof_ethernet in
  Macaddr.to_cstruct_raw smac (Wire_structs.get_ethernet_src ethernet_frame) 0;
  Wire_structs.set_ethernet_ethertype ethernet_frame 0x86dd; (* IPv6 *)
  Ipv6_wire.set_ipv6_version_flow ipbuf 0x60000000l; (* IPv6 *)
  Ipaddr.V6.to_cstruct_raw src (Ipv6_wire.get_ipv6_src ipbuf) 0;
  Ipaddr.V6.to_cstruct_raw dst (Ipv6_wire.get_ipv6_dst ipbuf) 0;
  Ipv6_wire.set_ipv6_hlim ipbuf hlim;
  Ipv6_wire.set_ipv6_nhdr ipbuf proto;
  let header_len = Wire_structs.sizeof_ethernet + Ipv6_wire.sizeof_ipv6 in
  (ethernet_frame, header_len)

let allocate_error state ~src ~dst ~ty ~code ?(reserved = 0l) buf =
  let eth_frame, header_len = allocate_frame state ~src ~dst ~hlim:255 ~proto:58 () in
  let eth_frame = Cstruct.set_len eth_frame (header_len + Ipv6_wire.sizeof_icmpv6) in
  let maxbuf = Defaults.min_link_mtu - (header_len + Ipv6_wire.sizeof_icmpv6) in
  (* FIXME ? hlim = 255 *)
  let buf     = Cstruct.sub buf 0 (min (Cstruct.len buf) maxbuf) in
  let icmpbuf = Cstruct.set_len eth_frame Ipv6_wire.sizeof_icmpv6 in
  Ipv6_wire.set_icmpv6_ty       icmpbuf ty;
  Ipv6_wire.set_icmpv6_code     icmpbuf code;
  Ipv6_wire.set_icmpv6_reserved icmpbuf reserved;
  Ipv6_wire.set_icmpv6_csum     icmpbuf 0;
  Ipv6_wire.set_icmpv6_csum     icmpbuf @@ checksum eth_frame [ icmpbuf; buf ];
  (eth_frame, buf :: [])

let allocate_ns state ~src ~dst ~target =
  let eth_frame, header_len = allocate_frame state ~src ~dst ~hlim:255 ~proto:58 () in
  let eth_frame = Cstruct.set_len eth_frame (header_len + Ipv6_wire.sizeof_ns + Ipv6_wire.sizeof_llopt) in
  let icmpbuf = Cstruct.shift eth_frame header_len in
  let optbuf  = Cstruct.shift icmpbuf Ipv6_wire.sizeof_ns in
  Ipv6_wire.set_ns_ty       icmpbuf 135; (* NS *)
  Ipv6_wire.set_ns_code     icmpbuf 0;
  Ipv6_wire.set_ns_reserved icmpbuf 0l;
  Ipaddr.V6.to_cstruct_raw target (Ipv6_wire.get_ns_target icmpbuf) 0;
  Ipv6_wire.set_llopt_ty    optbuf  1;
  Ipv6_wire.set_llopt_len   optbuf  1;
  Macaddr.to_cstruct_raw (Ndpv6.mac state) optbuf 2;
  Ipv6_wire.set_icmpv6_csum     icmpbuf 0;
  Ipv6_wire.set_icmpv6_csum icmpbuf @@ checksum eth_frame [ icmpbuf ];
  eth_frame

let allocate_na state ~src ~dst ~target ~solicited =
  let eth_frame, header_len = allocate_frame state ~src ~dst ~hlim:255 ~proto:58 () in
  let eth_frame = Cstruct.set_len eth_frame (header_len + Ipv6_wire.sizeof_na + Ipv6_wire.sizeof_llopt) in
  let icmpbuf = Cstruct.shift eth_frame header_len in
  let optbuf  = Cstruct.shift icmpbuf Ipv6_wire.sizeof_na in
  Ipv6_wire.set_na_ty       icmpbuf 136; (* NA *)
  Ipv6_wire.set_na_code     icmpbuf 0;
  Ipv6_wire.set_na_reserved icmpbuf (if solicited then 0x60000000l else 0x20000000l);
  Ipaddr.V6.to_cstruct_raw  target  (Ipv6_wire.get_na_target icmpbuf) 0;
  Ipv6_wire.set_llopt_ty    optbuf  2;
  Ipv6_wire.set_llopt_len   optbuf  1;
  Macaddr.to_cstruct_raw (Ndpv6.mac state) optbuf 2;
  Ipv6_wire.set_icmpv6_csum     icmpbuf 0;
  Ipv6_wire.set_icmpv6_csum icmpbuf @@ checksum eth_frame [ icmpbuf ];
  eth_frame

let allocate_rs state =
  let src = Ndpv6.select_source_address state in
  let dst = Ipaddr.V6.link_routers in
  let eth_frame, header_len = allocate_frame state ~src ~dst ~hlim:255 ~proto:58 () in
  let include_slla = Ipaddr.V6.(compare src unspecified) != 0 in
  let eth_frame =
    Cstruct.set_len eth_frame (header_len + Ipv6_wire.sizeof_rs + if include_slla then Ipv6_wire.sizeof_llopt else 0)
  in
  let icmpbuf = Cstruct.shift eth_frame header_len in
  Ipv6_wire.set_rs_ty icmpbuf 133;
  Ipv6_wire.set_rs_code icmpbuf 0;
  Ipv6_wire.set_rs_reserved icmpbuf 0l;
  if include_slla then begin
    let optbuf = Cstruct.shift icmpbuf Ipv6_wire.sizeof_rs in
    Macaddr.to_cstruct_raw (Ndpv6.mac state) optbuf 2
  end;
  Ipv6_wire.set_icmpv6_csum icmpbuf 0;
  Ipv6_wire.set_icmpv6_csum icmpbuf @@ checksum eth_frame [ icmpbuf ];
  eth_frame

let allocate_pong state ~src ~dst ~id ~seq ~data =
  let eth_frame, header_len = allocate_frame state ~src ~dst ~hlim:255 ~proto:58 () in
  let eth_frame = Cstruct.set_len eth_frame (header_len + Ipv6_wire.sizeof_pingv6) in
  let icmpbuf = Cstruct.shift eth_frame header_len in
  Ipv6_wire.set_pingv6_ty       icmpbuf 129; (* ECHO REPLY *)
  Ipv6_wire.set_pingv6_code     icmpbuf 0;
  Ipv6_wire.set_pingv6_id icmpbuf id;
  Ipv6_wire.set_pingv6_seq icmpbuf seq;
  Ipv6_wire.set_pingv6_csum     icmpbuf 0;
  Ipv6_wire.set_pingv6_csum     icmpbuf @@ checksum eth_frame (icmpbuf :: data :: []);
  (eth_frame, data :: [])

let float_of_uint32 n =
  Uint32.to_float (Uint32.of_int32 n)

type ndp_option =
  | SLLA of Macaddr.t
  | TLLA of Macaddr.t
  | MTU of int
  | Prefix of Ndpv6.ra_prefix

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
      let prf_prefix =
        Ipaddr.V6.Prefix.make
          (Ipv6_wire.get_opt_prefix_prefix_len opt)
          (Ipaddr.V6.of_cstruct (Ipv6_wire.get_opt_prefix_prefix opt)) in
      let span x = float_of_uint32 x in
      let prf_on_link = Ipv6_wire.get_opt_prefix_on_link opt in
      let prf_autonomous = Ipv6_wire.get_opt_prefix_autonomous opt in
      let prf_valid_lifetime = span @@ Ipv6_wire.get_opt_prefix_valid_lifetime opt in
      let prf_preferred_lifetime = span @@ Ipv6_wire.get_opt_prefix_preferred_lifetime opt in
      let prf = {Ndpv6.prf_on_link; prf_autonomous; prf_valid_lifetime; prf_preferred_lifetime; prf_prefix} in
      let o = Prefix prf in
      fold_options f (f i o) opts
    | ty, len ->
      Printf.printf "ND: ND option (ty=%d,len=%d) not supported in RA\n%!" ty len;
      fold_options f i opts
  else
    i

type parse_result =
  | Drop
  | DropWithError of int * int * int
  | Ndp of Ipaddr.V6.t * Ipaddr.V6.t * Ndpv6.packet
  | Ping of Ipaddr.V6.t * Ipaddr.V6.t * int * int * Cstruct.t
  | Pong of Cstruct.t
  | Udp of Ipaddr.V6.t * Ipaddr.V6.t * Cstruct.t
  | Tcp of Ipaddr.V6.t * Ipaddr.V6.t * Cstruct.t
  | Default of int * Ipaddr.V6.t * Ipaddr.V6.t * Cstruct.t

let parse_ra ~src ~dst buf =
  let ra_cur_hop_limit = Ipv6_wire.get_ra_cur_hop_limit buf in
  let ra_router_lifetime = float_of_int (Ipv6_wire.get_ra_router_lifetime buf) in
  let ra_reachable_time = (float_of_uint32 @@ Ipv6_wire.get_ra_reachable_time buf) /. 1000.0 in
  let ra_retrans_timer = (float_of_uint32 @@ Ipv6_wire.get_ra_retrans_timer buf) /. 1000.0 in
  let ra_opts = Cstruct.shift buf Ipv6_wire.sizeof_ra in
  let ra_slla, ra_prefix =
    fold_options begin fun ra opt ->
      match opt with
      | SLLA ra_slla     -> let _, ra_prefix = ra in Some ra_slla, ra_prefix
      | Prefix ra_prefix -> let ra_slla, _ = ra in ra_slla, Some ra_prefix
      | _ -> ra
    end (None, None) ra_opts
  in
  let ra = {Ndpv6.ra_cur_hop_limit; ra_router_lifetime; ra_reachable_time; ra_retrans_timer; ra_slla; ra_prefix} in
  Ndp (src, dst, Ndpv6.RA ra)

let parse_ns ~src ~dst buf =
  let ns_target = Ipaddr.V6.of_cstruct (Ipv6_wire.get_ns_target buf) in
  let ns_opts = Cstruct.shift buf Ipv6_wire.sizeof_ns in
  let ns_slla =
    fold_options begin fun ns opt ->
      match opt with
      | SLLA ra_slla -> Some ra_slla
      | _ -> ns
    end None ns_opts
  in
  Ndp (src, dst, Ndpv6.NS {Ndpv6.ns_target; ns_slla})

let parse_na ~src ~dst buf =
  let na_router    = Ipv6_wire.get_na_router buf in
  let na_solicited = Ipv6_wire.get_na_solicited buf in
  let na_override  = Ipv6_wire.get_na_override buf in
  let na_target    = Ipaddr.V6.of_cstruct (Ipv6_wire.get_na_target buf) in
  let na_opts      = Cstruct.shift buf Ipv6_wire.sizeof_na in
  let na_tlla      =
    fold_options begin fun na opt ->
      match opt with
      | TLLA na_tlla -> Some na_tlla
      | _ -> na
    end None na_opts
  in
  Ndp (src, dst, Ndpv6.NA {Ndpv6.na_router; na_solicited; na_override; na_target; na_tlla})

(* buf : icmp packet with ipv6 header *)
let parse_icmp ~src ~dst buf poff =
  let icmpbuf  = Cstruct.shift buf poff in
  let csum = checksum' ~proto:58 buf [ icmpbuf ] in
  if csum != 0 then
    let () = Printf.printf "ICMP6 checksum error (0x%x), dropping packet\n%!" csum in
    Drop
  else
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
      parse_ra ~src ~dst icmpbuf
    | 135 (* NS *) ->
      parse_ns ~src ~dst icmpbuf
    | 136 (* NA *) ->
      parse_na ~src ~dst icmpbuf
    | n ->
      let () = Printf.printf "ICMP6: unrecognized type (%d)\n%!" n in
      Drop

let parse_packet ~state buf =
  let src = Ipaddr.V6.of_cstruct (Ipv6_wire.get_ipv6_src buf) in
  let dst = Ipaddr.V6.of_cstruct (Ipv6_wire.get_ipv6_dst buf) in

  (* TODO check version = 6 *)

  (* Printf.printf "IPv6 packet received from %s to %s\n%!" *)
  (* (Ipaddr.V6.to_string src) (Ipaddr.V6.to_string dst); *)

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
            if Ipaddr.V6.is_multicast dst then
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

  if Ipaddr.V6.Prefix.(mem src multicast) then begin
    Printf.printf "Dropping packet, src is mcast\n%!";
    Drop
  end else if not (Ndpv6.is_my_addr state dst || Ipaddr.V6.Prefix.(mem dst multicast)) then begin
    Printf.printf "Dropping packet, not for me\n%!";
    Drop
  end else
    parse_extension true (Ipv6_wire.get_ipv6_nhdr buf) Ipv6_wire.sizeof_ipv6

type action =
  | Send  of Cstruct.t list
  | Sleep of float

let rec run ~now ~state ~queued acts =
  let rec loop state queued acts = function
    | Ndpv6.Sleep dt :: rest ->
      Printf.printf "Sleeping for %.1fs\n%!" dt;
      loop state queued (Sleep dt :: acts) rest
    | Ndpv6.SendNS (src, dst, target) :: rest ->
      Printf.printf "Sending NS from %s to %s with target %s\n%!"
        (Ipaddr.V6.to_string src) (Ipaddr.V6.to_string dst) (Ipaddr.V6.to_string target);
      let frame = allocate_ns state ~src ~dst ~target in
      let (state, queued), acts' = output ~now (state, queued) ~dst frame [] in
      loop state queued (acts' @ acts) rest
    | Ndpv6.SendNA (src, dst, target, solicited) :: rest ->
      Printf.printf "Sending (%ssolicited) NA from %s to %s with target %s\n%!"
        (if solicited then "" else "un")
        (Ipaddr.V6.to_string src) (Ipaddr.V6.to_string dst) (Ipaddr.V6.to_string target);
      let frame = allocate_na state ~src ~dst ~target ~solicited in
      let (state, queued), acts' = output ~now (state, queued) ~dst frame [] in
      loop state queued (acts' @ acts) rest
    | Ndpv6.SendRS :: rest ->
      Printf.printf "Sending RS\n%!";
      let frame = allocate_rs state in
      let dst = Ipaddr.V6.link_routers in
      let (state, queued), acts' = output ~now (state, queued) ~dst frame [] in
      loop state queued (acts' @ acts) rest
    | Ndpv6.SendQueued (i, dmac) :: rest ->
      Printf.printf "Sending queued packet #%d to %s\n%!" i (Macaddr.to_string dmac);
      if IntMap.mem i queued then
        let datav = IntMap.find i queued in
        let queued = IntMap.remove i queued in
        loop state queued (Send (datav dmac) :: acts) rest
      else
        (* FIXME log warning / error / assert false *)
        loop state queued acts rest
    | Ndpv6.CancelQueued i :: rest ->
      Printf.printf "Cancelling packet #%d\n%!" i;
      loop state (IntMap.remove i queued) acts rest
    | [] ->
      (state, queued), acts
  in
  loop state queued [] acts

and output ~now (state, queued) ~dst frame datav =
  let datav dmac =
    Ipv6_wire.set_ipv6_len (Cstruct.shift frame Wire_structs.sizeof_ethernet)
      (Cstruct.lenv datav + Cstruct.len frame - Wire_structs.sizeof_ethernet - Ipv6_wire.sizeof_ipv6);
    Macaddr.to_cstruct_raw dmac (Wire_structs.get_ethernet_dst frame) 0;
    frame :: datav
  in
  let state, output, acts = Ndpv6.output ~now ~state ~dst in
  match output with
  | Ndpv6.SendNow dmac ->
    Printf.printf "Sending packet to %s\n%!" (Ipaddr.V6.to_string dst);
    let (state, queued), acts = run ~now ~state ~queued acts in
    (state, queued), Send (datav dmac) :: acts
  | Ndpv6.SendLater i ->
    Printf.printf "Queueing packet #%d to %s\n%!" i (Ipaddr.V6.to_string dst);
    let queued = IntMap.add i datav queued in
    run ~now ~state ~queued acts

let input ~now ((state, queued) as st) buf =
  let p = parse_packet ~state buf in
  match p with
  | Drop ->
    `Drop
  | Ndp (src, dst, packet) ->
    let state, acts = Ndpv6.input ~now ~state ~src ~dst packet in
    let st, acts = run ~now ~state ~queued acts in
    `Act (st, acts)
  | Default (proto, src, dst, pkt) ->
    `Default (proto, src, dst, pkt)
  | DropWithError (ty, code, off) ->
    `Drop (* TODO *)
  | Ping (src, dst, id, seq, data) ->
    Printf.printf "Received PING from %s to %s (id=%d,seq=%d)\n%!" (Ipaddr.V6.to_string src)
      (Ipaddr.V6.to_string dst) id seq;
    let dst = src
    and src = if Ipaddr.V6.is_multicast dst then Ndpv6.select_source_address state else dst in
    let frame, bufs = allocate_pong state ~src ~dst ~id ~seq ~data in
    let st, acts = output ~now st ~dst frame bufs in
    `Act (st, acts)
  | Pong buf ->
    `Drop
  | Tcp (src, dst, pkt) ->
    `Tcp (src, dst, pkt)
  | Udp (src, dst, pkt) ->
    `Udp (src, dst, pkt)

let tick ~now (state, queued) =
  let state, acts = Ndpv6.tick ~now ~state in
  run ~now ~state ~queued acts

let create ~now mac =
  let state, acts = Ndpv6.create ~now mac in
  run ~now ~state ~queued:IntMap.empty acts

let add_ip ~now (state, queued) ip =
  let state, acts = Ndpv6.add_ip ~now ~state ip in
  run ~now ~state ~queued acts

let get_ipv6 (state, _) =
  Ndpv6.get_ipv6 state

let add_prefix ~now (state, queued) prf =
  let state, acts = Ndpv6.add_prefix ~now ~state prf in
  run ~now ~state ~queued acts

let add_routers ~now (state, queued) ips =
  let state =
    List.fold_left (fun state ip -> Ndpv6.add_router ~now ~state ip) state ips
  in
  state, queued

let get_routers (state, _) =
  Ndpv6.get_routers state

let (>>=) = Lwt.(>>=)
let (>|=) = Lwt.(>|=)

module Make (E : V1_LWT.ETHIF) (T : V1_LWT.TIME) (C : V1.CLOCK) = struct
  type ethif    = E.t
  type 'a io    = 'a Lwt.t
  type buffer   = Cstruct.t
  type ipaddr   = Ipaddr.V6.t
  type callback = src:ipaddr -> dst:ipaddr -> buffer -> unit Lwt.t
  type prefix   = Ipaddr.V6.Prefix.t

  type queued = (Macaddr.t -> Cstruct.t list) IntMap.t
  type t =
    { ethif : E.t;
      mutable state : Ndpv6.state * queued }

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
        Lwt.ignore_result (T.sleep dt >>= fun () -> run_tick t);
        Lwt.return_unit
      | Send pkt ->
        E.writev t.ethif pkt
    end acts

  let allocate_frame t ~dst ~proto =
    let proto = match proto with `ICMP -> 58 | `UDP -> 17 | `TCP -> 6 in
    allocate_frame (fst t.state) ~dst ~proto ()

  let writev t frame bufs =
    let now = C.time () in
    let dst = Ipaddr.V6.of_cstruct (Ipv6_wire.get_ipv6_dst (Cstruct.shift frame Wire_structs.sizeof_ethernet)) in
    let state, acts = output ~now t.state ~dst frame bufs in
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
    T.sleep 10.0 >>= fun () ->
    Printf.printf "Starting\n%!";
    let now = C.time () in
    let state, acts = create ~now (E.mac ethif) in
    let t = {state; ethif} in
    run t acts >>= fun () ->
    Lwt.return (`Ok t)

  let disconnect _ = (* TODO *)
    Lwt.return_unit

  let set_ipv6 t ip =
    let state, acts = add_ip ~now:(C.time ()) t.state ip in
    t.state <- state;
    run t acts

  let get_ipv6 t =
    get_ipv6 t.state

  let checksum = checksum

  let get_source t ~dst =
    Ndpv6.select_source_address (fst t.state) (* FIXME dst *)

  let set_ip_gateways t ips =
    let now = C.time () in
    let state = add_routers ~now t.state ips in
    t.state <- state;
    Lwt.return_unit

  let get_ip_gateways t =
    get_routers t.state

  let get_prefixes t =
    Ndpv6.prefix_list (fst t.state)

  let set_prefix t pfx =
    let now = C.time () in
    let state, acts = add_prefix ~now t.state pfx in
    t.state <- state;
    run t acts
end
