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

module Defaults = struct
  let max_ptr_solicitation_delay = 1
  let ptr_solicitation_interval  = 4
  let max_rtr_solicitations      = 3
  let max_multicast_solicit      = 3
  let max_unicast_solicit        = 3
  let max_anycast_delay_time     = 1
  let max_neighbor_advertisement = 3
  let reachable_time             = 30
  let retrans_timer              = 1
  let delay_first_probe_time     = 5
  let min_random_factor          = 0.5
  let max_random_factor          = 1.5

  let link_mtu                   = 1500 (* RFC 2464, 2. *)
  let min_link_mtu               = 1280
end

module Ipv6_wire = Wire_structs.Ipv6_wire

module Engine : sig
  type state

  type alert =
    | Icmp_checksum_failed
    | No_route_to_host of Ipaddr.V6.t
    | Not_implemented

  type proto =
    | TCP
    | UDP
    | Other of int

  type ret_data =
    | Data of proto * Ipaddr.V6.t * Ipaddr.V6.t * Cstruct.t
    | Response of Cstruct.t
    | Nothing

  type ret =
    | Ok of state * ret_data
    | Fail of alert

  val tick : state -> state * Cstruct.t list
  val handle_input : state -> Cstruct.t -> ret
  val create : Macaddr.t -> state
end = struct
  (* type proto = *)
  (*   [ `ICMP *)
  (*   | `TCP *)
  (*   | `UDP *)
  (*   | `OTHER of int ] *)

  (* let proto_num (p : proto) = *)
  (*   match p with *)
  (*   | `ICMP    -> 58 *)
  (*   | `TCP     -> 6 *)
  (*   | `UDP     -> 17 *)
  (*   | `OTHER n -> n *)

  module IpMap     = Map.Make (Ipaddr.V6)
  module PrefixMap = Map.Make (Ipaddr.V6.Prefix)

  type nd_state =
    | INCOMPLETE of int * int * (Ipaddr.V6.t * int * Cstruct.t) option
    | REACHABLE  of int * Macaddr.t
    | STALE      of Macaddr.t
    | DELAY      of int * Macaddr.t
    | PROBE      of int * int * Macaddr.t

  type nbh_info =
    { state               : nd_state;
      link_mtu            : int;
      cur_hop_limit       : int;
      base_reachable_time : int; (* default Defaults.reachable_time *)
      reachable_time      : int;
      retrans_timer       : int; (* Defaults.retrans_timer *)
      is_router           : bool }

  type state =
    { nb_cache  : nbh_info IpMap.t;
      (* dst_cache : Ipaddr.V6.t IpaddrMap.t; *)
      pre_list  : int PrefixMap.t; (* invalidation timer *)
      rt_list   : int IpMap.t; (* invalidation timer *)
      my_mac    : Macaddr.t;
      my_ips    : Ipaddr.V6.t list;
      tick      : int }

  type alert =
    | Icmp_checksum_failed
    | No_route_to_host of Ipaddr.V6.t
    | Not_implemented

  type proto =
    | TCP
    | UDP
    | Other of int

  type ret_data =
    | Data of proto * Ipaddr.V6.t * Ipaddr.V6.t * Cstruct.t
    | Response of Cstruct.t
    | Nothing

  type ret =
    | Ok of state * ret_data
    | Fail of alert

  (* type send_ret = *)
  (*   [ `Ok of state * [ `Response of Cstruct.t list list ] *)
  (*   | `Fail of alert ] *)

  (* This will have to be moved somewhere else later, since the same computation
     is needed for UDP, TCP, ICMP, etc. over IPv6. Also, [Tcpip_checksum] is a
     bad name since it is used for other protocols as well. *)
  let pbuf =
    Cstruct.sub (Cstruct.of_bigarray (Io_page.get 1)) 0
      Ipv6_wire.sizeof_ipv6_pseudo_header

  (* buf : beginning of ipv6 packet
     off : beginning of higher-layer protocol packet *)
  let cksum ~src ~dst ~proto (data : Cstruct.t) =
    Ipaddr.V6.to_cstruct_raw src pbuf 0;
    Ipaddr.V6.to_cstruct_raw dst pbuf 16;
    Cstruct.BE.set_uint32 pbuf 32 (Int32.of_int (Cstruct.len data));
    Cstruct.BE.set_uint32 pbuf 36 (Int32.of_int proto); (* (proto_num proto)); *)
    Tcpip_checksum.ones_complement_list [ pbuf; data ]

  let solicited_node_prefix =
    Ipaddr.V6.(Prefix.make 104 (of_int16 (0xff02, 0, 0, 0, 0, 1, 0xff00, 0)))

  let is_local st ip =
    PrefixMap.exists (fun pref _ -> Ipaddr.V6.Prefix.mem ip pref) st.pre_list

  let multicast_mac =
    let pbuf = Cstruct.create 6 in
    Cstruct.BE.set_uint16 pbuf 0 0x3333;
    fun ip ->
      let _, _, _, n = Ipaddr.V6.to_int32 ip in
      Cstruct.BE.set_uint32 pbuf 2 n;
      Macaddr.of_cstruct pbuf

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

  let alloc_frame ~smac ~dmac ~src ~dst ~proto =
    let ethernet_frame = Cstruct.create (Wire_structs.sizeof_ethernet + Ipv6_wire.sizeof_ipv6) in
    Macaddr.to_cstruct_raw dmac (Wire_structs.get_ethernet_dst ethernet_frame) 0;
    Macaddr.to_cstruct_raw smac (Wire_structs.get_ethernet_src ethernet_frame) 0;
    Wire_structs.set_ethernet_ethertype ethernet_frame 0x86dd; (* IPv6 *)
    let buf = Cstruct.shift ethernet_frame Wire_structs.sizeof_ethernet in
    (* Write the constant IPv6 header fields *)
    Ipv6_wire.set_ipv6_version_flow buf 0x60000000l; (* IPv6 *)
    Ipv6_wire.set_ipv6_nhdr buf proto; (* (proto_num proto); *)
    Ipv6_wire.set_ipv6_hlim buf 64; (* Same as IPv4 TTL ? TODO *)
    Ipaddr.V6.to_cstruct_raw src (Ipv6_wire.get_ipv6_src buf) 0;
    Ipaddr.V6.to_cstruct_raw dst (Ipv6_wire.get_ipv6_dst buf) 0;
    ethernet_frame

  module Cs = struct
    let append csl =
      let cs = Cstruct.create (Cstruct.lenv csl) in
      let rec loop off = function
        | [] -> ()
        | cs1 :: csl ->
          Cstruct.blit cs1 0 cs off (Cstruct.len cs1);
          loop (off + Cstruct.len cs1) csl
      in
      loop 0 csl;
      cs
  end

  let (<+>) cs1 cs2 = Cs.append [ cs1; cs2 ]

  let rec alloc_ns ~smac ~dmac ~src ~dst ~target =
    let frame = alloc_frame ~smac ~dmac ~src ~dst ~proto:58 (* `ICMP *) in
    let ipbuf = Cstruct.shift frame Wire_structs.sizeof_ethernet in
    Ipv6_wire.set_ipv6_hlim ipbuf 255; (* hop limit *)
    let icmpbuf = Cstruct.create (Ipv6_wire.sizeof_icmpv6_nsna + Ipv6_wire.sizeof_icmpv6_opt + 6) in
    (* Fill ICMPv6 Header *)
    Ipv6_wire.set_icmpv6_nsna_ty icmpbuf 135; (* NS *)
    Ipv6_wire.set_icmpv6_nsna_code icmpbuf 0;
    (* Fill ICMPv6 Payload *)
    Ipv6_wire.set_icmpv6_nsna_reserved icmpbuf 0l;
    Ipaddr.V6.to_cstruct_raw target (Ipv6_wire.get_icmpv6_nsna_target icmpbuf) 0;
    let optbuf = Cstruct.shift icmpbuf Ipv6_wire.sizeof_icmpv6_nsna in
    Ipv6_wire.set_icmpv6_opt_ty optbuf 1;
    Ipv6_wire.set_icmpv6_opt_len optbuf 1;
    Macaddr.to_cstruct_raw smac optbuf 2;
    (* Fill ICMPv6 Checksum *)
    let csum = cksum ~src ~dst ~proto:58 (* `ICMP *) icmpbuf in
    Ipv6_wire.set_icmpv6_csum icmpbuf csum;
    frame <+> icmpbuf

  let alloc_ns_multicast ~smac ~src ~target =
    let dst = Ipaddr.V6.Prefix.network_address solicited_node_prefix target in
    let dmac = multicast_mac dst in
    alloc_ns ~smac ~dmac ~src ~dst ~target

  let alloc_ns_unicast ~smac ~dmac ~src ~dst =
    alloc_ns ~smac ~dmac ~src ~dst ~target:dst

  (* let next_hop st ip = *)
  (*   if List.exists (Ipaddr.V6.Prefix.mem ip) st.pre_list then *)
  (*     `Ok ip *)
  (*   else if List.length st.rt_list > 0 then *)
  (*     `Ok (List.nth st.rt_list (Random.int (List.length st.rt_list))) *)
  (*   else *)
  (*     `Fail (`No_route_to_host ip) *)

  (* let output st ~dst ~proto datav = *)
  (*   if Ipaddr.V6.is_multicast dst then *)
  (*     let dmac = multicast_mac dst in *)
  (*     let src = choose_src st in *)
  (*     let frame = alloc_frame ~smac:st.my_mac ~dmac ~src ~dst ~proto in *)
  (*     `Ok (st, `Response (frame :: datav)) *)
  (*   else *)
  (*     let nh = next_hop st dst in *)
  (*     if IpaddrMap.mem dst st.dst_cache then *)
  (*       let next_hop = IpaddrMap.find dst st.dst_cache in *)
  (*       let nh_info = Ipaddr.find next_hop st.nbh_cache in *)
  (*       match nh_info.reach with *)
  (*       | INCOMPLETE pending -> *)
  (*         `Ok ({st with nbh_cache = IpaddrMap.add next_hop {nh_info with pending = (proto, datav) :: st.pending}}, *)
  (*              `Response [], None) *)
  (*       | REACHABLE dmac -> *)
  (*         let frame = alloc_frame ~mac:st.my_mac ~dmac ~src ~dst ~proto in *)
  (*         `Ok (st, `Response [ frame :: datav ]) *)
  (*       | STALE dmac -> *)
  (*     else (\* next-hop *\) *)
  (*       let nbh_cache = IpaddrMap.add nh { reach = INCOMPLETE (st.tick, 0, [ proto, datav ]); *)
  (*                                          is_router = false } st.nbh_cache in *)
  (*       let ... = alloc_ns_output in *)
  (*       `Ok ({st with nbh_cache}, `Response [...]) *)

  (* FIXME if node goes from router to host, remove from default router list;
     this could be handled in input_icmp_message *)

  let map_option f = function None -> None | Some x -> Some (f x)

  (* val : nb_data -> Macaddr.t option -> bool -> bool -> bool -> nb * (Ipaddr.V6.t * Cstruct.t) option *)
  let on_nbh_adv tick ip nb mac is_router solicited override =
    match nb.state, mac, solicited, override with
    | INCOMPLETE (_, _, pending), Some dmac, false, _ ->
      let pending = map_option (fun x -> dmac, x) pending in
      (* FIXME create the actual messages with the received dmac *)
      Printf.printf "NDP: %s is now STALE\n%!" (Ipaddr.V6.to_string ip);
      {nb with state = STALE dmac}, pending
    | INCOMPLETE (_, _, pending), Some dmac, true, _ ->
      let pending = map_option (fun x -> dmac, x) pending in
      (* FIXME create the actual messages with the received dmac *)
      Printf.printf "NDP: %s is now REACHABLE\n%!" (Ipaddr.V6.to_string ip);
      {nb with state = REACHABLE (tick + nb.reachable_time, dmac) }, pending
    | INCOMPLETE _, None, _, _ ->
      {nb with is_router}, None
    | PROBE (_, _, old_mac), Some mac, true, false when old_mac = mac ->
      Printf.printf "NDP: %s is now REACHABLE\n%!" (Ipaddr.V6.to_string ip);
      {nb with state = REACHABLE (tick + nb.reachable_time, mac)}, None
    | PROBE (_, _, mac), None, true, false ->
      Printf.printf "NDP: %s is now REACHABLE\n%!" (Ipaddr.V6.to_string ip);
      {nb with state = REACHABLE (tick + nb.reachable_time, mac)}, None
    | (REACHABLE _ | STALE _ | DELAY _ | PROBE _), None, _, _ ->
      {nb with is_router}, None
    | REACHABLE (_, old_mac), Some mac, true, false when mac <> old_mac ->
      Printf.printf "NDP: %s is now STALE\n%!" (Ipaddr.V6.to_string ip);
      {nb with state = STALE old_mac}, None (* TODO check old_mac or mac *)
    | (STALE old_mac | PROBE (_, _, old_mac) | DELAY (_, old_mac)),
      Some mac, true, false when mac <> old_mac ->
      nb, None
    | (REACHABLE _ | STALE _ | DELAY _ | PROBE _), Some mac, true, true ->
      {nb with state = REACHABLE (tick + nb.reachable_time, mac)}, None
    | (REACHABLE _ | STALE _ | DELAY _ | PROBE _), _, false, false ->
      nb, None
    | (REACHABLE (_, old_mac) | STALE old_mac | DELAY (_, old_mac) | PROBE (_, _, old_mac)),
      Some mac, false, true when mac = old_mac ->
      nb, None
    | (REACHABLE (_, old_mac) | STALE old_mac | DELAY (_, old_mac) | PROBE (_, _, old_mac)),
      Some mac, false, true when mac <> old_mac ->
      Printf.printf "NDP: %s is now STALE\n%!" (Ipaddr.V6.to_string ip);
      {nb with state = STALE mac}, None
    | _ ->
      nb, None

  type unsolicited =
    | NS
    | RA
    | Redirect

  let on_unsolicited nb mac kind =
    match nb.state, mac, kind with
    | INCOMPLETE (_, _, pending), Some mac, _ ->
      { nb with state = STALE mac }, pending
    | (REACHABLE (_, old_mac) | STALE old_mac | DELAY (_, old_mac) | PROBE (_, _, old_mac)),
      Some mac, _ when mac <> old_mac ->
      { nb with state = STALE mac }, None
    | INCOMPLETE _, None, NS ->
      nb, None
    | (REACHABLE (_, old_mac) | STALE old_mac | DELAY (_, old_mac) | PROBE (_, _, old_mac)),
      Some mac, (NS | RA) when mac = old_mac ->
      nb, None
    | _ ->
      nb, None

  let select_source_address st =
    match st.my_ips with
    | ip :: _ -> ip
    | [] -> Ipaddr.V6.unspecified

  (* val tick : state -> state * Cstruct.t list *)
  let tick st =
    let st = {st with tick = st.tick + 1} in
    let process ip nb (nb_cache, pending) =
      match nb.state with
      | INCOMPLETE (t, tn, msgs) ->
        begin
          match t <= st.tick, tn < Defaults.max_multicast_solicit with
          | true, true ->
            let src = select_source_address st in (* FIXME choose src in a paritcular way ? see 7.2.2 *)
            let msg = alloc_ns_multicast ~smac:st.my_mac ~src ~target:ip in
            let nb = {nb with state = INCOMPLETE (st.tick + nb.retrans_timer, tn + 1, msgs)} in
            IpMap.add ip nb nb_cache, pending
          | true, false ->
            (* TODO Generate ICMP error: Destination Unreachable *)
            nb_cache, pending (* discard entry *)
          | _ ->
            nb_cache, pending
        end
      | REACHABLE (t, mac) ->
        begin
          match t <= st.tick with
          | true ->
            IpMap.add ip {nb with state = STALE mac } nb_cache, pending
          | false ->
            nb_cache, pending
        end
      | DELAY (t, dmac) ->
        begin
          match t <= st.tick with
          | true ->
            let src = select_source_address st in (* FIXME choose source address *)
            let msg = alloc_ns_unicast ~smac:st.my_mac ~dmac ~src ~dst:ip in
            let nb = {nb with state = PROBE (st.tick + nb.retrans_timer, 0, dmac)} in
            IpMap.add ip nb nb_cache, (msg :: pending)
          | false ->
            nb_cache, pending
        end
      | PROBE (t, tn, dmac) ->
        begin
          match t <= st.tick, tn < Defaults.max_unicast_solicit with
          | true, true ->
            let src = select_source_address st in
            let msg = alloc_ns_unicast ~smac:st.my_mac ~dmac ~src ~dst:ip in
            let nb = {nb with state = PROBE (st.tick + nb.retrans_timer, tn + 1, dmac)} in
            IpMap.add ip nb nb_cache, (msg :: pending)
          | true, false ->
            nb_cache, pending (* discard entry *)
          | _ ->
            nb_cache, pending
        end
      | _ ->
        nb_cache, pending
    in
    let nb_cache, pending = IpMap.fold process st.nb_cache (IpMap.empty, []) in
    let rt_list = IpMap.filter (fun _ t -> t > st.tick) st.rt_list in
    (* FIXME if we are keeping a destination cache, we must remove the stale routers from there as well. *)
    {st with nb_cache; rt_list}, pending

  let next_option buf =
    if Cstruct.len buf >= Ipv6_wire.sizeof_icmpv6_opt then
      Some (Cstruct.split buf (Ipv6_wire.get_icmpv6_opt_len buf * 8))
    else
      None

  let get_neighbour st ~ip ~mac =
    if IpMap.mem ip st.nb_cache then
      st, IpMap.find ip st.nb_cache
    else
      let reachable_time =
        let rt = float Defaults.reachable_time in
        let d = Defaults.(max_random_factor -. min_random_factor) in
        truncate (Random.float (d *. rt) +. Defaults.min_random_factor *. rt)
      in
      let entry =
        { state = STALE mac;
          link_mtu = Defaults.link_mtu;
          cur_hop_limit = 64; (* TODO *)
          base_reachable_time = Defaults.reachable_time;
          reachable_time;
          retrans_timer = Defaults.retrans_timer;
          is_router = false }
      in
      {st with nb_cache = IpMap.add ip entry st.nb_cache}, entry

  let handle_prefix st buf =
    let on_link = Ipv6_wire.get_icmpv6_opt_prefix_on_link buf in
    let pref =
      Ipaddr.V6.Prefix.make
        (Ipv6_wire.get_icmpv6_opt_prefix_pref_len buf)
        (Ipaddr.V6.of_cstruct (Ipv6_wire.get_icmpv6_opt_prefix_prefix buf))
    in
    let vlt = Int32.to_int (Ipv6_wire.get_icmpv6_opt_prefix_valid_lifetime buf) in
    match on_link, PrefixMap.mem pref st.pre_list, Ipaddr.V6.Prefix.(compare pref link) = 0, vlt with
    | true, _, true, _ ->
      st
    | true, false, false, 0 ->
      st
    | true, true, false, 0 ->
      {st with pre_list = PrefixMap.remove pref st.pre_list}
    | true, _, false, n ->
      Printf.printf "NDP: Adding prefix %s\n%!" (Ipaddr.V6.Prefix.to_string pref);
      {st with pre_list = PrefixMap.add pref n st.pre_list}
    | false, _, _, _ ->
      st

  (* buf : icmp packet *)
  let handle_icmp_input st ~src ~dst buf : ret =
    let csum = cksum ~src ~dst ~proto:58 (* `ICMP *) buf in
    if not (csum = 0) then begin
      Printf.printf "ICMP6 checksum error (0x%x)\n%!" csum;
      Fail Icmp_checksum_failed
    end else
      match Ipv6_wire.get_icmpv6_ty buf with
      | 129 (* Echo reply *) ->
        Printf.printf "ICMP6: discarding echo reply\n%!";
        Ok (st, Nothing)
      | 133 (* RS *) ->
        (* RFC 4861, 2.6.2 *)
        Ok (st, Nothing)
      | 134 (* RA *) ->
        (* FIXME add router to default router list *)
        let opts = Cstruct.shift buf Ipv6_wire.sizeof_icmpv6_ra in
        let rec loop st mac mtu opts =
          match next_option opts with
          | None ->
            st, mac, mtu
          | Some (opt, opts) ->
            begin
              match Ipv6_wire.get_icmpv6_opt_ty opt, Ipv6_wire.get_icmpv6_opt_len opt with
              | 1, 1 -> (* Source Link-Layer Address *)
                loop st (Some (Macaddr.of_cstruct (Cstruct.shift opt 2))) mtu opts
              | 5, 1 -> (* MTU *)
                let new_mtu = Int32.to_int (Cstruct.BE.get_uint32 opt 4) in
                let mtu =
                  if Defaults.min_link_mtu <= new_mtu && new_mtu <= Defaults.link_mtu then
                    Some new_mtu
                  else
                    mtu
                in
                loop st mac mtu opts
              | 3, 4 -> (* Prefix Information *)
                loop (handle_prefix st opt) mac mtu opts
              | _ ->
                loop st mac mtu opts
            end
        in
        let st, mac, mtu = loop st None None opts in
        begin
          match mac with
          | Some mac ->
            Printf.printf "RA: Hello from %s (%s)\n%!" (Ipaddr.V6.to_string src) (Macaddr.to_string mac);
            let st, nb = get_neighbour st ~ip:src ~mac in
            let nb, pending = on_unsolicited nb (Some mac) RA in
            let st = {st with nb_cache = IpMap.add src nb st.nb_cache} in (* FIXME add to default router list *)
            (* `Ok (st, match pending with None -> `None | Some x -> `Response x) *)
            assert false
          | None ->
            Ok (st, Nothing)
        end
      | 135 (* NS *) ->
        let target = Ipaddr.V6.of_cstruct (Ipv6_wire.get_icmpv6_nsna_target buf) in
        Printf.printf "NDP: %s wants to know our mac addr\n%!" (Ipaddr.V6.to_string target);
        let is_router = Ipv6_wire.get_icmpv6_nsna_router buf in
        let solicited = Ipv6_wire.get_icmpv6_nsna_solicited buf in
        let override = Ipv6_wire.get_icmpv6_nsna_override buf in
        let rec loop opts =
          match next_option opts with
          | None -> None
          | Some (opt, opts) ->
            begin
              match Ipv6_wire.get_icmpv6_opt_ty opt, Ipv6_wire.get_icmpv6_opt_len opt with
              | 2, 1 ->
                Some (Macaddr.of_cstruct (Cstruct.shift opt 2))
              | _ ->
                loop opts
            end
        in
        let mac = loop (Cstruct.shift buf Ipv6_wire.sizeof_icmpv6_nsna) in
        let is_unspec = Ipaddr.V6.(compare unspecified src) = 0 in
        let _ = (* FIXME *)
          match mac, is_unspec with
          | Some mac, false ->
            let st, nb = get_neighbour st ~ip:src ~mac in (* CHECK *)
            let nb, pending = on_unsolicited nb (Some mac) NS in (* TODO handle pending *)
            {st with nb_cache = IpMap.add src nb st.nb_cache}
            (* FIXME update or CREATE NC entry *)
          | _ ->
            st
        in
        (* FIXME send NA *)
        assert false
      | 136 (* NA *) ->
        let target = Ipaddr.V6.of_cstruct (Ipv6_wire.get_icmpv6_nsna_target buf) in
        let is_router = Ipv6_wire.get_icmpv6_nsna_router buf in
        let solicited = Ipv6_wire.get_icmpv6_nsna_solicited buf in
        let override = Ipv6_wire.get_icmpv6_nsna_override buf in
        let rec loop opts =
          match next_option opts with
          | None -> None
          | Some (opt, opts) ->
            begin
              match Ipv6_wire.get_icmpv6_opt_ty opt, Ipv6_wire.get_icmpv6_opt_len opt with
              | 2, 1 ->
                Some (Macaddr.of_cstruct (Cstruct.shift opt 2))
              | _ ->
                loop opts
            end
        in
        let mac = loop (Cstruct.shift buf Ipv6_wire.sizeof_icmpv6_nsna) in
        (* Printf.printf "NDP: %s -> %s\n%!" (Ipaddr.V6.to_string target); *)
        if IpMap.mem target st.nb_cache then
          let nb = IpMap.find target st.nb_cache in
          let nb, resp = on_nbh_adv st.tick target nb mac is_router solicited override in
          let resp =
            map_option
              (fun (dmac, (src, proto, data)) ->
                 alloc_frame ~smac:st.my_mac ~dmac ~src ~dst:target ~proto <+> data)
              resp
          in
          Ok (st, match resp with None -> Nothing | Some m -> Response m)
        else
          Ok (st, Nothing)
      | n ->
        Printf.printf "ICMP6: unrecognized type (%d)\n%!" n;
        Ok (st, Nothing)

  let handle_input st buf =
    let src = Ipaddr.V6.of_cstruct (Ipv6_wire.get_ipv6_src buf) in
    let dst = Ipaddr.V6.of_cstruct (Ipv6_wire.get_ipv6_dst buf) in

    (* Printf.printf "Got IPv6 Packet (proto:%d) %s -> %s\n%!" *)
    (*   (Ipv6_wire.get_ipv6_nhdr buf) (Ipaddr.V6.to_string src) (Ipaddr.V6.to_string dst); *)

    (* See http://en.wikipedia.org/wiki/List_of_IP_protocol_numbers *)
    let rec loop st first hdr off =
      match hdr with
      | 0 when first -> (* HOPOPT *)
        loop st false (Cstruct.get_uint8 buf 0) (8 + 8 * Cstruct.get_uint8 buf 1)
      | 0 (* HOPOPT should only appear in first position. So we drop this packet. *)
      | 60 (* TODO IPv6-Opts *)
      | 43 (* TODO IPv6-Route *)
      | 44 (* TODO IPv6-Frag *)
      | 50 (* TODO ESP *)
      | 51 (* TODO AH *)
      | 135 (* TODO Mobility Header *)
      | 59 (* NO NEXT HEADER *) ->
        Ok (st, Nothing)
      | 58 (* ICMP *) ->
        handle_icmp_input st ~src ~dst (Cstruct.shift buf Ipv6_wire.sizeof_ipv6)
      | 17 (* UDP *) ->
        Ok (st, Data (UDP, src, dst, Cstruct.shift buf Ipv6_wire.sizeof_ipv6))
      | 6 (* TCP *) ->
        Ok (st, Data (TCP, src, dst, Cstruct.shift buf Ipv6_wire.sizeof_ipv6))
      | n when 143 <= n && n <= 255 ->
        (* UNASSIGNED, EXPERIMENTAL & RESERVED *)
        Ok (st, Nothing)
      | n ->
        Ok (st, Data (Other n, src, dst, Cstruct.shift buf Ipv6_wire.sizeof_ipv6))
    in
    loop st true (Ipv6_wire.get_ipv6_nhdr buf) Ipv6_wire.sizeof_ipv6

  let create mac =
    { nb_cache = IpMap.empty;
      pre_list = PrefixMap.empty;
      rt_list = IpMap.empty;
      my_mac = mac;
      my_ips = [];
      tick = 0 }
end

let (>>=) = Lwt.(>>=)

module Make (Ethif : V1_LWT.ETHIF) (Time : V1_LWT.TIME) = struct
  type ethif = Ethif.t
  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t
  type ipv6addr = Ipaddr.V6.t
  type callback = src:ipv6addr -> dst:ipv6addr -> buffer -> unit Lwt.t

  type t =
    { ethif : Ethif.t;
      mutable state : Engine.state;
      stop_ticker : unit Lwt.u }

  let input t ~tcp ~udp ~default buf =
    let open Engine in
    match handle_input t.state buf with
    | Ok (st, Data (TCP, src, dst, buf)) ->
      t.state <- st;
      tcp ~src ~dst buf
    | Ok (st, Data (UDP, src, dst, buf)) ->
      t.state <- st;
      udp ~src ~dst buf
    | Ok (st, Data (Other n, src, dst, buf)) ->
      t.state <- st;
      default ~proto:n ~src ~dst buf
    | Ok (st, Response packet) ->
      t.state <- st;
      Ethif.write t.ethif packet
    | Ok (st, Nothing) ->
      t.state <- st;
      Lwt.return_unit
    | Fail _ ->
      Lwt.fail (Failure "Ipv6.input")

  let disconnect t =
    Lwt.wakeup t.stop_ticker ();
    Lwt.return_unit

  let connect ethif =
    let waiter, stop_ticker = Lwt.wait () in
    let t = { ethif; state = Engine.create (Ethif.mac ethif); stop_ticker } in
    let rec ticker () =
      let st, pending = Engine.tick t.state in
      t.state <- st;
      Lwt_list.iter_s (Ethif.write t.ethif) pending >>= fun () ->
      Lwt.pick [ (Time.sleep 1.0 >>= fun () -> Lwt.return `Ok);
                 (waiter >>= fun () -> Lwt.return `Stop) ] >>= function
      | `Ok ->
        ticker ()
      | `Stop ->
        Lwt.return_unit
    in
    Lwt.async ticker;
    (* TODO join multicast groups + negotiate SLAAC *)
    Lwt.return (`Ok t)
end
