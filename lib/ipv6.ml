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

module Cs = struct
  let append csl =
    let cs = Cstruct.create (Cstruct.lenv csl) in
    let rec loop off = function
      | [] -> cs
      | cs1 :: csl ->
        Cstruct.blit cs1 0 cs off (Cstruct.len cs1);
        loop (off + Cstruct.len cs1) csl
    in
    loop 0 csl
end

module Engine : sig
  type state

  exception No_route_to_host of Ipaddr.V6.t

  type proto =
    | TCP
    | UDP
    | Other of int

  type ret =
    | Receive of proto * Ipaddr.V6.t * Ipaddr.V6.t * Cstruct.t
    | Send of Cstruct.t list

  val tick : state -> Cstruct.t list
  val handle_input : state -> Cstruct.t -> ret
  val create : Macaddr.t -> state
end = struct
  module IpMap     = Map.Make (Ipaddr.V6)
  module PrefixMap = Map.Make (Ipaddr.V6.Prefix)

  type nd_state =
    | INCOMPLETE of int * int * (Macaddr.t -> Cstruct.t) option
    | REACHABLE  of int * Macaddr.t
    | STALE      of Macaddr.t
    | DELAY      of int * Macaddr.t
    | PROBE      of int * int * Macaddr.t

  type nb_info =
    { mutable state               : nd_state;
      mutable is_router           : bool }

  type addr_state =
    | TENTATIVE
    | ASSIGNED

  (* TODO add destination cache *)
  type state =
    { nb_cache                    : (Ipaddr.V6.t, nb_info) Hashtbl.t;
      mutable prefix_list         : (Ipaddr.V6.Prefix.t * int) list;
      mutable rt_list             : (Ipaddr.V6.t * int) list; (* invalidation timer *)
      my_mac                      : Macaddr.t;
      mutable my_ips              : (Ipaddr.V6.t * addr_state) list;
      mutable tick                : int;
      mutable link_mtu            : int;
      mutable curr_hop_limit      : int;
      mutable base_reachable_time : int; (* default Defaults.reachable_time *)
      mutable reachable_time      : int;
      mutable retrans_timer       : int } (* Defaults.retrans_timer *)

  exception No_route_to_host of Ipaddr.V6.t

  type proto =
    | TCP
    | UDP
    | Other of int

  type ret =
    | Receive of proto * Ipaddr.V6.t * Ipaddr.V6.t * Cstruct.t
    | Send of Cstruct.t list

  (* This will have to be moved somewhere else later, since the same computation
     is needed for UDP, TCP, ICMP, etc. over IPv6. Also, [Tcpip_checksum] is a
     bad name since it is used for other protocols as well. *)
  let pbuf =
    Cstruct.create Ipv6_wire.sizeof_ipv6_pseudo_header

  let cksum ~src ~dst ~proto data =
    Ipaddr.V6.to_cstruct_raw src pbuf 0;
    Ipaddr.V6.to_cstruct_raw dst pbuf 16;
    Cstruct.BE.set_uint32 pbuf 32 (Int32.of_int (Cstruct.len data));
    Cstruct.BE.set_uint32 pbuf 36 (Int32.of_int proto);
    Tcpip_checksum.ones_complement_list [ pbuf; data ]

  let solicited_node_prefix =
    Ipaddr.V6.(Prefix.make 104 (of_int16 (0xff02, 0, 0, 0, 0, 1, 0xff00, 0)))

  let is_local st ip =
    List.exists (fun (pref, _) -> Ipaddr.V6.Prefix.mem ip pref) st.prefix_list

  let multicast_mac =
    let pbuf = Cstruct.create 6 in
    Cstruct.BE.set_uint16 pbuf 0 0x3333;
    fun ip ->
      let _, _, _, n = Ipaddr.V6.to_int32 ip in
      Cstruct.BE.set_uint32 pbuf 2 n;
      Macaddr.of_cstruct pbuf

  let link_local_addr mac =
    let bmac = Macaddr.to_bytes mac in
    let c i = Char.code (Bytes.get bmac i) in
    Ipaddr.V6.make
      0xfe80 0 0 0
      ((c 0 lxor 2) lsl 8 + c 1)
      (c 2 lsl 8 + 0xff)
      (0xfe00 + c 3)
      (c 4 lsl 8 + c 5)

  let alloc_frame ~smac ~dmac ~src ~dst ?(hlim = 64) ~len ~proto () =
    let ethernet_frame = Cstruct.create (Wire_structs.sizeof_ethernet + Ipv6_wire.sizeof_ipv6) in
    Macaddr.to_cstruct_raw dmac (Wire_structs.get_ethernet_dst ethernet_frame) 0;
    Macaddr.to_cstruct_raw smac (Wire_structs.get_ethernet_src ethernet_frame) 0;
    Wire_structs.set_ethernet_ethertype ethernet_frame 0x86dd; (* IPv6 *)
    let buf = Cstruct.shift ethernet_frame Wire_structs.sizeof_ethernet in
    (* Write the constant IPv6 header fields *)
    Ipv6_wire.set_ipv6_version_flow buf 0x60000000l; (* IPv6 *)
    Ipv6_wire.set_ipv6_len buf len;
    Ipv6_wire.set_ipv6_nhdr buf proto;
    Ipv6_wire.set_ipv6_hlim buf hlim;
    Ipaddr.V6.to_cstruct_raw src (Ipv6_wire.get_ipv6_src buf) 0;
    Ipaddr.V6.to_cstruct_raw dst (Ipv6_wire.get_ipv6_dst buf) 0;
    ethernet_frame

  let (<+>) cs1 cs2 = Cs.append [ cs1; cs2 ]

  let rec alloc_ns ~smac ~dmac ~src ~dst ~target =
    let icmpbuf = Cstruct.create (Ipv6_wire.sizeof_ns + Ipv6_wire.sizeof_icmpv6_opt + 6) in
    let frame = alloc_frame ~smac ~dmac ~src ~dst ~hlim:255 ~len:(Cstruct.len icmpbuf) ~proto:58 () (* `ICMP *) in
    (* Fill ICMPv6 Header *)
    Ipv6_wire.set_ns_ty icmpbuf 135; (* NS *)
    Ipv6_wire.set_ns_code icmpbuf 0;
    (* Fill ICMPv6 Payload *)
    Ipv6_wire.set_ns_reserved icmpbuf 0l;
    Ipaddr.V6.to_cstruct_raw target (Ipv6_wire.get_ns_target icmpbuf) 0;
    let optbuf = Cstruct.shift icmpbuf Ipv6_wire.sizeof_ns in
    Ipv6_wire.set_icmpv6_opt_ty optbuf 1; (* SLLA *)
    Ipv6_wire.set_icmpv6_opt_len optbuf 1;
    Macaddr.to_cstruct_raw smac optbuf 2;
    (* Fill ICMPv6 Checksum *)
    let csum = cksum ~src ~dst ~proto:58 (* ICMP *) icmpbuf in
    Ipv6_wire.set_icmpv6_csum icmpbuf csum;
    frame <+> icmpbuf

  let alloc_ns_multicast ~smac ~src ~target =
    let dst = Ipaddr.V6.Prefix.network_address solicited_node_prefix target in
    let dmac = multicast_mac dst in
    alloc_ns ~smac ~dmac ~src ~dst ~target

  let alloc_ns_unicast ~smac ~dmac ~src ~dst =
    alloc_ns ~smac ~dmac ~src ~dst ~target:dst

  let alloc_na_data ~smac ~src ~target ~dst ~solicited =
    let icmpbuf = Cstruct.create (Ipv6_wire.sizeof_na + Ipv6_wire.sizeof_icmpv6_opt + 6) in
    (* Fill ICMPv6 Header *)
    Ipv6_wire.set_na_ty icmpbuf 136; (* NA *)
    Ipv6_wire.set_na_code icmpbuf 0;
    (* Fill ICMPv6 Payload *)
    Ipv6_wire.set_na_reserved icmpbuf
      (if solicited then 0x60000000l else 0x20000000l);
    Ipaddr.V6.to_cstruct_raw target (Ipv6_wire.get_na_target icmpbuf) 0;
    let optbuf = Cstruct.shift icmpbuf Ipv6_wire.sizeof_na in
    Ipv6_wire.set_icmpv6_opt_ty optbuf 2; (* TLLA *)
    Ipv6_wire.set_icmpv6_opt_len optbuf 1;
    Macaddr.to_cstruct_raw smac optbuf 2;
    (* Fill ICMPv6 Checksum *)
    let csum = cksum ~src ~dst ~proto:58 (* ICMP *) icmpbuf in
    Ipv6_wire.set_icmpv6_csum icmpbuf csum;
    icmpbuf

  let select_source_address st =
    let rec loop = function
      | (ip, ASSIGNED) :: _ -> ip
      | (_, TENTATIVE) :: rest -> loop rest
      | [] -> Ipaddr.V6.unspecified
    in
    loop st.my_ips

  let fresh_nb_entry tick reachable_time data =
    { state = INCOMPLETE (tick + reachable_time, 0, data);
      is_router = false }

  let get_neighbour st ~ip ~state =
    if Hashtbl.mem st.nb_cache ip then
      Hashtbl.find st.nb_cache ip
    else
      let nb = fresh_nb_entry st.tick st.reachable_time None in
      nb.state <- state;
      Hashtbl.add st.nb_cache ip nb;
      nb

  let next_hop st ip =
    if is_local st ip then
      Some ip
    else if not (List.length st.rt_list = 0) then
       (* TODO Default Router Selection 6.3.6 *)
      Some (fst (List.nth st.rt_list (Random.int (List.length st.rt_list))))
    else
      None

  let output st ~dst ?hlim ~proto data =
    if Ipaddr.V6.is_multicast dst then
      let dmac = multicast_mac dst in
      let src = select_source_address st in
      let frame = alloc_frame ~smac:st.my_mac ~dmac ~src ~dst ~len:(Cstruct.len data) ?hlim ~proto () in
      [ frame <+> data ]
    else
      match next_hop st dst with
      | None ->
        raise (No_route_to_host dst)
      | Some ip ->
        let src = select_source_address st in
        let msg dmac =
          let frame = alloc_frame ~smac:st.my_mac ~dmac ~src ~dst ~len:(Cstruct.len data) ~proto () in
          frame <+> data
        in
        if Hashtbl.mem st.nb_cache ip then
          let nb = Hashtbl.find st.nb_cache ip in
          match nb.state with
          | INCOMPLETE (t, nt, _) ->
            nb.state <- INCOMPLETE (t, nt, Some msg);
            []
          | REACHABLE (_, dmac) | DELAY (_, dmac) | PROBE (_, _, dmac) ->
            [ msg dmac ]
          | STALE dmac ->
            nb.state <- DELAY (st.tick + Defaults.delay_first_probe_time, dmac);
            [ msg dmac ]
        else
          let nb = fresh_nb_entry st.tick st.reachable_time (Some msg) in
          Hashtbl.add st.nb_cache ip nb;
          let msg = alloc_ns_multicast ~smac:st.my_mac ~src ~target:ip in
          [ msg ]

  (* FIXME if node goes from router to host, remove from default router list;
     this could be handled in input_icmp_message *)

  let map_option f = function None -> None | Some x -> Some (f x)

  (* val tick : state -> state * Cstruct.t list *)
  let tick st =
    st.tick <- st.tick + 1;
    let process ip nb pending =
      match nb.state with
      | INCOMPLETE (t, tn, msg) ->
        begin
          match t <= st.tick, tn < Defaults.max_multicast_solicit with
          | true, true ->
            Printf.printf "NDP: %s INCOMPLETE timeout, retrying\n%!" (Ipaddr.V6.to_string ip);
            let src = select_source_address st in (* FIXME choose src in a paritcular way ? see 7.2.2 *)
            let ns = alloc_ns_multicast ~smac:st.my_mac ~src ~target:ip in
            nb.state <- INCOMPLETE (st.tick + st.retrans_timer, tn + 1, msg);
            ns :: pending
          | true, false ->
            Printf.printf "NDP: %s unrachable, discarding\n%!" (Ipaddr.V6.to_string ip);
            (* TODO Generate ICMP error: Destination Unreachable *)
            Hashtbl.remove st.nb_cache ip;
            pending
          | _ ->
            pending
        end
      | REACHABLE (t, mac) ->
        begin
          match t <= st.tick with
          | true ->
            Printf.printf "NDP: %s REACHABLE --> STALE\n%!" (Ipaddr.V6.to_string ip);
            nb.state <- STALE mac;
            pending
          | false ->
            pending
        end
      | DELAY (t, dmac) ->
        begin
          match t <= st.tick with
          | true ->
            Printf.printf "NDP: %s DELAY --> PROBE\n%!" (Ipaddr.V6.to_string ip);
            let src = select_source_address st in
            let ns = alloc_ns_unicast ~smac:st.my_mac ~dmac ~src ~dst:ip in
            nb.state <- PROBE (st.tick + st.retrans_timer, 0, dmac);
            ns :: pending
          | false ->
            pending
        end
      | PROBE (t, tn, dmac) ->
        begin
          match t <= st.tick, tn < Defaults.max_unicast_solicit with
          | true, true ->
            Printf.printf "NDP: %s PROBE timeout, retrying\n%!" (Ipaddr.V6.to_string ip);
            let src = select_source_address st in
            let msg = alloc_ns_unicast ~smac:st.my_mac ~dmac ~src ~dst:ip in
            nb.state <- PROBE (st.tick + st.retrans_timer, tn + 1, dmac);
            msg :: pending
          | true, false ->
            Printf.printf "NDP: %s PROBE unreachable, discarding\n%!" (Ipaddr.V6.to_string ip);
            Hashtbl.remove st.nb_cache ip;
            pending
          | _ ->
            pending
        end
      | _ ->
        pending
    in
    let pending = Hashtbl.fold process st.nb_cache [] in
    st.rt_list <- List.filter (fun (_, t) -> t < st.tick) st.rt_list;
    (* TODO expire prefixes *)
    (* FIXME if we are keeping a destination cache, we must remove the stale routers from there as well. *)
    pending

  let rec fold_options f opts i =
    if Cstruct.len opts >= Ipv6_wire.sizeof_icmpv6_opt then
      (* TODO check for invalid len == 0 *)
      let opt, opts = Cstruct.split opts (Ipv6_wire.get_icmpv6_opt_len opts * 8) in
      let i = f (Ipv6_wire.get_icmpv6_opt_ty opt) (Ipv6_wire.get_icmpv6_opt_len opt) opt i in
      fold_options f opts i
    else
      i

  let handle_prefix st buf =
    let on_link = Ipv6_wire.get_icmpv6_opt_prefix_on_link buf in
    let pref =
      Ipaddr.V6.Prefix.make
        (Ipv6_wire.get_icmpv6_opt_prefix_pref_len buf)
        (Ipaddr.V6.of_cstruct (Ipv6_wire.get_icmpv6_opt_prefix_prefix buf))
    in
    let vlt = Int32.to_int (Ipv6_wire.get_icmpv6_opt_prefix_valid_lifetime buf) in
    let already_exists = List.mem_assoc pref st.prefix_list in
    match on_link, already_exists, Ipaddr.V6.Prefix.(compare pref link) = 0, vlt with
    | true, _, true, _
    | true, false, false, 0 ->
      ()
    | true, true, false, 0 ->
      Printf.printf "NDP: Removing prefix: %s\n%!" (Ipaddr.V6.Prefix.to_string pref);
      st.prefix_list <- List.remove_assoc pref st.prefix_list
    | true, true, false, n ->
      Printf.printf "NDP: Refreshing prefix: %s invalid-in: %d\n%!" (Ipaddr.V6.Prefix.to_string pref) n;
      let prefix_list = List.remove_assoc pref st.prefix_list in
      st.prefix_list <- (pref, n) :: prefix_list
    | true, false, false, n ->
      Printf.printf "NDP: Adding prefix: %s invalid-in: %d\n%!" (Ipaddr.V6.Prefix.to_string pref) n;
      st.prefix_list <- (pref, n) :: st.prefix_list
    | false, _, _, _ ->
      ()

  let compute_reachable_time rt =
    rt (* TODO *)

  let add_nc_entry st ~ip ~is_router ~state =
    Printf.printf "Adding neighbor with ip addr %s\n%!" (Ipaddr.V6.to_string ip);
    let nb = { state; is_router } in
    Hashtbl.replace st.nb_cache ip nb;
    nb

  let ra_input st src dst buf =
    Printf.printf "NDP: Received RA from %s to %s\n%!" (Ipaddr.V6.to_string src) (Ipaddr.V6.to_string dst);

    let chl = Ipv6_wire.get_ra_curr_hop_limit buf in
    if chl <> 0 then begin
      st.curr_hop_limit <- chl;
      Printf.printf "NDP: curr_hop_lim %d\n%!" chl
    end;

    let rt = Ipv6_wire.get_ra_reachable_time buf |> Int32.to_int in
    if rt <> 0 && st.base_reachable_time <> rt then begin
      st.base_reachable_time <- rt / 1000;
      st.reachable_time <- compute_reachable_time rt / 1000
    end;

    let rt = Ipv6_wire.get_ra_retrans_timer buf |> Int32.to_int in
    if rt <> 0 then begin
      st.retrans_timer <- rt / 1000
    end;

    (* Options processing *)
    let opts = Cstruct.shift buf Ipv6_wire.sizeof_ra in

    let process_option ty len opt pending =
      match ty, len with
      | 1, 1 -> (* SLLA *)
        Printf.printf "NDP: Processing SLLA option in RA\n%!";
        let new_mac = Macaddr.of_cstruct (Cstruct.shift opt 2) in
        let nb =
          try
            Hashtbl.find st.nb_cache src
          with
          | Not_found ->
            add_nc_entry st ~ip:src ~is_router:true ~state:(STALE new_mac)
        in
        let pending = match nb.state with
          | INCOMPLETE (_, _, pending) ->
            nb.state <- STALE new_mac;
            map_option (fun x -> x new_mac) pending
          | REACHABLE (_, mac) | STALE mac | DELAY (_, mac) | PROBE (_, _, mac) ->
            if mac <> new_mac then nb.state <- STALE new_mac;
            pending
        in
        nb.is_router <- true;
        pending
      | 5, 1 -> (* MTU *)
        Printf.printf "NDP: Processing MTU option in RA\n%!";
        let new_mtu = Int32.to_int (Cstruct.BE.get_uint32 opt 4) in
        if Defaults.min_link_mtu <= new_mtu && new_mtu <= Defaults.link_mtu then
          st.link_mtu <- new_mtu;
        pending
      | 3, 4 -> (* Prefix Information *)
        Printf.printf "NDP: Processing PREFIX option in RA\n%!";
        (* FIXME *)
        (* handle_prefix st opt; *)
        pending
      | ty, _ ->
        Printf.printf "NDP: ND option (%d) not supported in RA\n%!" ty;
        pending
    in
    (* TODO update the is_router flag even if there was no SLLA *)
    let pending = fold_options process_option opts None in
    let rtlt = Ipv6_wire.get_ra_rtlt buf in
    Printf.printf "RA: Adding %s to the Default Router List\n%!" (Ipaddr.V6.to_string src);
    if rtlt > 0 then begin
      let rt_list = List.remove_assoc src st.rt_list in
      st.rt_list <- (src, rtlt + st.tick) :: rt_list
    end;
    match pending with None -> [] | Some x -> [ x ]

  let ns_input st src dst buf =
    let target = Ipaddr.V6.of_cstruct (Ipv6_wire.get_ns_target buf) in

    Printf.printf "NDP: Received NS from %s to %s with target address %s\n%!"
      (Ipaddr.V6.to_string src) (Ipaddr.V6.to_string dst) (Ipaddr.V6.to_string target);

    (* TODO check hlim = 255, target not mcast, code = 0 *)

    let rec process_option ty len opt pending =
      match ty, len with
      | 2, 1 -> (* SLLA *) (* FIXME fail if DAD (src = unspec) *)
        let new_mac = Macaddr.of_cstruct (Cstruct.shift opt 2) in
        let nb =
          try
            Hashtbl.find st.nb_cache src
          with
          | Not_found ->
            add_nc_entry st ~ip:src ~is_router:false ~state:(STALE new_mac)
        in
        let pending = match nb.state with
          | INCOMPLETE (_, _, pending) ->
            nb.state <- STALE new_mac;
            map_option (fun x -> x new_mac) pending
          | REACHABLE (_, mac) | STALE mac | DELAY (_, mac) | PROBE (_, _, mac) ->
            if mac <> new_mac then nb.state <- STALE new_mac;
            pending
        in
        pending
      | ty, _ ->
        Printf.printf "NDP: ND option (%d) not supported in NS\n%!" ty;
        pending
    in
    let opts = Cstruct.shift buf Ipv6_wire.sizeof_ns in
    let pending = fold_options process_option opts None in

    if List.mem_assoc target st.my_ips then begin
      let pending1 =
        output st ~dst ~proto:58 ~hlim:255
          (alloc_na_data ~smac:st.my_mac ~src:dst ~target ~dst:src ~solicited:true)
      in
      match pending with
      | None -> pending1
      | Some x -> x :: pending1
    end else
      []

  let na_input st src dst buf =
    let target = Ipaddr.V6.of_cstruct (Ipv6_wire.get_na_target buf) in

    Printf.printf "NDP: Received NA from %s to %s with target address %s\n%!"
      (Ipaddr.V6.to_string src) (Ipaddr.V6.to_string dst) (Ipaddr.V6.to_string target);

    let is_router = Ipv6_wire.get_na_router buf in
    let solicited = Ipv6_wire.get_na_solicited buf in
    let override = Ipv6_wire.get_na_override buf in

    (* TODO check hlim = 255, code = 0, target not mcast, not (solicited && mcast (dst)) *)

    let rec process_options ty len opt mac =
      match ty, len with
      | 2, 1 ->
        Some (Macaddr.of_cstruct (Cstruct.shift opt 2))
      | ty, _ ->
        Printf.printf "NDP: ND option (%d) not supported in NA\n%!" ty;
        mac
    in
    let opts = Cstruct.shift buf Ipv6_wire.sizeof_na in
    let new_mac = fold_options process_options opts None in

    let send = ref [] in

    (* TODO if target is one of the my_ips then fail.  If my_ip is TENTATIVE then fail DAD. *)

    (* Printf.printf "NDP: %s -> %s\n%!" (Ipaddr.V6.to_string target); *)
    if Hashtbl.mem st.nb_cache target then begin
      let nb = Hashtbl.find st.nb_cache target in
      match nb.state, new_mac, solicited, override with
      | INCOMPLETE (_, _, pending), Some new_mac, false, _ ->
        Printf.printf "NDP: %s INCOMPLETE --> STALE\n%!" (Ipaddr.V6.to_string target);
        nb.state <- STALE new_mac;
        (match pending with None -> () | Some x -> send := [ x new_mac ])
      | INCOMPLETE (_, _, pending), Some new_mac, true, _ ->
        Printf.printf "NDP: %s INCOMPLETE --> REACHABLE\n%!" (Ipaddr.V6.to_string target);
        nb.state <- REACHABLE (st.tick + st.reachable_time, new_mac);
        (match pending with None -> () | Some x -> send := [ x new_mac ])
      | INCOMPLETE _, None, _, _ ->
        nb.is_router <- is_router
      | PROBE (_, _, mac), Some new_mac, true, false when mac = new_mac ->
        Printf.printf "NDP: %s PROBE --> REACHABLE\n%!" (Ipaddr.V6.to_string target);
        nb.state <- REACHABLE (st.tick + st.reachable_time, new_mac)
      | PROBE (_, _, mac), None, true, false ->
        Printf.printf "NDP: %s PROBE --> REACHABLE\n%!" (Ipaddr.V6.to_string target);
        nb.state <- REACHABLE (st.tick + st.reachable_time, mac)
      | (REACHABLE _ | STALE _ | DELAY _ | PROBE _), None, _, _ ->
        nb.is_router <- is_router
      | REACHABLE (_, mac), Some new_mac, true, false when mac <> new_mac ->
        Printf.printf "NDP: %s REACHABLE --> STALE\n%!" (Ipaddr.V6.to_string target);
        nb.state <- STALE mac (* TODO check mac or new_mac *)
      | (REACHABLE _ | STALE _ | DELAY _ | PROBE _), Some new_mac, true, true ->
        nb.state <- REACHABLE (st.tick + st.reachable_time, new_mac)
      | (REACHABLE (_, mac) | STALE mac | DELAY (_, mac) | PROBE (_, _, mac)),
        Some new_mac, false, true when mac <> new_mac ->
        Printf.printf "NDP: %s REACHABLE --> STALE\n%!" (Ipaddr.V6.to_string target);
        nb.state <- STALE mac
      | _ ->
        ()
    end;
    !send

  (* buf : icmp packet *)
  let icmp_input st ~src ~dst buf =
    let csum = cksum ~src ~dst ~proto:58 (* ICMP *) buf in
    if not (csum = 0) then begin
      Printf.printf "ICMP6 checksum error (0x%x), dropping packet\n%!" csum;
      []
    end else begin
      match Ipv6_wire.get_icmpv6_ty buf with
      | 129 (* Echo reply *) ->
        Printf.printf "ICMP6: Discarding Echo Reply\n%!";
        []
      | 133 (* RS *) ->
        (* RFC 4861, 2.6.2 *)
        []
      | 134 (* RA *) ->
        ra_input st src dst buf
      | 135 (* NS *) ->
        ns_input st src dst buf
      | 136 (* NA *) ->
        na_input st src dst buf
      | n ->
        Printf.printf "ICMP6: unrecognized type (%d)\n%!" n;
        []
    end

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
        Send []
      | 58 (* ICMP *) ->
        Send (icmp_input st ~src ~dst (Cstruct.shift buf Ipv6_wire.sizeof_ipv6))
      | 17 (* UDP *) ->
        Receive (UDP, src, dst, Cstruct.shift buf Ipv6_wire.sizeof_ipv6)
      | 6 (* TCP *) ->
        Receive (TCP, src, dst, Cstruct.shift buf Ipv6_wire.sizeof_ipv6)
      | n when 143 <= n && n <= 255 ->
        (* UNASSIGNED, EXPERIMENTAL & RESERVED *)
        Send []
      | n ->
        Receive (Other n, src, dst, Cstruct.shift buf Ipv6_wire.sizeof_ipv6)
    in
    loop st true (Ipv6_wire.get_ipv6_nhdr buf) Ipv6_wire.sizeof_ipv6

  let create mac =
    let reachable_time =
      let rt = float Defaults.reachable_time in
      let d = Defaults.(max_random_factor -. min_random_factor) in
      truncate (Random.float (d *. rt) +. Defaults.min_random_factor *. rt)
    in
    { nb_cache    = Hashtbl.create 0;
      prefix_list = [];
      rt_list     = [];
      my_mac      = mac;
      my_ips      = [];
      tick        = 0;

      link_mtu            = Defaults.link_mtu;
      curr_hop_limit      = 64; (* TODO *)
      base_reachable_time = Defaults.reachable_time;
      reachable_time;
      retrans_timer       = Defaults.retrans_timer }
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
      state : Engine.state;
      stop_ticker : unit Lwt.u }

  let input t ~tcp ~udp ~default buf =
    let open Engine in
    match handle_input t.state buf with
    | Receive (TCP, src, dst, buf) ->
      tcp ~src ~dst buf
    | Receive (UDP, src, dst, buf) ->
      udp ~src ~dst buf
    | Receive (Other n, src, dst, buf) ->
      default ~proto:n ~src ~dst buf
    | Send packets ->
      Lwt_list.iter_s begin fun packet ->
        Printf.printf "Sending ...%!";
        Cstruct.hexdump packet;
        Ethif.write t.ethif packet
      end packets

  let disconnect t =
    Lwt.wakeup t.stop_ticker ();
    Lwt.return_unit

  let connect ethif =
    let waiter, stop_ticker = Lwt.wait () in
    let t = { ethif; state = Engine.create (Ethif.mac ethif); stop_ticker } in
    let rec ticker () =
      let pending = Engine.tick t.state in
      List.iter (fun packet ->
          Printf.printf "Sending ...%!";
          Cstruct.hexdump packet) pending;
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
