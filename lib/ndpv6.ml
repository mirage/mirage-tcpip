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

let multicast_mac =
  let pbuf = Cstruct.create 6 in
  Cstruct.BE.set_uint16 pbuf 0 0x3333;
  fun ip ->
    let _, _, _, n = Ipaddr.V6.to_int32 ip in
    Cstruct.BE.set_uint32 pbuf 2 n;
    Macaddr.of_bytes_exn (Cstruct.to_string pbuf)

let interface_addr mac =
  let bmac = Macaddr.to_bytes mac in
  let c i = Char.code (Bytes.get bmac i) in
  Ipaddr.V6.make
    0 0 0 0
    ((c 0 lxor 2) lsl 8 + c 1)
    (c 2 lsl 8 + 0xff)
    (0xfe00 + c 3)
    (c 4 lsl 8 + c 5)

let link_local_addr mac =
  Ipaddr.V6.(Prefix.network_address
               (Prefix.make 64 (make 0xfe80 0 0 0 0 0 0 0))
               (interface_addr mac))

let solicited_node_prefix =
  Ipaddr.V6.(Prefix.make 104 (of_int16 (0xff02, 0, 0, 0, 0, 1, 0xff00, 0)))

module Defaults = struct
  let max_rtr_solicitation_delay = 1.0
  let ptr_solicitation_interval  = 4
  let max_rtr_solicitations      = 3
  let max_multicast_solicit      = 3
  let max_unicast_solicit        = 3
  let max_anycast_delay_time     = 1
  let max_neighbor_advertisement = 3
  let reachable_time             = 30.0
  let retrans_timer              = 1.0
  let delay_first_probe_time     = 5.0
  let min_random_factor          = 0.5
  let max_random_factor          = 1.5

  let link_mtu                   = 1500 (* RFC 2464, 2. *)
  let min_link_mtu               = 1280

  let dup_addr_detect_transmits  = 1
end

type na = {
  na_router    : bool;
  na_solicited : bool;
  na_override  : bool;
  na_target    : Ipaddr.V6.t;
  na_tlla      : Macaddr.t option
}

type ra_prefix = {
  prf_on_link            : bool;
  prf_autonomous         : bool;
  prf_valid_lifetime     : float;
  prf_preferred_lifetime : float;
  prf_prefix             : Ipaddr.V6.Prefix.t
}

type ra = {
  ra_cur_hop_limit   : int;
  ra_router_lifetime : float;
  ra_reachable_time  : float;
  ra_retrans_timer   : float;
  ra_slla            : Macaddr.t option;
  ra_prefix          : ra_prefix option
}

type ns = {
  ns_target : Ipaddr.V6.t;
  ns_slla   : Macaddr.t option
}

type nd_state =
  | INCOMPLETE of float * int * int option
  | REACHABLE  of float * Macaddr.t
  | STALE      of Macaddr.t
  | DELAY      of float * Macaddr.t
  | PROBE      of float * int * Macaddr.t

type nb_info = {
  state     : nd_state;
  is_router : bool
}

module IpMap = Map.Make (Ipaddr.V6)

type addr_state =
  | TENTATIVE  of (float * float option) option * int * float
  | PREFERRED  of (float * float option) option
  | DEPRECATED of float option

(* TODO add destination cache *)
type state = {
  neighbor_cache      : nb_info IpMap.t;
  prefix_list         : (Ipaddr.V6.Prefix.t * float option) list;
  router_list         : (Ipaddr.V6.t * float) list; (* invalidation timer *)
  mac                 : Macaddr.t;
  my_ips              : (Ipaddr.V6.t * addr_state) list;
  link_mtu            : int;
  cur_hop_limit       : int;
  base_reachable_time : float;
  reachable_time      : float;
  retrans_timer       : float;
  queue_count         : int
}

let is_local ~state ip =
  List.exists (fun (prf, _) -> Ipaddr.V6.Prefix.mem ip prf) state.prefix_list

let select_source_address st =
  let rec loop = function
    | (_, TENTATIVE _) :: rest -> loop rest
    | (ip, _) :: _             -> ip (* FIXME *)
    | []                       -> Ipaddr.V6.unspecified
  in
  loop st.my_ips

let next_hop ~state ip =

  (* RFC 2461, 5.2.  Next-hop determination for a given unicast destination
     operates as follows.  The sender performs a longest prefix match against
     the Prefix List to determine whether the packet's destination is on- or
     off-link.  If the destination is on-link, the next-hop address is the
     same as the packet's destination address.  Otherwise, the sender selects
     a router from the Default Router List (following the rules described in
     Section 6.3.6).  If the Default Router List is empty, the sender assumes
     that the destination is on-link. *)

  if is_local ~state ip then
    ip
  else
    (* TODO round-robin on non-potentially reachable routers *)
    let rec select_router = function
      | [] -> ip
      | [ip, _]              -> ip
      | (ip, _) :: rest ->
        if IpMap.mem ip state.neighbor_cache then
          let nb = IpMap.find ip state.neighbor_cache in
          match nb.state with
          | INCOMPLETE _ -> select_router rest
          | _ -> ip
        else
          select_router rest
    in
    match state.router_list with
    | [] -> ip
    | _ -> select_router state.router_list

type packet =
  | NS of ns
  | RA of ra
  | NA of na

type action =
  | Sleep        of float
  | SendNS       of Ipaddr.V6.t * Ipaddr.V6.t * Ipaddr.V6.t
  | SendNA       of Ipaddr.V6.t * Ipaddr.V6.t * Ipaddr.V6.t * bool
  | SendRS
  | SendQueued   of int * Macaddr.t
  | CancelQueued of int

let tick_nud ~now ~state ~ip ~nb =
  match nb.state with
  | INCOMPLETE (t, tn, pending) when t <= now ->
    if tn < Defaults.max_multicast_solicit then begin
      Printf.printf "ND: %s --> INCOMPLETE [Timeout]\n%!" (Ipaddr.V6.to_string ip);
      let src = select_source_address state in (* FIXME choose src in a paritcular way ? see 7.2.2 *)
      let dst = Ipaddr.V6.Prefix.network_address solicited_node_prefix ip in
      let dt  = state.retrans_timer in
      let nc  = IpMap.add ip {nb with state = INCOMPLETE (now +. dt, tn+1, pending)} state.neighbor_cache in
      {state with neighbor_cache = nc}, [ Sleep dt ; SendNS (src, dst, ip) ]
    end else begin
      Printf.printf "ND: Discarding %s\n%!" (Ipaddr.V6.to_string ip);
      (* TODO Generate ICMP error: Destination Unreachable *)
      let nc = IpMap.remove ip state.neighbor_cache in
      let acts = match pending with None -> [] | Some qc -> [ CancelQueued qc ] in
      {state with neighbor_cache = nc}, acts
    end
  | REACHABLE (t, mac) when t <= now ->
    Printf.printf "ND: %s --> STALE\n%!" (Ipaddr.V6.to_string ip);
    let nc = IpMap.add ip {nb with state = STALE mac} state.neighbor_cache in
    {state with neighbor_cache = nc}, []
  | DELAY (t, dmac) when t <= now ->
    Printf.printf "ND: %s --> PROBE\n%!" (Ipaddr.V6.to_string ip);
    let src = select_source_address state in
    let dt  = state.retrans_timer in
    let nc  = IpMap.add ip {nb with state = PROBE (now +. dt, 0, dmac)} state.neighbor_cache in
    {state with neighbor_cache = nc}, [ Sleep dt ; SendNS (src, ip, ip) ]
  | PROBE (t, tn, dmac) when t <= now ->
    if tn < Defaults.max_unicast_solicit then begin
      Printf.printf "ND: %s PROBE timeout, retrying\n%!" (Ipaddr.V6.to_string ip);
      let src = select_source_address state in
      let dt  = state.retrans_timer in
      let nc  = IpMap.add ip {nb with state = PROBE (now +. dt, tn+1, dmac)} state.neighbor_cache in
      {state with neighbor_cache = nc}, [ Sleep dt ; SendNS (src, ip, ip) ]
    end else begin
      Printf.printf "ND: %s PROBE failed, discarding\n%!" (Ipaddr.V6.to_string ip);
      let nc = IpMap.remove ip state.neighbor_cache in
      {state with neighbor_cache = nc}, []
    end
  | _ ->
    state, []

let tick_address ~now ~state = function
  | (ip, TENTATIVE (timeout, n, t)) when t <= now ->
    if n + 1 >= Defaults.dup_addr_detect_transmits then
      let timeout, acts = match timeout with
        | None -> None, []
        | Some (preferred_lifetime, valid_lifetime) ->
          Some (now +. preferred_lifetime, valid_lifetime), [ Sleep preferred_lifetime ]
      in
      Printf.printf "DAD: %s --> PREFERRED\n%!" (Ipaddr.V6.to_string ip);
      Some (ip, PREFERRED timeout), acts
    else
      let dst = Ipaddr.V6.Prefix.network_address solicited_node_prefix ip in
      let dt  = state.retrans_timer in
      Some (ip, TENTATIVE (timeout, n + 1, now +. dt)),
      [ Sleep dt ; SendNS (Ipaddr.V6.unspecified, dst, ip) ]
  | ip, PREFERRED (Some (preferred_timeout, valid_lifetime)) when preferred_timeout <= now ->
    Printf.printf "DAD : %s --> DEPRECATED\n%!" (Ipaddr.V6.to_string ip);
    let valid_timeout, acts = match valid_lifetime with
      | None -> None, []
      | Some valid_lifetime -> Some (now +. valid_lifetime), [ Sleep valid_lifetime ]
    in
    Some (ip, DEPRECATED valid_timeout), acts
  | ip, DEPRECATED (Some t) when t <= now ->
    Printf.printf "DAD: %s --> EXPIRED\n%!" (Ipaddr.V6.to_string ip);
    None, []
  | addr ->
    Some addr, []

let tick ~now ~state =

  let state, acts =
    IpMap.fold (fun ip nb (state, acts) ->
        let state, acts' = tick_nud ~now ~state ~ip ~nb in
        state, acts' @ acts) state.neighbor_cache (state, [])
  in

  let some_router_expired = List.exists (fun (_, t) -> t <= now) state.router_list in
  let state =
    if some_router_expired then
      {state with router_list = List.filter (fun (_, t) -> t > now) state.router_list}
    else
      state
  in
  (* FIXME if we are keeping a destination cache, we must remove the stale routers from there as well. *)

  let some_prefix_expired = List.exists (function (_, Some t) -> t <= now | _ -> false) state.prefix_list in
  let state =
    if some_prefix_expired then
      {state with prefix_list = List.filter (function (_, Some t) -> t > now | _ -> true) state.prefix_list}
    else
      state
  in

  let some_address_expired =
    List.exists begin function
      | _, TENTATIVE (_, _, t)
      | _, PREFERRED (Some (t, _))
      | _, DEPRECATED (Some t) -> t <= now
      | _ -> false
    end state.my_ips
  in

  if some_address_expired then begin
    let my_ips, acts =
      List.fold_right begin fun ip (ips, acts) ->
        let addr, acts' = tick_address ~now ~state ip in
        let acts        = acts' @ acts in
        let ips         = match addr with Some ip -> ip :: ips | None -> ips in
        ips, acts
      end state.my_ips ([], acts)
    in
    {state with my_ips}, acts
  end else
    state, acts

let update_prefix ~now ~state prf ~valid =
  let already_exists = List.mem_assoc prf state.prefix_list in
  match already_exists, valid with
  | false, 0.0 ->
    state, []
  | true, 0.0 ->
    Printf.printf "ND: Removing prefix %s\n%!" (Ipaddr.V6.Prefix.to_string prf);
    {state with prefix_list = List.remove_assoc prf state.prefix_list}, []
  | true, dt ->
    Printf.printf "ND: Refreshing prefix %s, lifetime %f\n%!" (Ipaddr.V6.Prefix.to_string prf) dt;
    let prefix_list = List.remove_assoc prf state.prefix_list in
    {state with prefix_list = (prf, Some (now +. dt)) :: prefix_list}, [ Sleep dt ]
  | false, dt ->
    Printf.printf "ND: Adding prefix %s, lifetime %f\n%!" (Ipaddr.V6.Prefix.to_string prf) dt;
    {state with prefix_list = (prf, Some (now +. dt)) :: state.prefix_list}, [ Sleep dt ]

let add_router ~now ~state ?(lifetime = max_float) ip =
  {state with router_list = (ip, now +. lifetime) :: state.router_list} (* FIXME *)

let get_routers state =
  List.map fst state.router_list

let compute_reachable_time dt =
  let r = Defaults.(min_random_factor +. Random.float (max_random_factor -. min_random_factor)) in
  r *. dt

let lookup_prefix ~st pref =
  let rec loop = function
    | (ip, _) :: _ when Ipaddr.V6.Prefix.mem ip pref -> Some ip
    | _ :: rest                                      -> loop rest
    | []                                             -> None
  in
  loop st.my_ips

let add_ip ~now ~state ?lifetime ip =
  if not (List.mem_assq ip state.my_ips) then
    let dt  = state.retrans_timer in
    let state  = {state with my_ips = (ip, TENTATIVE (lifetime, 0, now +. dt)) :: state.my_ips} in
    let src = Ipaddr.V6.unspecified in
    let dst = Ipaddr.V6.Prefix.network_address solicited_node_prefix ip in
    state, [ Sleep dt ; SendNS (src, dst, ip) ]
  else
    (* TODO log warning *)
    state, []

let float_of_uint32 n = Uint32.to_float @@ Uint32.of_int32 n

let handle_ra_slla ~state ~src new_mac =
  Printf.printf "ND: Processing SLLA option in RA\n%!";
  let nb =
    if IpMap.mem src state.neighbor_cache then
      let nb = IpMap.find src state.neighbor_cache in
      if nb.is_router then
        nb
      else
        {nb with is_router = true}
    else
      {state = STALE new_mac; is_router = true}
  in
  let nb, acts =
    match nb.state with
    | INCOMPLETE (_, _, pending) ->
      let nb = {nb with state = STALE new_mac} in
      let acts = match pending with None -> [] | Some qc -> [ SendQueued (qc, new_mac) ] in
      nb, acts
    | REACHABLE (_, mac) | STALE mac | DELAY (_, mac) | PROBE (_, _, mac) ->
      let nb = if mac <> new_mac then {nb with state = STALE new_mac} else nb in
      nb, []
  in
  {state with neighbor_cache = IpMap.add src nb state.neighbor_cache}, acts

let handle_ra_prefix ~now ~state prf =
  Printf.printf "ND: Processing PREFIX option in RA\n%!";
  (* TODO check for 0 (this is checked in update_prefix currently), infinity *)
  if prf.prf_valid_lifetime >= prf.prf_preferred_lifetime && Ipaddr.V6.Prefix.link <> prf.prf_prefix then
    let state, acts =
      if prf.prf_on_link then
        update_prefix ~now ~state prf.prf_prefix ~valid:prf.prf_valid_lifetime
      else
        state, []
    in
    if prf.prf_autonomous && prf.prf_valid_lifetime > 0.0 then
      match lookup_prefix state prf.prf_prefix with
      | Some addr ->
        (* TODO handle already configured SLAAC address 5.5.3 e). *)
        state, acts
      | None ->
        let ip = Ipaddr.V6.Prefix.network_address prf.prf_prefix (interface_addr state.mac) in
        let state, acts' =
          add_ip ~now ~state ~lifetime:(prf.prf_preferred_lifetime, Some prf.prf_valid_lifetime) ip
        in
        state, acts' @ acts
    else
      state, acts
  else
    state, []

let handle_ra ~now ~state ~src ~dst ~ra =
  Printf.printf "ND: Received RA from %s to %s\n%!" (Ipaddr.V6.to_string src) (Ipaddr.V6.to_string dst);

  let state =
    if ra.ra_cur_hop_limit <> 0 then {state with cur_hop_limit = ra.ra_cur_hop_limit} else state
  in

  let state =
    if ra.ra_reachable_time <> 0.0 && state.base_reachable_time <> ra.ra_reachable_time then
      {state with base_reachable_time = ra.ra_reachable_time;
                  reachable_time      = compute_reachable_time ra.ra_reachable_time}
    else
      state
  in

  let state =
    if ra.ra_retrans_timer <> 0.0 then
      {state with retrans_timer = ra.ra_retrans_timer}
    else
      state
  in

  let state, acts =
    match ra.ra_slla with
    | Some new_mac ->
      handle_ra_slla ~state ~src new_mac
    | None ->
      state, []
  in

  let state, acts' =
    match ra.ra_prefix with
    | Some prf ->
      handle_ra_prefix ~now ~state prf
    | None ->
      state, []
  in

  let acts = acts @ acts' in

  (* TODO update the is_router flag even if there was no SLLA *)

  let router_list, acts' =
    match List.mem_assoc src state.router_list with
    | true ->
      let router_list = List.remove_assoc src state.router_list in
      if ra.ra_router_lifetime > 0.0 then begin
        Printf.printf "RA: Refreshing Router %s ltime %f\n%!" (Ipaddr.V6.to_string src) ra.ra_router_lifetime;
        let dt = ra.ra_router_lifetime in
        (src, now +. dt) :: router_list, [ Sleep dt ]
      end else begin
        Printf.printf "RA: Router %s is EOL\n%!" (Ipaddr.V6.to_string src);
        router_list, []
      end
    | false ->
      if ra.ra_router_lifetime > 0.0 then begin
        Printf.printf "RA: Adding %s to the Default Router List\n%!" (Ipaddr.V6.to_string src);
        let dt = ra.ra_router_lifetime in
        (src, now +. dt) :: state.router_list, [ Sleep dt ]
      end else
        state.router_list, []
  in

  {state with router_list}, acts' @ acts

let handle_ns_slla ~state ~src new_mac =
  let nb =
    if IpMap.mem src state.neighbor_cache then
      IpMap.find src state.neighbor_cache
    else
      {state = STALE new_mac; is_router = false}
  in
  let nb, acts =
    match nb.state with
    | INCOMPLETE (_, _, pending) ->
      let nb = {nb with state = STALE new_mac} in
      let acts = match pending with None -> [] | Some qc -> [ SendQueued (qc, new_mac) ] in
      nb, acts
    | REACHABLE (_, mac) | STALE mac | DELAY (_, mac) | PROBE (_, _, mac) ->
      let nb = if mac <> new_mac then {nb with state = STALE new_mac} else nb in
      nb, []
  in
  {state with neighbor_cache = IpMap.add src nb state.neighbor_cache}, acts

let handle_ns ~now ~state ~src ~dst ~ns =
  Printf.printf "ND: Received NS from %s to %s with target address %s\n%!"
    (Ipaddr.V6.to_string src) (Ipaddr.V6.to_string dst) (Ipaddr.V6.to_string ns.ns_target);

  (* TODO check hlim = 255, target not mcast, code = 0 *)

  let state, acts = match ns.ns_slla with
    | Some new_mac ->
      handle_ns_slla ~state ~src new_mac
    | None ->
      state, []
  in

  if List.mem_assoc ns.ns_target state.my_ips then begin
    let src = ns.ns_target and dst = src in (* FIXME src & dst *)
    (* Printf.printf "Sending NA to %s from %s with target address %s\n%!" *)
      (* (Ipaddr.V6.to_string dst) (Ipaddr.V6.to_string src) (Ipaddr.V6.to_string target); *)
    state, SendNA (src, dst, ns.ns_target, true) :: acts
  end else
    state, acts

let handle_na ~now ~state ~src ~dst ~na =
  Printf.printf "ND: Received NA from %s to %s with target address %s\n%!"
    (Ipaddr.V6.to_string src) (Ipaddr.V6.to_string dst) (Ipaddr.V6.to_string na.na_target);

  (* TODO check hlim = 255, code = 0, target not mcast, not (solicited && mcast (dst)) *)

  let new_mac = na.na_tlla in

  (* TODO if target is one of the my_ips then fail.  If my_ip is TENTATIVE then fail DAD. *)

  let nc = state.neighbor_cache in

  let update nb =
    match nb.state, new_mac, na.na_solicited, na.na_override with
    | INCOMPLETE (_, _, pending), Some new_mac, false, _ ->
      Printf.printf "ND: %s --> STALE\n%!" (Ipaddr.V6.to_string na.na_target);
      let nb = {nb with state = STALE new_mac} in
      let acts = match pending with None -> [] | Some qc -> [ SendQueued (qc, new_mac) ] in
      IpMap.add na.na_target nb nc, acts
    | INCOMPLETE (_, _, pending), Some new_mac, true, _ ->
      Printf.printf "ND: %s --> REACHABLE\n%!" (Ipaddr.V6.to_string na.na_target);
      let dt = state.reachable_time in
      let nb = {nb with state = REACHABLE (now +. dt, new_mac)} in
      let acts = match pending with None -> [] | Some qc -> [ SendQueued (qc, new_mac) ] in
      IpMap.add na.na_target nb nc, Sleep dt :: acts
    | INCOMPLETE _, None, _, _ ->
      let nc =
        if nb.is_router != na.na_router then
          IpMap.add na.na_target {nb with is_router = na.na_router} nc
        else
          nc
      in
      nc, []
    | PROBE (_, _, mac), Some new_mac, true, false when mac = new_mac ->
      Printf.printf "ND: %s --> REACHABLE\n%!" (Ipaddr.V6.to_string na.na_target);
      let dt = state.reachable_time in
      let nb = {nb with state = REACHABLE (now +. dt, new_mac)} in
      IpMap.add na.na_target nb nc, [ Sleep dt ]
    | PROBE (_, _, mac), None, true, false ->
      Printf.printf "ND: %s --> REACHABLE\n%!" (Ipaddr.V6.to_string na.na_target);
      let dt = state.reachable_time in
      let nb = {nb with state = REACHABLE (now +. dt, mac)} in
      IpMap.add na.na_target nb nc, [ Sleep dt ]
    | (REACHABLE _ | STALE _ | DELAY _ | PROBE _), None, _, _ ->
      let nc =
        if nb.is_router != na.na_router then
          IpMap.add na.na_target {nb with is_router = na.na_router} nc
        else
          nc
      in
      nc, []
    | REACHABLE (_, mac), Some new_mac, true, false when mac <> new_mac ->
      Printf.printf "ND: %s --> STALE\n%!" (Ipaddr.V6.to_string na.na_target);
      let nb = {nb with state = STALE mac} in (* TODO check mac or new_mac *)
      IpMap.add na.na_target nb nc, []
    | (REACHABLE _ | STALE _ | DELAY _ | PROBE _), Some new_mac, true, true ->
      Printf.printf "ND: %s --> REACHABLE\n%!" (Ipaddr.V6.to_string na.na_target);
      let dt = state.reachable_time in
      let nb = {nb with state = REACHABLE (now +. dt, new_mac)} in
      IpMap.add na.na_target nb nc, [ Sleep dt ]
    | (REACHABLE (_, mac) | STALE mac | DELAY (_, mac) | PROBE (_, _, mac)),
      Some new_mac, false, true when mac <> new_mac ->
      Printf.printf "ND: %s --> STALE\n%!" (Ipaddr.V6.to_string na.na_target);
      let nb = {nb with state = STALE mac} in
      IpMap.add na.na_target nb nc, []
    | _ ->
      nc, []
  in

  if IpMap.mem na.na_target state.neighbor_cache then
    let nb = IpMap.find na.na_target state.neighbor_cache in
    let nc, acts = update nb in
    {state with neighbor_cache = nc}, acts
  else
    state, []

(* buf : icmp packet with ipv6 header *)
let input ~now ~state ~src ~dst = function
  | RA ra ->
    handle_ra ~now ~state ~src ~dst ~ra
  | NS ns ->
    handle_ns ~now ~state ~src ~dst ~ns
  | NA na ->
    handle_na ~now ~state ~src ~dst ~na

let is_my_addr ~state ip =
  List.exists begin function
    | _, TENTATIVE _                    -> false
    | ip', (PREFERRED _ | DEPRECATED _) -> Ipaddr.V6.compare ip' ip = 0
  end state.my_ips

let create ~now mac =
  let state =
    { neighbor_cache      = IpMap.empty;
      prefix_list         = [Ipaddr.V6.Prefix.make 64 (Ipaddr.V6.make 0xfe80 0 0 0 0 0 0 0), None];
      router_list         = [];
      mac                 = mac;
      my_ips              = [];
      link_mtu            = Defaults.link_mtu;
      cur_hop_limit       = 64; (* TODO *)
      base_reachable_time = Defaults.reachable_time;
      reachable_time      = compute_reachable_time Defaults.reachable_time;
      retrans_timer       = Defaults.retrans_timer;
      queue_count         = 0 }
  in
  let ip = link_local_addr mac in
  let state, acts = add_ip ~now ~state ip in
  state, SendRS :: acts

type output =
  | SendNow of Macaddr.t
  | SendLater of int

let output ~now ~state ~dst =
  match Ipaddr.V6.is_multicast dst with
  | true ->
    state, SendNow (multicast_mac dst), []
  | false ->
    let ip = next_hop ~state dst in
    if IpMap.mem ip state.neighbor_cache then
      let nb = IpMap.find ip state.neighbor_cache in
      match nb.state with
      | INCOMPLETE (t, nt, pending) ->
        let qc = state.queue_count in
        let acts = match pending with None -> [] | Some qc -> [CancelQueued qc] in
        let nc = IpMap.add dst {nb with state = INCOMPLETE (t, nt, Some qc)} state.neighbor_cache in
        {state with neighbor_cache = nc; queue_count = qc + 1}, SendLater qc, acts
      | REACHABLE (_, dmac) | DELAY (_, dmac) | PROBE (_, _, dmac) ->
        state, SendNow dmac, []
      | STALE dmac ->
        let dt = Defaults.delay_first_probe_time in
        let nc = IpMap.add dst {nb with state = DELAY (now +. dt, dmac)} state.neighbor_cache in
        {state with neighbor_cache = nc}, SendNow dmac, [ Sleep dt ]
    else
      let dt  = state.reachable_time in
      let qc  = state.queue_count in
      let nb  = {state = INCOMPLETE (now +. dt, 0, Some qc); is_router = false} in
      let nc  = IpMap.add ip nb state.neighbor_cache in
      let dst = Ipaddr.V6.Prefix.network_address solicited_node_prefix ip in
      let state = {state with neighbor_cache = nc; queue_count = qc + 1} in
      state, SendLater qc, [ SendNS (select_source_address state, dst, ip); Sleep dt ]

let mac state = state.mac

let get_ipv6 state =
  let rec loop = function
    | [] -> []
    | (_, TENTATIVE _) :: rest -> loop rest
    | (ip, (PREFERRED _ | DEPRECATED _)) :: rest -> ip :: loop rest
  in
  loop state.my_ips

let cur_hop_limit state =
  state.cur_hop_limit
