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

module Ipaddr = Ipaddr.V6

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
  Ipaddr.(Prefix.network_address
            (Prefix.make 64 (make 0xfe80 0 0 0 0 0 0 0))
            (interface_addr mac))

let solicited_node_prefix =
  Ipaddr.(Prefix.make 104 (of_int16 (0xff02, 0, 0, 0, 0, 1, 0xff00, 0)))

module Defaults = struct
  let max_rtr_solicitation_delay = 1.0
  let ptr_solicitation_interval  = 4
  let max_rtr_solicitations      = 3
  let max_multicast_solicit      = 3
  let max_unicast_solicit        = 3
  let max_anycast_delay_time     = 1
  let max_neighbor_advertisement = 3
  let delay_first_probe_time     = 5.0

  let link_mtu                   = 1500 (* RFC 2464, 2. *)
  let min_link_mtu               = 1280

  let dup_addr_detect_transmits  = 1
end

module Action = struct
  type specified_flag =
    | Unspecified
    | Specified
  type solicited_flag =
    | Solicited
    | Unsolicited
  type t =
    | Sleep of float
    | SendNS of specified_flag * Ipaddr.t * Ipaddr.t
    | SendNA of Ipaddr.t * Ipaddr.t * Ipaddr.t * solicited_flag
    | SendRS
    | SendQueued of Ipaddr.t * Macaddr.t
    | CancelQueued of Ipaddr.t
end

module AddressList = struct

  type state =
    | TENTATIVE of (float * float option) option * int * float
    | PREFERRED of (float * float option) option
    | DEPRECATED of float option

  type t =
    (Ipaddr.t * state) list

  let empty =
    []

  let to_list al =
    let rec loop = function
      | [] -> []
      | (_, TENTATIVE _) :: rest -> loop rest
      | (ip, (PREFERRED _ | DEPRECATED _)) :: rest -> ip :: loop rest
    in
    loop al

  let select_source al ~dst:_ =
    let rec loop = function
      | (_, TENTATIVE _) :: rest -> loop rest
      | (ip, _) :: _             -> ip (* FIXME *)
      | []                       -> Ipaddr.unspecified
    in
    loop al

  let tick_one ~now ~retrans_timer = function
    | (ip, TENTATIVE (timeout, n, t)) when t <= now ->
      if n + 1 >= Defaults.dup_addr_detect_transmits then
        let timeout, acts = match timeout with
          | None -> None, []
          | Some (preferred_lifetime, valid_lifetime) ->
            Some (now +. preferred_lifetime, valid_lifetime), [Action.Sleep preferred_lifetime]
        in
        Printf.printf "SLAAC: %s --> PREFERRED\n%!" (Ipaddr.to_string ip);
        Some (ip, PREFERRED timeout), acts
      else
        let dst = Ipaddr.Prefix.network_address solicited_node_prefix ip in
        Some (ip, TENTATIVE (timeout, n+1, now +. retrans_timer)),
        [Action.Sleep retrans_timer; Action.SendNS (Action.Unspecified, dst, ip)]
    | ip, PREFERRED (Some (preferred_timeout, valid_lifetime)) when preferred_timeout <= now ->
      Printf.printf "SLAAC: %s --> DEPRECATED\n%!" (Ipaddr.to_string ip);
      let valid_timeout, acts = match valid_lifetime with
        | None -> None, []
        | Some valid_lifetime -> Some (now +. valid_lifetime), [Action.Sleep valid_lifetime]
      in
      Some (ip, DEPRECATED valid_timeout), acts
    | ip, DEPRECATED (Some t) when t <= now ->
      Printf.printf "SLAAC: %s --> EXPIRED\n%!" (Ipaddr.to_string ip);
      None, []
    | addr ->
      Some addr, []

  let tick al ~now ~retrans_timer =
    List.fold_right begin fun ip (ips, acts) ->
      let addr, acts' = tick_one ~now ~retrans_timer ip in
      let acts = acts' @ acts in
      let ips = match addr with Some ip -> ip :: ips | None -> ips in
      ips, acts
    end al ([], [])

  let expired al ~now =
    List.exists begin function
      | _, TENTATIVE (_, _, t)
      | _, PREFERRED (Some (t, _))
      | _, DEPRECATED (Some t) -> t <= now
      | _ -> false
    end al

  let add al ~now ~retrans_timer ~lft ip =
    if not (List.mem_assoc ip al) then
      let al = (ip, TENTATIVE (lft, 0, now +. retrans_timer)) :: al in
      let dst = Ipaddr.Prefix.network_address solicited_node_prefix ip in
      al, [Action.Sleep retrans_timer; Action.SendNS (Action.Unspecified, dst, ip)]
    else
      (* TODO log warning *)
      al, []

  let is_my_addr al ip =
    List.exists
      (function
        | _, TENTATIVE _ -> false
        | ip', (PREFERRED _ | DEPRECATED _) -> Ipaddr.compare ip' ip = 0)
      al

  let find_prefix al pfx =
    let rec loop = function
      | (ip, _) :: _ when Ipaddr.Prefix.mem ip pfx -> Some ip
      | _ :: rest -> loop rest
      | [] -> None
    in
    loop al

  let configure al ~now ~retrans_timer ~lft mac pfx =
    (* FIXME is this the same as add ? *)
    match find_prefix al pfx with
    | Some addr ->
      (* TODO handle already configured SLAAC address 5.5.3 e). *)
      al, []
    | None ->
      let ip = Ipaddr.Prefix.network_address pfx (interface_addr mac) in
      add al ~now ~retrans_timer ~lft ip

  let handle_na al ip =
    assert false
end

module PrefixList = struct

  type t =
    (Ipaddr.Prefix.t * float option) list

  let link_local =
    [Ipaddr.Prefix.link, None]

  let to_list pl =
    List.map fst pl

  let is_local pl ip =
    List.exists (fun (pfx, _) -> Ipaddr.Prefix.mem ip pfx) pl

  let expired pl ~now =
    List.exists (function (_, Some t) -> t <= now | (_, None) -> false) pl

  let tick pl ~now =
    List.filter (function (_, Some t) -> t > now | (_, None) -> true) pl

  let add pl ~now pfx ~vlft =
    let vlft = match vlft with
      | None -> None
      | Some dt -> Some (now +. dt)
    in
    match List.mem_assoc pfx pl with
    | false ->
      (pfx, vlft) :: pl
    | true ->
      let pl = List.remove_assoc pfx pl in
      (pfx, vlft) :: pl

  let handle_ra pl ~now ~vlft pfx =

    (* RFC 2461, 6.3.4.

       For each Prefix Information option with the on-link flag set, a host
       does the following:

       - If the prefix is the link-local prefix, silently ignore the
         Prefix Information option.

       - If the prefix is not already present in the Prefix List, and the Prefix
         Information option's Valid Lifetime field is non-zero, create a new
         entry for the prefix and initialize its invalidation timer to the Valid
         Lifetime value in the Prefix Information option.

       - If the prefix is already present in the host's Prefix List as the
         result of a previously-received advertisement, reset its invalidation
         timer to the Valid Lifetime value in the Prefix Information option.  If
         the new Lifetime value is zero, time-out the prefix immediately (see
         Section 6.3.5).

       - If the Prefix Information option's Valid Lifetime field is zero, and
         the prefix is not present in the host's Prefix List, silently ignore
         the option. *)

    Printf.printf "ND6: Processing PREFIX option in RA\n%!";
    if Ipaddr.Prefix.link <> pfx then
      match vlft, List.mem_assoc pfx pl with
      | Some 0.0, true ->
        Printf.printf "ND6: Removing PREFIX: pfx=%s\n%!" (Ipaddr.Prefix.to_string pfx);
        List.remove_assoc pfx pl, []
      | Some 0.0, false ->
        pl, []
      | Some dt, true ->
        Printf.printf "ND6: Refreshing PREFIX: pfx=%s lft=%f\n%!" (Ipaddr.Prefix.to_string pfx) dt;
        let pl = List.remove_assoc pfx pl in
        (pfx, Some (now +. dt)) :: pl, [Action.Sleep dt]
      | Some dt, false ->
        Printf.printf "ND6: Received new PREFIX: pfx=%s lft=%f\n%!" (Ipaddr.Prefix.to_string pfx) dt;
        (pfx, Some (now +. dt)) :: pl, [Action.Sleep dt]
      | None, true ->
        Printf.printf "ND6: Refreshing PREFIX: pfx=%s lft=inf\n%!" (Ipaddr.Prefix.to_string pfx);
        let pl = List.remove_assoc pfx pl in
        (pfx, None) :: pl, []
      | None, false ->
        Printf.printf "ND6: Received new PREFIX: pfx=%s lft=inf\n%!" (Ipaddr.Prefix.to_string pfx);
        (pfx, None) :: pl, []
    else
      pl, []
    (* TODO check for 0 (this is checked in update_prefix currently), infinity *)
    (* if vlft >= plft && Ipaddr.Prefix.link <> pfx then *)
    (*   let pl, acts = *)
    (*     if on_link then *)
    (*       update pl ~now ~valid:vlft pfx *)
    (*     else *)
    (*       pl, [] *)
    (*   in *)
    (*   if aut && (vlft :> float) > 0.0 then *)
    (*     pl, acts, Some (pfx, plft, vlft) *)
    (*   else *)
    (*     pl, acts, None *)
    (* else *)
    (*   pl, [], None *)
end

module NeighborCache = struct

  type state =
    | INCOMPLETE of float * int
    | REACHABLE  of float * Macaddr.t
    | STALE      of Macaddr.t
    | DELAY      of float * Macaddr.t
    | PROBE      of float * int * Macaddr.t

  type info = {
    state     : state;
    is_router : bool
  }

  module IpMap = Map.Make (Ipaddr)

  type t =
    info IpMap.t

  let empty =
    IpMap.empty

  let tick_one ~now ~retrans_timer ip nb nc =
    match nb.state with
    | INCOMPLETE (t, tn) when t <= now ->
      if tn < Defaults.max_multicast_solicit then begin
        Printf.printf "NUD: %s --> INCOMPLETE [Timeout]\n%!" (Ipaddr.to_string ip);
        let dst = Ipaddr.Prefix.network_address solicited_node_prefix ip in
        IpMap.add ip {nb with state = INCOMPLETE (now +. retrans_timer, tn+1)} nc,
        [Action.Sleep retrans_timer; Action.SendNS (Action.Specified, dst, ip)]
      end else begin
        Printf.printf "NUD: %s --> UNREACHABLE [Discarding]\n%!" (Ipaddr.to_string ip);
        (* TODO Generate ICMP error: Destination Unreachable *)
        IpMap.remove ip nc, [Action.CancelQueued ip]
      end
    | REACHABLE (t, mac) when t <= now ->
      Printf.printf "NUD: %s --> STALE\n%!" (Ipaddr.to_string ip);
      IpMap.add ip {nb with state = STALE mac} nc, []
    | DELAY (t, dmac) when t <= now ->
      Printf.printf "NUD: %s --> PROBE\n%!" (Ipaddr.to_string ip);
      IpMap.add ip {nb with state = PROBE (now +. retrans_timer, 0, dmac)} nc,
      [Action.Sleep retrans_timer; Action.SendNS (Action.Specified, ip, ip)]
    | PROBE (t, tn, dmac) when t <= now ->
      if tn < Defaults.max_unicast_solicit then begin
        Printf.printf "NUD: %s --> PROBE [Timeout]\n%!" (Ipaddr.to_string ip);
        IpMap.add ip {nb with state = PROBE (now +. retrans_timer, tn+1, dmac)} nc,
        [Action.Sleep retrans_timer; Action.SendNS (Action.Specified, ip, ip)]
      end else begin
        Printf.printf "NUD: %s --> UNREACHABLE [Discarding]\n%!" (Ipaddr.to_string ip);
        IpMap.remove ip nc, []
      end
    | _ ->
      nc, []

  let tick nc ~now ~retrans_timer =
    IpMap.fold
      (fun ip nb (nc, acts) ->
        let nc, acts' = tick_one ~now ~retrans_timer ip nb nc in
        nc, acts' @ acts) nc (nc, [])

  let handle_ns nc ~src new_mac =
    let nb =
      if IpMap.mem src nc then
        IpMap.find src nc
      else
        {state = STALE new_mac; is_router = false}
    in
    let nb, acts =
      match nb.state with
      | INCOMPLETE _ ->
        let nb = {nb with state = STALE new_mac} in
        nb, [Action.SendQueued (src, new_mac)]
      | REACHABLE (_, mac) | STALE mac | DELAY (_, mac) | PROBE (_, _, mac) ->
        let nb = if mac <> new_mac then {nb with state = STALE new_mac} else nb in
        nb, []
    in
    IpMap.add src nb nc, acts

  let handle_ra nc ~src new_mac =
    Printf.printf "ND6: Processing SLLA option in RA\n%!";
    let nb =
      try
        let nb = IpMap.find src nc in
        {nb with is_router = true}
      with
      | Not_found ->
        {state = STALE new_mac; is_router = true}
    in
    match nb.state with
    | INCOMPLETE _ ->
      let nb = {nb with state = STALE new_mac} in
      IpMap.add src nb nc, [Action.SendQueued (src, new_mac)]
    | REACHABLE (_, mac) | STALE mac | DELAY (_, mac) | PROBE (_, _, mac) ->
      let nb = if mac <> new_mac then {nb with state = STALE new_mac} else nb in
      IpMap.add src nb nc, []

  let handle_na nc ~now ~reachable_time ~rtr ~sol ~ovr ~tgt ~lladdr =
    let new_mac = lladdr in

    let update nb =
      match nb.state, new_mac, sol, ovr with
      | INCOMPLETE _, Some new_mac, false, _ ->
        Printf.printf "NUD: %s --> STALE\n%!" (Ipaddr.to_string tgt);
        let nb = {nb with state = STALE new_mac} in
        IpMap.add tgt nb nc, [Action.SendQueued (tgt, new_mac)]
      | INCOMPLETE _, Some new_mac, true, _ ->
        Printf.printf "NUD: %s --> REACHABLE\n%!" (Ipaddr.to_string tgt);
        let nb = {nb with state = REACHABLE (now +. reachable_time, new_mac)} in
        IpMap.add tgt nb nc, [Action.Sleep reachable_time; Action.SendQueued (tgt, new_mac)]
      | INCOMPLETE _, None, _, _ ->
        let nc =
          if nb.is_router != rtr then
            IpMap.add tgt {nb with is_router = rtr} nc
          else
            nc
        in
        nc, []
      | PROBE (_, _, mac), Some new_mac, true, false when mac = new_mac ->
        Printf.printf "NUD: %s --> REACHABLE\n%!" (Ipaddr.to_string tgt);
        let nb = {nb with state = REACHABLE (now +. reachable_time, new_mac)} in
        IpMap.add tgt nb nc, [Action.Sleep reachable_time]
      | PROBE (_, _, mac), None, true, false ->
        Printf.printf "NUD: %s --> REACHABLE\n%!" (Ipaddr.to_string tgt);
        let nb = {nb with state = REACHABLE (now +. reachable_time, mac)} in
        IpMap.add tgt nb nc, [Action.Sleep reachable_time]
      | (REACHABLE _ | STALE _ | DELAY _ | PROBE _), None, _, _ ->
        let nc =
          if nb.is_router != rtr then
            IpMap.add tgt {nb with is_router = rtr} nc
          else
            nc
        in
        nc, []
      | REACHABLE (_, mac), Some new_mac, true, false when mac <> new_mac ->
        Printf.printf "NUD: %s --> STALE\n%!" (Ipaddr.to_string tgt);
        let nb = {nb with state = STALE mac} in (* TODO check mac or new_mac *)
        IpMap.add tgt nb nc, []
      | (REACHABLE _ | STALE _ | DELAY _ | PROBE _), Some new_mac, true, true ->
        Printf.printf "NUD: %s --> REACHABLE\n%!" (Ipaddr.to_string tgt);
        let nb = {nb with state = REACHABLE (now +. reachable_time, new_mac)} in
        IpMap.add tgt nb nc, [Action.Sleep reachable_time]
      | (REACHABLE (_, mac) | STALE mac | DELAY (_, mac) | PROBE (_, _, mac)),
        Some new_mac, false, true when mac <> new_mac ->
        Printf.printf "NUD: %s --> STALE\n%!" (Ipaddr.to_string tgt);
        let nb = {nb with state = STALE mac} in
        IpMap.add tgt nb nc, []
      | _ ->
        nc, []
    in
    try
      let nb = IpMap.find tgt nc in
      update nb
    with
    | Not_found ->
      nc, []

  let query nc ~now ~reachable_time ip =
    try
      let nb = IpMap.find ip nc in
      match nb.state with
      | INCOMPLETE _ ->
        nc, None, []
      | REACHABLE (_, dmac) | DELAY (_, dmac) | PROBE (_, _, dmac) ->
        nc, Some dmac, []
      | STALE dmac ->
        let dt = Defaults.delay_first_probe_time in
        let nc = IpMap.add ip {nb with state = DELAY (now +. dt, dmac)} nc in
        nc, Some dmac, [Action.Sleep dt]
    with
    | Not_found ->
      let nb  = {state = INCOMPLETE (now +. reachable_time, 0); is_router = false} in
      let nc  = IpMap.add ip nb nc in
      let dst = Ipaddr.Prefix.network_address solicited_node_prefix ip in
      nc, None, [Action.SendNS (Action.Specified, dst, ip); Action.Sleep reachable_time]

  let reachable nc ip =
    try
      let nb = IpMap.find ip nc in
      match nb.state with
      | INCOMPLETE _ -> false
      | _ -> true
    with
    | Not_found -> false
end

module RouterList = struct

  type t =
    (Ipaddr.t * float) list

  let empty =
    []

  let to_list rl =
    List.map fst rl

  let add rl ~now ?(lifetime = max_float) ip =
    (* FIXME *)
    (ip, now +. lifetime) :: rl

  let expired rl ~now =
    List.exists (fun (_, t) -> t <= now) rl

  (* FIXME if we are keeping a destination cache, we must remove the stale routers from there as well. *)
  let tick rl ~now =
    List.filter (fun (_, t) -> t > now) rl

  let handle_ra rl ~now ~src ~lft =
    match List.mem_assoc src rl with
    | true ->
      let rl = List.remove_assoc src rl in
      if lft > 0.0 then begin
        Printf.printf "RA: Refreshing Router: src=%s lft=%f\n%!" (Ipaddr.to_string src) lft;
        (src, now +. lft) :: rl, [Action.Sleep lft]
      end else begin
        Printf.printf "RA: Router Expired: src=%s\n%!" (Ipaddr.to_string src);
        rl, []
      end
    | false ->
      if lft > 0.0 then begin
        Printf.printf "RA: Adding Router: src=%s\n%!" (Ipaddr.to_string src);
        (src, now +. lft) :: rl, [Action.Sleep lft]
      end else
        rl, []

  let add rl ~now ip =
    match List.mem_assoc ip rl with
    | true -> rl
    | false -> (ip, max_float) :: rl

  let select rl reachable ip =
    let rec loop = function
      | [] ->
        begin match rl with
          | [] -> ip, rl
          | (ip, _) as r :: rest ->
            ip, rest @ [r]
        end
      | (ip, _) :: _ when reachable ip -> ip, rl
      | _ :: rest -> loop rest
    in
    loop rl
end
