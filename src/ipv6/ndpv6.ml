(*
 * Copyright (c) 2015 Nicolas Ojeda Bar <n.oje.bar@gmail.com>
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
References:

- Transmission of IPv6 packets over Ethernet networks
  http://tools.ietf.org/html/rfc2464

- IPv6 Stateless Address Autoconfiguration
  https://tools.ietf.org/html/rfc2462

- Neighbor Discovery for IP Version 6 (IPv6)
  https://tools.ietf.org/html/rfc2461

- Internet Control Message Protocol (ICMPv6)
  http://tools.ietf.org/html/rfc2463

- IPv6 Node Requirements
  http://tools.ietf.org/html/rfc6434

- Multicast Listener Discovery Version 2 (MLDv2) for IPv6
  http://tools.ietf.org/html/rfc3810
*)

let src = Logs.Src.create "ndpc6" ~doc:"Mirage IPv6 discovery"
module Log = (val Logs.src_log src : Logs.LOG)

module Ipaddr = Ipaddr.V6

type buffer = Cstruct.t
type ipaddr = Ipaddr.t
type prefix = Ipaddr.Prefix.t
type time   = int64

module BoundedMap (K : Map.OrderedType) : sig
  type 'a t
  val empty: int -> 'a t
  val push: K.t -> 'a -> 'a t -> 'a t
  val pop: K.t -> 'a t -> 'a list * 'a t
end = struct
  module M = Map.Make (K)
  type 'a t = 'a list M.t * int
  let empty n = (M.empty, n)
  let push k d (m, n) =
    let l = try M.find k m with Not_found -> [] in
    match l, List.length l >= n with
    | _, false ->
      M.add k (l @ [d]) m, n
    | _ :: l, true ->
      M.add k (d :: l) m, n
    | [], true ->
      m, n
  let pop k (m, n) =
    let l = try M.find k m with Not_found -> [] in
    l, (M.remove k m, n)
end

module PacketQueue = BoundedMap (Ipaddr)

let solicited_node_prefix =
  Ipaddr.(Prefix.make 104 (of_int16 (0xff02, 0, 0, 0, 0, 1, 0xff00, 0)))

module Defaults = struct
  let _max_rtr_solicitation_delay = Duration.of_sec 1
  let _ptr_solicitation_interval  = 4
  let _max_rtr_solicitations      = 3
  let max_multicast_solicit      = 3
  let max_unicast_solicit        = 3
  let _max_anycast_delay_time     = 1
  let _max_neighbor_advertisement = 3
  let delay_first_probe_time     = Duration.of_sec 5

  let link_mtu                   = 1500 (* RFC 2464, 2. *)
  let min_link_mtu               = 1280

  let dup_addr_detect_transmits  = 1

  let min_random_factor          = 0.5
  let max_random_factor          = 1.5
  let reachable_time             = Duration.of_sec 30
  let retrans_timer              = Duration.of_sec 1
end

let ipaddr_of_cstruct cs =
  let hihi = Cstruct.BE.get_uint32 cs 0 in
  let hilo = Cstruct.BE.get_uint32 cs 4 in
  let lohi = Cstruct.BE.get_uint32 cs 8 in
  let lolo = Cstruct.BE.get_uint32 cs 12 in
  Ipaddr.of_int32 (hihi, hilo, lohi, lolo)

let ipaddr_to_cstruct_raw i cs off =
  let a, b, c, d = Ipaddr.to_int32 i in
  Cstruct.BE.set_uint32 cs (0 + off) a;
  Cstruct.BE.set_uint32 cs (4 + off) b;
  Cstruct.BE.set_uint32 cs (8 + off) c;
  Cstruct.BE.set_uint32 cs (12 + off) d

let macaddr_to_cstruct_raw x cs off =
  Cstruct.blit_from_string (Macaddr.to_bytes x) 0 cs off 6

let macaddr_of_cstruct cs =
  if Cstruct.len cs <> 6 then invalid_arg "macaddr_of_cstruct";
  match Macaddr.of_bytes (Cstruct.to_string cs) with
  | Some x -> x
  | None -> assert false

let interface_addr mac =
  let bmac = Macaddr.to_bytes mac in
  let c i = Char.code (String.get bmac i) in
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

(* vary the reachable time by some random factor between 0.5 and 1.5 *)
let compute_reachable_time r reachable_time =
  let factor =
    Defaults.min_random_factor +.
    Randomconv.float ~bound:Defaults.(max_random_factor -. min_random_factor) r
  in
  Int64.of_float (factor *. Int64.to_float reachable_time)

let cksum_buf =
  let pbuf = Io_page.to_cstruct (Io_page.get 1) in
  Cstruct.set_len pbuf 8

let checksum' ~proto frame bufs =
  Cstruct.BE.set_uint32 cksum_buf 0 (Int32.of_int (Cstruct.lenv bufs));
  Cstruct.BE.set_uint32 cksum_buf 4 (Int32.of_int proto);
  let src_dst = Cstruct.sub frame 8 (2 * 16) in
  Tcpip_checksum.ones_complement_list (src_dst :: cksum_buf :: bufs)

let checksum frame bufs =
  let frame = Cstruct.shift frame Ethif_wire.sizeof_ethernet in
  let proto = Ipv6_wire.get_ipv6_nhdr frame in
  checksum' ~proto frame bufs

module Allocate = struct
  let frame ~mac ~hlim ~src ~dst ~proto =
    let ethernet_frame = Io_page.to_cstruct (Io_page.get 1) in
    let ipbuf = Cstruct.shift ethernet_frame Ethif_wire.sizeof_ethernet in
    macaddr_to_cstruct_raw mac (Ethif_wire.get_ethernet_src ethernet_frame) 0;
    Ethif_wire.set_ethernet_ethertype ethernet_frame 0x86dd; (* IPv6 *)
    Ipv6_wire.set_ipv6_version_flow ipbuf 0x60000000l; (* IPv6 *)
    ipaddr_to_cstruct_raw src (Ipv6_wire.get_ipv6_src ipbuf) 0;
    ipaddr_to_cstruct_raw dst (Ipv6_wire.get_ipv6_dst ipbuf) 0;
    Ipv6_wire.set_ipv6_hlim ipbuf hlim;
    Ipv6_wire.set_ipv6_nhdr ipbuf proto;
    let header_len = Ethif_wire.sizeof_ethernet + Ipv6_wire.sizeof_ipv6 in
    (ethernet_frame, header_len)

  let _error ~mac ~src ~dst ~ty ~code ?(reserved = 0l) buf =
    let eth_frame, header_len = frame ~mac ~src ~dst ~hlim:255 ~proto:58 in
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
    let eth_frame, header_len = frame ~mac ~src ~dst ~hlim:255 ~proto:58 in
    let eth_frame = Cstruct.set_len eth_frame (header_len + Ipv6_wire.sizeof_ns + Ipv6_wire.sizeof_llopt) in
    let icmpbuf = Cstruct.shift eth_frame header_len in
    let optbuf  = Cstruct.shift icmpbuf Ipv6_wire.sizeof_ns in
    Ipv6_wire.set_ns_ty icmpbuf 135; (* NS *)
    Ipv6_wire.set_ns_code icmpbuf 0;
    Ipv6_wire.set_ns_reserved icmpbuf 0l;
    ipaddr_to_cstruct_raw tgt (Ipv6_wire.get_ns_target icmpbuf) 0;
    Ipv6_wire.set_llopt_ty optbuf  1;
    Ipv6_wire.set_llopt_len optbuf  1;
    macaddr_to_cstruct_raw mac optbuf 2;
    Ipv6_wire.set_icmpv6_csum icmpbuf 0;
    Ipv6_wire.set_icmpv6_csum icmpbuf @@ checksum eth_frame [ icmpbuf ];
    eth_frame

  let na ~mac ~src ~dst ~tgt ~sol =
    let eth_frame, header_len = frame ~mac ~src ~dst ~hlim:255 ~proto:58 in
    let eth_frame = Cstruct.set_len eth_frame (header_len + Ipv6_wire.sizeof_na + Ipv6_wire.sizeof_llopt) in
    let icmpbuf = Cstruct.shift eth_frame header_len in
    let optbuf  = Cstruct.shift icmpbuf Ipv6_wire.sizeof_na in
    Ipv6_wire.set_na_ty icmpbuf 136; (* NA *)
    Ipv6_wire.set_na_code icmpbuf 0;
    Ipv6_wire.set_na_reserved icmpbuf (if sol then 0x60000000l else 0x20000000l);
    ipaddr_to_cstruct_raw tgt (Ipv6_wire.get_na_target icmpbuf) 0;
    Ipv6_wire.set_llopt_ty optbuf 2;
    Ipv6_wire.set_llopt_len optbuf 1;
    macaddr_to_cstruct_raw mac optbuf 2;
    Ipv6_wire.set_icmpv6_csum icmpbuf 0;
    Ipv6_wire.set_icmpv6_csum icmpbuf @@ checksum eth_frame [ icmpbuf ];
    eth_frame

  let rs ~mac select_source =
    let dst = Ipaddr.link_routers in
    let src = select_source ~dst in
    let cmp = Ipaddr.compare in
    let eth_frame, header_len = frame ~mac ~src ~dst ~hlim:255 ~proto:58 in
    let include_slla = (cmp src Ipaddr.unspecified) != 0 in
    let slla_len = if include_slla then Ipv6_wire.sizeof_llopt else 0 in
    let eth_frame =
      Cstruct.set_len eth_frame (header_len + Ipv6_wire.sizeof_rs + slla_len)
    in
    let icmpbuf = Cstruct.shift eth_frame header_len in
    Ipv6_wire.set_rs_ty icmpbuf 133;
    Ipv6_wire.set_rs_code icmpbuf 0;
    Ipv6_wire.set_rs_reserved icmpbuf 0l;
    if include_slla then begin
      let optbuf = Cstruct.shift icmpbuf Ipv6_wire.sizeof_rs in
      macaddr_to_cstruct_raw mac optbuf 2
    end;
    Ipv6_wire.set_icmpv6_csum icmpbuf 0;
    Ipv6_wire.set_icmpv6_csum icmpbuf @@ checksum eth_frame [ icmpbuf ];
    eth_frame

  let pong ~mac ~src ~dst ~hlim ~id ~seq ~data =
    let eth_frame, header_len = frame ~mac ~src ~dst ~hlim ~proto:58 in
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

type ns =
  { ns_target : Ipaddr.t;
    ns_slla : Macaddr.t option }

type pfx =
  { pfx_on_link : bool;
    pfx_autonomous : bool;
    pfx_valid_lifetime : time option;
    pfx_preferred_lifetime : time option;
    pfx_prefix : Ipaddr.Prefix.t }

type ra =
  { ra_cur_hop_limit : int;
    ra_router_lifetime : time;
    ra_reachable_time : time option;
    ra_retrans_timer : time option;
    ra_slla : Macaddr.t option;
    ra_prefix : pfx list }

type na =
  { na_router : bool;
    na_solicited : bool;
    na_override : bool;
    na_target : Ipaddr.t;
    na_tlla : Macaddr.t option }

type action =
  | SendNS of [`Unspecified | `Specified ] * ipaddr * ipaddr
  | SendNA of ipaddr * ipaddr * ipaddr * [`Solicited | `Unsolicited]
  | SendRS
  | SendQueued of ipaddr * Macaddr.t
  | CancelQueued of ipaddr

module AddressList = struct

  type state =
    | TENTATIVE of (time * time option) option * int * time
    | PREFERRED of (time * time option) option
    | DEPRECATED of time option

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
        let timeout = match timeout with
          | None -> None
          | Some (preferred_lifetime, valid_lifetime) ->
            Some (Int64.add now preferred_lifetime, valid_lifetime)
        in
        Log.debug (fun f -> f "SLAAC: %a --> PREFERRED" Ipaddr.pp_hum ip);
        Some (ip, PREFERRED timeout), []
      else
        let dst = Ipaddr.Prefix.network_address solicited_node_prefix ip in
        Some (ip, TENTATIVE (timeout, n+1, Int64.add now retrans_timer)),
        [SendNS (`Unspecified, dst, ip)]
    | ip, PREFERRED (Some (preferred_timeout, valid_lifetime)) when preferred_timeout <= now ->
      Log.debug (fun f -> f "SLAAC: %a --> DEPRECATED" Ipaddr.pp_hum ip);
      let valid_timeout = match valid_lifetime with
        | None -> None
        | Some valid_lifetime -> Some (Int64.add now valid_lifetime)
      in
      Some (ip, DEPRECATED valid_timeout), []
    | ip, DEPRECATED (Some t) when t <= now ->
      Log.debug (fun f -> f "SLAAC: %a --> EXPIRED" Ipaddr.pp_hum ip);
      None, []
    | addr ->
      Some addr, []

  let tick al ~now ~retrans_timer =
    List.fold_right (fun ip (ips, acts) ->
        let addr, acts' = tick_one ~now ~retrans_timer ip in
        let acts = acts' @ acts in
        let ips = match addr with Some ip -> ip :: ips | None -> ips in
        ips, acts
      ) al ([], [])

  let _expired al ~now =
    List.exists (function
        | _, TENTATIVE (_, _, t)
        | _, PREFERRED (Some (t, _))
        | _, DEPRECATED (Some t) -> t <= now
        | _ -> false
      ) al

  let add al ~now ~retrans_timer ~lft ip =
    match List.mem_assoc ip al with
    | false ->
      let al = (ip, TENTATIVE (lft, 0, Int64.add now retrans_timer)) :: al in
      let dst = Ipaddr.Prefix.network_address solicited_node_prefix ip in
      al, [SendNS (`Unspecified, dst, ip)]
    | true ->
      Log.warn (fun f -> f "ndpv6: attempted to add ip %a already in address list"
                   Ipaddr.pp_hum ip);
      al, []

  let is_my_addr al ip =
    List.exists (function
        | _, TENTATIVE _ -> false
        | ip', (PREFERRED _ | DEPRECATED _) -> Ipaddr.compare ip' ip = 0
      ) al

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
    | Some _addr ->
      (* TODO handle already configured SLAAC address 5.5.3 e). *)
      al, []
    | None ->
      let ip = Ipaddr.Prefix.network_address pfx (interface_addr mac) in
      add al ~now ~retrans_timer ~lft ip

  let handle_na al ip =
    (* FIXME How to notify the client? *)
    try
      match List.assoc ip al with
      | TENTATIVE _ ->
        Log.info (fun f -> f "DAD: Failed: %a" Ipaddr.pp_hum ip);
        List.remove_assoc ip al
      | _ ->
        al
    with
    | Not_found -> al
end

module PrefixList = struct

  type t =
    (Ipaddr.Prefix.t * time option) list

  let link_local =
    [Ipaddr.Prefix.link, None]

  let to_list pl =
    List.map fst pl

  let is_local pl ip =
    List.exists (fun (pfx, _) -> Ipaddr.Prefix.mem ip pfx) pl

  let tick pl ~now =
    List.filter (function (_, Some t) -> t > now | (_, None) -> true) pl

  let add pl ~now pfx ~vlft =
    let vlft = match vlft with
      | None -> None
      | Some dt -> Some (Int64.add now dt)
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

    Log.debug (fun f -> f "ND6: Processing PREFIX option in RA");
    if Ipaddr.Prefix.link <> pfx then
      match vlft, List.mem_assoc pfx pl with
      | Some 0L, true ->
        Log.debug (fun f -> f "ND6: Removing PREFIX: pfx=%a" Ipaddr.Prefix.pp_hum pfx);
        List.remove_assoc pfx pl, []
      | Some 0L, false ->
        pl, []
      | Some dt, true ->
        Log.debug (fun f -> f "ND6: Refreshing PREFIX: pfx=%a lft=%Lu" Ipaddr.Prefix.pp_hum pfx dt);
        let pl = List.remove_assoc pfx pl in
        (pfx, Some (Int64.add now dt)) :: pl, []
      | Some dt, false ->
        Log.debug (fun f -> f "ND6: Received new PREFIX: pfx=%a lft=%Lu" Ipaddr.Prefix.pp_hum pfx dt);
        (pfx, Some (Int64.add now dt)) :: pl, []
      | None, true ->
        Log.debug (fun f -> f "ND6: Refreshing PREFIX: pfx=%a lft=inf" Ipaddr.Prefix.pp_hum pfx);
        let pl = List.remove_assoc pfx pl in
        (pfx, None) :: pl, []
      | None, false ->
        Log.debug (fun f -> f "ND6: Received new PREFIX: pfx=%a lft=inf" Ipaddr.Prefix.pp_hum pfx);
        (pfx, None) :: pl, []
    else
      pl, []
end

module NeighborCache = struct

  type state =
    | INCOMPLETE of time * int
    | REACHABLE of time * Macaddr.t
    | STALE of Macaddr.t
    | DELAY of time * Macaddr.t
    | PROBE of time * int * Macaddr.t

  type info =
    { state : state;
      is_router : bool }

  module IpMap = Map.Make (Ipaddr)

  type t =
    info IpMap.t

  let empty =
    IpMap.empty

  let tick_one ~now ~retrans_timer ip nb nc =
    match nb.state with
    | INCOMPLETE (t, tn) when t <= now ->
      if tn < Defaults.max_multicast_solicit then begin
        Log.info (fun f -> f "NUD: %a --> INCOMPLETE [Timeout]" Ipaddr.pp_hum ip);
        let dst = Ipaddr.Prefix.network_address solicited_node_prefix ip in
        IpMap.add ip {nb with state = INCOMPLETE ((Int64.add now retrans_timer), tn+1)} nc,
        [SendNS (`Specified, dst, ip)]
      end else begin
        Log.info (fun f -> f "NUD: %a --> UNREACHABLE [Discarding]" Ipaddr.pp_hum ip);
        (* TODO Generate ICMP error: Destination Unreachable *)
        IpMap.remove ip nc, [CancelQueued ip]
      end
    | REACHABLE (t, mac) when t <= now ->
      Log.info (fun f -> f "NUD: %a --> STALE" Ipaddr.pp_hum ip);
      IpMap.add ip {nb with state = STALE mac} nc, []
    | DELAY (t, dmac) when t <= now ->
      Log.info (fun f -> f "NUD: %a --> PROBE" Ipaddr.pp_hum ip);
      IpMap.add ip {nb with state = PROBE ((Int64.add now retrans_timer), 0, dmac)} nc,
      [SendNS (`Specified, ip, ip)]
    | PROBE (t, tn, dmac) when t <= now ->
      if tn < Defaults.max_unicast_solicit then begin
        Log.info (fun f -> f "NUD: %a --> PROBE [Timeout]" Ipaddr.pp_hum ip);
        IpMap.add ip {nb with state = PROBE ((Int64.add now retrans_timer), tn+1, dmac)} nc,
        [SendNS (`Specified, ip, ip)]
      end else begin
        Log.info (fun f -> f "NUD: %a --> UNREACHABLE [Discarding]" Ipaddr.pp_hum ip);
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
        nb, [SendQueued (src, new_mac)]
      | REACHABLE (_, mac) | STALE mac | DELAY (_, mac) | PROBE (_, _, mac) ->
        let nb = if mac <> new_mac then {nb with state = STALE new_mac} else nb in
        nb, []
    in
    IpMap.add src nb nc, acts

  let handle_ra nc ~src new_mac =
    Log.info (fun f -> f "ND6: Processing SLLA option in RA");
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
      IpMap.add src nb nc, [SendQueued (src, new_mac)]
    | REACHABLE (_, mac) | STALE mac | DELAY (_, mac) | PROBE (_, _, mac) ->
      let nb = if mac <> new_mac then {nb with state = STALE new_mac} else nb in
      IpMap.add src nb nc, []

  let handle_na nc ~now ~reachable_time ~rtr ~sol ~ovr ~tgt ~lladdr =
    let new_mac = lladdr in

    let update nb =
      match nb.state, new_mac, sol, ovr with
      | INCOMPLETE _, Some new_mac, false, _ ->
        Log.info (fun f -> f "NUD: %a --> STALE" Ipaddr.pp_hum tgt);
        let nb = {nb with state = STALE new_mac} in
        IpMap.add tgt nb nc, [SendQueued (tgt, new_mac)]
      | INCOMPLETE _, Some new_mac, true, _ ->
        Log.info (fun f -> f "NUD: %a --> REACHABLE" Ipaddr.pp_hum tgt);
        let nb = {nb with state = REACHABLE ((Int64.add now reachable_time), new_mac)} in
        IpMap.add tgt nb nc, [SendQueued (tgt, new_mac)]
      | INCOMPLETE _, None, _, _ ->
        let nc =
          if nb.is_router != rtr then
            IpMap.add tgt {nb with is_router = rtr} nc
          else
            nc
        in
        nc, []
      | PROBE (_, _, mac), Some new_mac, true, false when mac = new_mac ->
        Log.info (fun f -> f "NUD: %a --> REACHABLE" Ipaddr.pp_hum tgt);
        let nb = {nb with state = REACHABLE ((Int64.add now reachable_time), new_mac)} in
        IpMap.add tgt nb nc, []
      | PROBE (_, _, mac), None, true, false ->
        Log.info (fun f -> f "NUD: %a --> REACHABLE" Ipaddr.pp_hum tgt);
        let nb = {nb with state = REACHABLE ((Int64.add now reachable_time), mac)} in
        IpMap.add tgt nb nc, []
      | (REACHABLE _ | STALE _ | DELAY _ | PROBE _), None, _, _ ->
        let nc =
          if nb.is_router != rtr then
            IpMap.add tgt {nb with is_router = rtr} nc
          else
            nc
        in
        nc, []
      | REACHABLE (_, mac), Some new_mac, true, false when mac <> new_mac ->
        Log.info (fun f -> f "NUD: %a --> STALE" Ipaddr.pp_hum tgt);
        let nb = {nb with state = STALE mac} in (* TODO check mac or new_mac *)
        IpMap.add tgt nb nc, []
      | (REACHABLE _ | STALE _ | DELAY _ | PROBE _), Some new_mac, true, true ->
        Log.info (fun f -> f "NUD: %a --> REACHABLE" Ipaddr.pp_hum tgt);
        let nb = {nb with state = REACHABLE ((Int64.add now reachable_time), new_mac)} in
        IpMap.add tgt nb nc, []
      | (REACHABLE (_, mac) | STALE mac | DELAY (_, mac) | PROBE (_, _, mac)),
        Some new_mac, false, true when mac <> new_mac ->
        Log.info (fun f -> f "NUD: %a --> STALE" Ipaddr.pp_hum tgt);
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
        let nc = IpMap.add ip {nb with state = DELAY (Int64.add now dt, dmac)} nc in
        nc, Some dmac, []
    with
    | Not_found ->
      let nb  = {state = INCOMPLETE (Int64.add now reachable_time, 0); is_router = false} in
      let nc  = IpMap.add ip nb nc in
      let dst = Ipaddr.Prefix.network_address solicited_node_prefix ip in
      nc, None, [SendNS (`Specified, dst, ip)]

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
    (Ipaddr.t * time) list

  let empty =
    []

  let to_list rl =
    List.map fst rl

  let add rl ~now ?(lifetime = Duration.of_year 1) ip =
    (* FIXME *)
    (* yomimono 2016-06-30: fix what? *)
    (* yomimono 2016-08-17: maybe fix this default lifetime. *)
    (ip, Int64.add now lifetime) :: rl

  (* FIXME if we are keeping a destination cache, we must remove the stale routers from there as well. *)
  let tick rl ~now =
    List.filter (fun (_, t) -> t > now) rl

  let handle_ra rl ~now ~src ~lft =
    match List.mem_assoc src rl with
    | true ->
      let rl = List.remove_assoc src rl in
      if lft > 0L then begin
        Log.info (fun f -> f "RA: Refreshing Router: src=%a lft=%Lu" Ipaddr.pp_hum src lft);
        (src, Int64.add now lft) :: rl, []
      end else begin
        Log.info (fun f -> f "RA: Router Expired: src=%a" Ipaddr.pp_hum src);
        rl, []
      end
    | false ->
      if lft > 0L then begin
	Log.info (fun f -> f "RA: Adding Router: src=%a" Ipaddr.pp_hum src);
        (add rl ~now ~lifetime:lft src), []
      end else
        rl, []

  let add rl ~now:_ ip =
    match List.mem_assoc ip rl with
    | true -> rl
    | false -> (ip, Duration.of_year 1) :: rl

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

module Parser = struct
  type packet =
    | Drop
    | DropWithError of int * int * int
    | NA of Ipaddr.t * Ipaddr.t * na
    | NS of Ipaddr.t * Ipaddr.t * ns
    | RA of Ipaddr.t * Ipaddr.t * ra
    | Ping of Ipaddr.t * Ipaddr.t * int * int * Cstruct.t
    | Pong of Cstruct.t
    | Udp of Ipaddr.t * Ipaddr.t * Cstruct.t
    | Tcp of Ipaddr.t * Ipaddr.t * Cstruct.t
    | Default of int * Ipaddr.t * Ipaddr.t * Cstruct.t

  type option =
    | SLLA of Macaddr.t
    | TLLA of Macaddr.t
    | MTU of int
    | PREFIX of pfx

  let rec parse_options1 opts =
    if Cstruct.len opts >= Ipv6_wire.sizeof_opt then
      (* TODO check for invalid len == 0 *)
      let opt, opts = Cstruct.split opts (Ipv6_wire.get_opt_len opts * 8) in
      match Ipv6_wire.get_opt_ty opt, Ipv6_wire.get_opt_len opt with
      | 1, 1 ->
        SLLA (macaddr_of_cstruct (Ipv6_wire.get_llopt_addr opt)) :: parse_options1 opts
      | 2, 1 ->
        TLLA (macaddr_of_cstruct (Ipv6_wire.get_llopt_addr opt)) :: parse_options1 opts
      | 5, 1 ->
        MTU (Int32.to_int (Cstruct.BE.get_uint32 opt 4)) :: parse_options1 opts
      | 3, 4 ->
        let pfx_prefix =
          Ipaddr.Prefix.make
            (Ipv6_wire.get_opt_prefix_prefix_len opt)
            (ipaddr_of_cstruct (Ipv6_wire.get_opt_prefix_prefix opt))
        in
        let pfx_on_link = Ipv6_wire.get_opt_prefix_on_link opt in
        let pfx_autonomous = Ipv6_wire.get_opt_prefix_autonomous opt in
        let pfx_valid_lifetime =
          let n = Ipv6_wire.get_opt_prefix_valid_lifetime opt in
          match n with
          | 0xffffffffl -> None
          | n -> Some (Int64.of_int32 n)
        in
        let pfx_preferred_lifetime =
          let n = Ipv6_wire.get_opt_prefix_preferred_lifetime opt in
          match n with
          | 0xffffffffl -> None
          | n -> Some (Int64.of_int32 n)
        in
        let pfx =
          {pfx_on_link; pfx_autonomous; pfx_valid_lifetime; pfx_preferred_lifetime; pfx_prefix}
        in
        PREFIX pfx :: parse_options1 opts
      | ty, len ->
        Log.info (fun f -> f "ND6: Unsupported ND option in RA: ty=%d len=%d" ty len);
        parse_options1 opts
    else
      []

  let parse_ra buf =
    let ra_cur_hop_limit = Ipv6_wire.get_ra_cur_hop_limit buf in
    let ra_router_lifetime =
      Int64.of_int (Ipv6_wire.get_ra_router_lifetime buf)
    in
    let ra_reachable_time =
      let n = Ipv6_wire.get_ra_reachable_time buf in
      if n = 0l then None
      else
        let dt = Int64.of_int32 @@ Int32.div n 1000l in
        Some dt
    in
    let ra_retrans_timer =
      let n = Ipv6_wire.get_ra_retrans_timer buf in
      if n = 0l then None
      else
        let dt = Int64.of_int32 @@ Int32.div n 1000l in
        Some dt
    in
    let opts = Cstruct.shift buf Ipv6_wire.sizeof_ra in
    let ra_slla, ra_prefix =
      let opts = parse_options1 opts in
      List.fold_left (fun ra opt ->
          match ra, opt with
          | (_, pfxs), SLLA slla -> Some slla, pfxs
          | (slla, pfxs), PREFIX pfx -> slla, (pfx :: pfxs)
          | _ -> ra
        ) (None, []) opts
    in
    {ra_cur_hop_limit; ra_router_lifetime; ra_reachable_time; ra_retrans_timer; ra_slla; ra_prefix}

  let parse_ns buf =
    (* FIXME check code = 0 or drop *)
    let ns_target = ipaddr_of_cstruct (Ipv6_wire.get_ns_target buf) in
    let opts = Cstruct.shift buf Ipv6_wire.sizeof_ns in
    let ns_slla =
      let opts = parse_options1 opts in
      List.fold_left (fun ns opt ->
          match opt with
          | SLLA slla -> Some slla
          | _ -> ns
        ) None opts
    in
    {ns_target; ns_slla}

  let parse_na buf =
    (* FIXME check code = 0 or drop *)
    let na_router = Ipv6_wire.get_na_router buf in
    let na_solicited = Ipv6_wire.get_na_solicited buf in
    let na_override = Ipv6_wire.get_na_override buf in
    let na_target = ipaddr_of_cstruct (Ipv6_wire.get_na_target buf) in
    let na_tlla =
      let opts = Cstruct.shift buf Ipv6_wire.sizeof_na in
      let opts = parse_options1 opts in
      List.fold_left (fun na opt ->
          match opt with
          | TLLA tlla -> Some tlla
          | _ -> na
        ) None opts
    in
    {na_router; na_solicited; na_override; na_target; na_tlla}

  let dst_unreachable icmpbuf =
    match Ipv6_wire.get_icmpv6_code icmpbuf with
    | 0 -> "No route to destination"
    | 1 -> "Communication with destination administratively prohibited"
    | 2 -> "Beyond scope of source address"
    | 3 -> "Address unreachable"
    | 4 -> "Port unreachable"
    | 5 -> "Source address failed ingress/egress policy"
    | 6 -> "Reject route to destination"
    | 7 -> "Error in Source Routing Header"
    | c -> "Unknown code: " ^ string_of_int c

  let time_exceeded icmpbuf =
    match Ipv6_wire.get_icmpv6_code icmpbuf with
    | 0 -> "Hop limit exceeded in transit"
    | 1 -> "Fragment reassembly time exceeded"
    | c -> "Unknown code: " ^ string_of_int c

  let parameter_problem icmpbuf =
    match Ipv6_wire.get_icmpv6_code icmpbuf with
    | 0 -> "Erroneous header field encountered"
    | 1 -> "Unrecognized Next Header type encountered"
    | 2 -> "Unrocognized IPv6 option encountered"
    | c -> "Unknown code: " ^ string_of_int c

  (* buf : icmp packet with ipv6 header *)
  let parse_icmp ~src ~dst buf poff =
    let icmpbuf  = Cstruct.shift buf poff in
    let csum = checksum' ~proto:58 buf [ icmpbuf ] in
    if csum != 0 then begin
      Log.info (fun f -> f "ICMP6: Checksum error, dropping packet: csum=0x%x" csum);
      Drop
    end else begin
      match Ipv6_wire.get_icmpv6_ty icmpbuf with
      | 128 -> (* Echo request *)
        let id = Cstruct.BE.get_uint16 icmpbuf 4 in
        let seq = Cstruct.BE.get_uint16 icmpbuf 6 in
        Ping (src, dst, id, seq, Cstruct.shift icmpbuf 8)
      | 129 (* Echo reply *) ->
        Pong (Cstruct.shift buf poff)
      (* Log.info (fun f -> f "ICMP6: Discarding Echo Reply"; *)
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
          if Ipaddr.is_multicast ns.ns_target then
            Drop
          else
            NS (src, dst, ns)
      | 136 (* NA *) ->
        if Ipv6_wire.get_ipv6_hlim buf <> 255 then
          Drop
        else
          let na = parse_na icmpbuf in
          if Ipaddr.is_multicast na.na_target ||
             (na.na_solicited && Ipaddr.is_multicast dst) then
            Drop
          else
            NA (src, dst, na)
      | 1 ->
        Log.info (fun f -> f "ICMP6 Destination Unreachable: %s" (dst_unreachable icmpbuf));
        Drop
      | 2 ->
        Log.info (fun f -> f "ICMP6 Packet Too Big");
        Drop
      | 3 ->
        Log.info (fun f -> f "ICMP6 Time Exceeded: %s" (time_exceeded icmpbuf));
        Drop
      | 4 ->
        Log.info (fun f -> f "ICMP6 Parameter Problem: %s" (parameter_problem icmpbuf));
        Drop
      | n ->
        Log.info (fun f -> f "ICMP6: Unknown packet type: ty=%d" n);
        Drop
    end

  let rec parse_extension ~src ~dst buf first hdr (poff : int) =
    match hdr with
    | 0 (* HOPTOPT *) when first ->
      Log.info (fun f -> f "IP6: Processing HOPOPT header");
      parse_options ~src ~dst buf poff
    | 0 ->
      Drop
    | 60 (* IPv6-Opts *) ->
      Log.info (fun f -> f "IP6: Processing DESTOPT header");
      parse_options ~src ~dst buf poff
    | 43 (* IPv6-Route *)
    | 44 (* IPv6-Frag *)
    | 50 (* ESP *)
    | 51 (* AH *)
    | 135 (* Mobility Header *)
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

  and parse_options ~src ~dst buf poff =
    let pbuf = Cstruct.shift buf poff in
    let nhdr = Ipv6_wire.get_opt_ty pbuf in
    let olen = Ipv6_wire.get_opt_len pbuf * 8 + 8 in
    let oend = olen + poff in
    let rec loop ooff =
      if ooff < oend then begin
        let obuf = Cstruct.shift buf ooff in
        match Ipv6_wire.get_opt_ty obuf with
        | 0 ->
          Log.info (fun f -> f "IP6: Processing PAD1 option");
          loop (ooff+1)
        | 1 ->
          Log.info (fun f -> f "IP6: Processing PADN option");
          let len = Ipv6_wire.get_opt_len obuf in
          loop (ooff+len+2)
        | _ as n ->
          Log.info (fun f -> f "IP6: Processing unknown option, MSB %x" n);
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
      end else
        parse_extension ~src ~dst buf false nhdr oend
    in
    loop (poff+2)

  let packet is_my_addr buf =
    let src = ipaddr_of_cstruct (Ipv6_wire.get_ipv6_src buf) in
    let dst = ipaddr_of_cstruct (Ipv6_wire.get_ipv6_dst buf) in

    (* TODO check version = 6 *)

    (* Log.debug (fun f -> f "IPv6 packet received from %s to %s" *)
    (* Ipaddr.pp_hum src) Ipaddr.pp_hum dst); *)

    if Ipaddr.Prefix.(mem src multicast) then begin
      Log.debug (fun f -> f "IP6: Dropping packet, src is mcast");
      Drop
    end else
    if not (is_my_addr dst || Ipaddr.Prefix.(mem dst multicast)) then begin
      Log.debug (fun f -> f "IP6: Dropping packet, not for me");
      Drop
    end
    else
      parse_extension ~src ~dst buf true (Ipv6_wire.get_ipv6_nhdr buf) Ipv6_wire.sizeof_ipv6
end

type event =
  [ `Tcp of ipaddr * ipaddr * buffer
  | `Udp of ipaddr * ipaddr * buffer
  | `Default of int * ipaddr * ipaddr * buffer ]

(* TODO add destination cache *)
type context =
  { neighbor_cache : NeighborCache.t;
    prefix_list : PrefixList.t;
    router_list : RouterList.t;
    mac : Macaddr.t;
    address_list : AddressList.t;
    link_mtu : int;
    cur_hop_limit : int;
    base_reachable_time : time;
    reachable_time : time;
    retrans_timer : time;
    packet_queue : (Macaddr.t -> Cstruct.t list) PacketQueue.t }

let next_hop ctx ip =
  if PrefixList.is_local ctx.prefix_list ip then
    ctx, ip
  else
    let ip, router_list =
      RouterList.select ctx.router_list (NeighborCache.reachable ctx.neighbor_cache) ip
    in
    {ctx with router_list}, ip

let rec process_actions ~now ctx actions =
  let aux ctx = function
    | SendNS (unspec, dst, tgt) ->
      let src = match unspec with
        | `Unspecified -> Ipaddr.unspecified
        | `Specified -> AddressList.select_source ctx.address_list ~dst
      in
      Log.debug (fun f -> f "ND6: Sending NS src=%a dst=%a tgt=%a"
        Ipaddr.pp_hum src Ipaddr.pp_hum dst Ipaddr.pp_hum tgt);
      let frame = Allocate.ns ~mac:ctx.mac ~src ~dst ~tgt in
      send ~now ctx dst frame []
    | SendNA (src, dst, tgt, sol) ->
      let sol = match sol with `Solicited -> true | `Unsolicited -> false in
      Log.debug (fun f -> f "ND6: Sending NA: src=%a dst=%a tgt=%a sol=%B"
        Ipaddr.pp_hum src Ipaddr.pp_hum dst Ipaddr.pp_hum tgt sol);
      let frame = Allocate.na ~mac:ctx.mac ~src ~dst ~tgt ~sol in
      send ~now ctx dst frame []
    | SendRS ->
      Log.debug (fun f -> f "ND6: Sending RS");
      let frame = Allocate.rs ~mac:ctx.mac (AddressList.select_source ctx.address_list) in
      let dst = Ipaddr.link_routers in
      send ~now ctx dst frame []
    | SendQueued (ip, dmac) ->
      Log.debug (fun f -> f "IP6: Releasing queued packets: dst=%a mac=%s" Ipaddr.pp_hum ip (Macaddr.to_string dmac));
      let pkts, packet_queue = PacketQueue.pop ip ctx.packet_queue in
      let bufs = List.map (fun datav -> datav dmac) pkts in
      let ctx = {ctx with packet_queue} in
      ctx, bufs
    | CancelQueued ip ->
      Log.debug (fun f -> f "IP6: Cancelling packets: dst = %a" Ipaddr.pp_hum ip);
      let _, packet_queue = PacketQueue.pop ip ctx.packet_queue in
      let ctx = {ctx with packet_queue} in
      ctx, []
  in
  List.fold_left (fun (ctx, bufs) action ->
      let ctx, bufs' = aux ctx action in
      ctx, bufs @ bufs'
    ) (ctx, []) actions

and send ~now ctx dst frame datav =
  let datav dmac =
    Ipv6_wire.set_ipv6_len (Cstruct.shift frame Ethif_wire.sizeof_ethernet)
      (Cstruct.lenv datav + Cstruct.len frame - Ethif_wire.sizeof_ethernet - Ipv6_wire.sizeof_ipv6);
    macaddr_to_cstruct_raw dmac (Ethif_wire.get_ethernet_dst frame) 0;
    frame :: datav
  in
  match Ipaddr.is_multicast dst with
  | true ->
    ctx, [datav (multicast_mac dst)]
  | false ->
    let ctx, ip = next_hop ctx dst in
    let neighbor_cache, mac, actions =
      NeighborCache.query ctx.neighbor_cache ~now ~reachable_time:ctx.reachable_time ip in
    let ctx = {ctx with neighbor_cache} in
    match mac with
    | Some dmac ->
      Log.debug (fun f -> f "IP6: Sending packet: dst=%a mac=%s" Ipaddr.pp_hum dst (Macaddr.to_string dmac));
      let ctx, bufs = process_actions ~now ctx actions in
      ctx, datav dmac :: bufs
    | None ->
      Log.debug (fun f -> f "IP6: Queueing packet: dst=%a" Ipaddr.pp_hum dst);
      let packet_queue = PacketQueue.push ip datav ctx.packet_queue in
      let ctx = {ctx with packet_queue} in
      process_actions ~now ctx actions

let local ~now ~random mac =
  let ctx =
    { neighbor_cache = NeighborCache.empty;
      prefix_list = PrefixList.link_local;
      router_list = RouterList.empty;
      mac = mac;
      address_list = AddressList.empty;
      link_mtu = Defaults.link_mtu;
      cur_hop_limit = 64; (* TODO *)
      base_reachable_time  = Defaults.reachable_time;
      reachable_time = compute_reachable_time random Defaults.reachable_time;
      retrans_timer = Defaults.retrans_timer;
      packet_queue = PacketQueue.empty 3 }
  in
  let ip = link_local_addr mac in
  let address_list, actions =
    AddressList.add ctx.address_list ~now ~retrans_timer:ctx.retrans_timer ~lft:None ip
  in
  let ctx, actions = {ctx with address_list}, SendRS :: actions in
  process_actions ~now ctx actions

let add_ip ~now ctx ip =
  let address_list, actions =
    AddressList.add ctx.address_list ~now ~retrans_timer:ctx.retrans_timer ~lft:None ip
  in
  let ctx = {ctx with address_list} in
  process_actions ~now ctx actions

let get_ip ctx =
  AddressList.to_list ctx.address_list

let allocate_frame ctx dst proto =
  let proto = Ipv6_wire.protocol_to_int proto in
  let src = AddressList.select_source ctx.address_list ~dst in
  Allocate.frame ~mac:ctx.mac ~src ~hlim:ctx.cur_hop_limit ~dst ~proto

let select_source ctx dst =
  AddressList.select_source ctx.address_list ~dst

let handle_ra ~now ~random ctx ~src ~dst ra =
  Log.debug (fun f -> f "ND: Received RA: src=%a dst=%a" Ipaddr.pp_hum src Ipaddr.pp_hum dst);
  let ctx =
    if ra.ra_cur_hop_limit <> 0 then
      {ctx with cur_hop_limit = ra.ra_cur_hop_limit}
    else ctx
  in
  let ctx = match ra.ra_reachable_time with
    | None -> ctx
    | Some rt ->
      if ctx.base_reachable_time <> rt then
        {ctx with base_reachable_time = rt;
                  reachable_time = compute_reachable_time random rt}
      else
        ctx
  in
  let ctx = match ra.ra_retrans_timer with
    | None -> ctx
    | Some rt ->
      {ctx with retrans_timer = rt}
  in
  let ctx, actions =
    match ra.ra_slla with
    | Some new_mac ->
      let neighbor_cache, actions = NeighborCache.handle_ra ctx.neighbor_cache ~src new_mac in
      {ctx with neighbor_cache}, actions
    | None ->
      ctx, []
  in
  let ctx, actions' =
    List.fold_left
      (fun (state, _) pfx ->
         let vlft = pfx.pfx_valid_lifetime in
         let prefix_list, acts = PrefixList.handle_ra state.prefix_list ~now ~vlft pfx.pfx_prefix in
         match pfx.pfx_autonomous, vlft with
         | _, Some 0L ->
           {state with prefix_list}, acts
         | true, Some _ ->
           let plft = pfx.pfx_preferred_lifetime in
           let lft = match plft with
             | None -> None
             | Some plft -> Some (plft, vlft)
           in
           let address_list, acts' = (* FIXME *)
             AddressList.configure state.address_list ~now ~retrans_timer:state.retrans_timer
               ~lft state.mac pfx.pfx_prefix
           in
           {state with address_list; prefix_list}, acts @ acts'
         | _ ->
           {state with prefix_list}, acts) (ctx, actions) ra.ra_prefix
  in
  let router_list, actions'' =
    RouterList.handle_ra ctx.router_list ~now ~src ~lft:ra.ra_router_lifetime
  in
  let actions = actions @ actions' @ actions'' in
  {ctx with router_list}, actions

let handle_ns ~now:_ ctx ~src ~dst ns =
  Log.debug (fun f -> f "ND: Received NS: src=%a dst=%a tgt=%a"
    Ipaddr.pp_hum src Ipaddr.pp_hum dst Ipaddr.pp_hum ns.ns_target);
  (* TODO check hlim = 255, target not mcast, code = 0 *)
  let ctx, actions = match ns.ns_slla with
    | Some new_mac ->
      let neighbor_cache, actions = NeighborCache.handle_ns ctx.neighbor_cache ~src new_mac in
      {ctx with neighbor_cache}, actions
      (* handle_ns_slla ~state ~src new_mac *)
    | None ->
      ctx, []
  in
  if AddressList.is_my_addr ctx.address_list ns.ns_target then
    let src = ns.ns_target and dst = src in
(*     (\* Log.debug (fun f -> f "Sending NA to %a from %a with target address %a" *\) *)
(*       (\* Ipaddr.pp_hum dst Ipaddr.pp_hum src Ipaddr.pp_hum target); *\) *)
    ctx, SendNA (src, dst, ns.ns_target, `Solicited) :: actions
  else
    ctx, actions

let handle_na ~now ctx ~src ~dst na =
  Log.debug (fun f -> f "ND: Received NA: src=%a dst=%a tgt=%a"
    Ipaddr.pp_hum src Ipaddr.pp_hum dst Ipaddr.pp_hum na.na_target);

  (* TODO Handle case when na.target is one of my bound IPs. *)

  (* If my_ip is TENTATIVE then fail DAD. *)
  let address_list = AddressList.handle_na ctx.address_list na.na_target in
  let neighbor_cache, actions =
    NeighborCache.handle_na ctx.neighbor_cache
      ~now ~reachable_time:ctx.reachable_time
      ~rtr:na.na_router ~sol:na.na_solicited ~ovr:na.na_override ~tgt:na.na_target
      ~lladdr:na.na_tlla
  in
  let ctx = {ctx with neighbor_cache; address_list} in
  ctx, actions

let handle ~now ~random ctx buf =
  let open Parser in
  match packet (AddressList.is_my_addr ctx.address_list) buf with
  | RA (src, dst, ra) ->
    let ctx, actions = handle_ra ~now ~random ctx ~src ~dst ra in
    let ctx, bufs = process_actions ~now ctx actions in
    ctx, bufs, []
  | NS (src, dst, ns) ->
    let ctx, actions = handle_ns ~now ctx ~src ~dst ns in
    let ctx, bufs = process_actions ~now ctx actions in
    ctx, bufs, []
  | NA (src, dst, na) ->
    let ctx, actions = handle_na ~now ctx ~src ~dst na in
    let ctx, bufs = process_actions ~now ctx actions in
    ctx, bufs, []
  | Ping (src, dst, id, seq, data) ->
    Log.info (fun f -> f "ICMP6: Received PING: src=%a dst=%a id=%d seq=%d" Ipaddr.pp_hum src
      Ipaddr.pp_hum dst id seq);
    let dst = src
    and src =
      if Ipaddr.is_multicast dst then
        AddressList.select_source ctx.address_list ~dst
      else
        dst
    in
    let frame, bufs =
      Allocate.pong ~mac:ctx.mac ~src ~dst ~hlim:ctx.cur_hop_limit ~id ~seq ~data
    in
    let ctx, bufs = send ~now ctx dst frame bufs in
    ctx, bufs, []
  | DropWithError _ (* TODO *) | Drop ->
    ctx, [], []
  | Pong _ ->
    ctx, [], []
  | Tcp (src, dst, buf) ->
    ctx, [], [`Tcp (src, dst, buf)]
  | Udp (src, dst, buf) ->
    ctx, [], [`Udp (src, dst, buf)]
  | Default (proto, src, dst, buf) ->
    ctx, [], [`Default (proto, src, dst, buf)]

let tick ~now ctx =
  let retrans_timer = ctx.retrans_timer in
  let address_list, actions = AddressList.tick ctx.address_list ~now ~retrans_timer in
  let prefix_list = PrefixList.tick ctx.prefix_list ~now in
  let neighbor_cache, actions' = NeighborCache.tick ctx.neighbor_cache ~now ~retrans_timer in
  let router_list = RouterList.tick ctx.router_list ~now in
  let ctx = {ctx with address_list; prefix_list; neighbor_cache; router_list} in
  let actions = actions @ actions' in
  process_actions ~now ctx actions

let add_prefix ~now ctx pfx =
  let prefix_list = PrefixList.add ctx.prefix_list ~now pfx ~vlft:None in
  {ctx with prefix_list}

let get_prefix ctx =
  PrefixList.to_list ctx.prefix_list

let add_routers ~now ctx ips =
  let router_list = List.fold_left (RouterList.add ~now) ctx.router_list ips in
  {ctx with router_list}

let get_routers ctx =
  RouterList.to_list ctx.router_list
