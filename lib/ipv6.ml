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
end

module Ipv6_wire = Wire_structs.Ipv6_wire

module Time : sig
  type t
  module Span : sig
    type t
    val of_float : float -> t
    val to_float : t -> float
  end
  val of_float : float -> t
  val to_float : t -> float
  val add : t -> Span.t -> t
end = struct
  type t = float
  module Span = struct
    type t = float
    let of_float dt = dt
    let to_float dt = dt
  end
  let of_float t = t
  let to_float t = t
  let add t dt = t +. dt
end

module Defaults = struct
  let max_rtr_solicitation_delay = 1.0
  let ptr_solicitation_interval  = 4
  let max_rtr_solicitations      = 3
  let max_multicast_solicit      = 3
  let max_unicast_solicit        = 3
  let max_anycast_delay_time     = 1
  let max_neighbor_advertisement = 3
  let reachable_time             = Time.Span.of_float 30.0
  let retrans_timer              = Time.Span.of_float 1.0
  let delay_first_probe_time     = 5
  let min_random_factor          = 0.5
  let max_random_factor          = 1.5

  let link_mtu                   = 1500 (* RFC 2464, 2. *)
  let min_link_mtu               = 1280

  let dup_addr_detect_transmits  = 1
end

module Engine = struct
  module IpMap     = Map.Make (Ipaddr.V6)
  module PrefixMap = Map.Make (Ipaddr.V6.Prefix)

  type nd_state =
    | INCOMPLETE of Time.t * int * (Macaddr.t -> Cstruct.t list) option
    | REACHABLE  of Time.t * Macaddr.t
    | STALE      of Macaddr.t
    | DELAY      of Time.t * Macaddr.t
    | PROBE      of Time.t * int * Macaddr.t

  type nb_info =
    { mutable state               : nd_state;
      mutable is_router           : bool }

  type addr_state =
    | TENTATIVE  of (Time.Span.t * Time.Span.t option) option * int * Time.t
    | PREFERRED  of (Time.t * Time.Span.t option) option
    | DEPRECATED of Time.t option

  (* TODO add destination cache *)
  type state =
    { nb_cache                    : (Ipaddr.V6.t, nb_info) Hashtbl.t;
      mutable prefix_list         : (Ipaddr.V6.Prefix.t * Time.t option) list;
      mutable rt_list             : (Ipaddr.V6.t * Time.t) list; (* invalidation timer *)
      mac                         : Macaddr.t;
      mutable my_ips              : (Ipaddr.V6.t * addr_state) list;
      mutable link_mtu            : int;
      mutable cur_hop_limit       : int;
      mutable base_reachable_time : Time.Span.t;
      mutable reachable_time      : Time.Span.t;
      mutable retrans_timer       : Time.Span.t }

  exception No_route_to_host of Ipaddr.V6.t

  type proto =
    | TCP
    | UDP
    | Other of int

  (* This will have to be moved somewhere else later, since the same computation
     is needed for UDP, TCP, ICMP, etc. over IPv6. Also, [Tcpip_checksum] is a
     bad name since it is used for other protocols as well. *)
  let pbuf =
    Cstruct.create Ipv6_wire.sizeof_ipv6_pseudo_header

  let cksum ~src ~dst ~proto data =
    Ipaddr.V6.to_cstruct_raw src pbuf 0;
    Ipaddr.V6.to_cstruct_raw dst pbuf 16;
    Cstruct.BE.set_uint32 pbuf 32 (Int32.of_int (Cstruct.lenv data));
    Cstruct.BE.set_uint32 pbuf 36 (Int32.of_int proto);
    Tcpip_checksum.ones_complement_list (pbuf :: data)

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

  let alloc_frame ~smac ~dmac ~src ~dst =
    let ethernet_frame = Io_page.to_cstruct (Io_page.get 1) in
    let ethernet_frame = Cstruct.sub ethernet_frame 0 (Wire_structs.sizeof_ethernet + Ipv6_wire.sizeof_ipv6) in
    Macaddr.to_cstruct_raw dmac (Wire_structs.get_ethernet_dst ethernet_frame) 0;
    Macaddr.to_cstruct_raw smac (Wire_structs.get_ethernet_src ethernet_frame) 0;
    Wire_structs.set_ethernet_ethertype ethernet_frame 0x86dd; (* IPv6 *)
    let buf = Cstruct.shift ethernet_frame Wire_structs.sizeof_ethernet in
    (* Write the constant IPv6 header fields *)
    Ipv6_wire.set_ipv6_version_flow buf 0x60000000l; (* IPv6 *)
    Ipaddr.V6.to_cstruct_raw src (Ipv6_wire.get_ipv6_src buf) 0;
    Ipaddr.V6.to_cstruct_raw dst (Ipv6_wire.get_ipv6_dst buf) 0;
    (* Ipv6_wire.set_ipv6_hlim buf hlim; *)
    ethernet_frame

  let alloc_icmp_error ~src ~dst ~ty ~code ?(reserved = 0l) buf frame =
    let maxbuf =
      Defaults.min_link_mtu - (Wire_structs.sizeof_ethernet + Ipv6_wire.sizeof_ipv6 + Ipv6_wire.sizeof_icmpv6)
    in
    (* FIXME ? hlim = 255 *)
    let buf = Cstruct.sub buf 0 (min (Cstruct.len buf) maxbuf) in
    let frame = Cstruct.add_len frame Ipv6_wire.sizeof_icmpv6 in
    let ipbuf = Cstruct.shift frame Wire_structs.sizeof_ethernet in
    Ipv6_wire.set_ipv6_nhdr ipbuf 58;
    Ipv6_wire.set_ipv6_len ipbuf (Cstruct.len buf + Ipv6_wire.sizeof_icmpv6);
    let icmpbuf = Cstruct.shift frame (Wire_structs.sizeof_ethernet + Ipv6_wire.sizeof_ipv6) in
    Ipv6_wire.set_icmpv6_ty icmpbuf ty;
    Ipv6_wire.set_icmpv6_code icmpbuf code;
    Ipv6_wire.set_icmpv6_reserved icmpbuf reserved;
    let csum = cksum ~src ~dst ~proto:58 [ icmpbuf; buf ] in
    Ipv6_wire.set_icmpv6_csum icmpbuf csum;
    [ frame; buf ]

  let alloc_ns ~target frame =
    let len = Ipv6_wire.sizeof_ns + Ipv6_wire.sizeof_opt + 6 in
    let frame = Cstruct.add_len frame len in
    let ipbuf = Cstruct.shift frame Wire_structs.sizeof_ethernet in
    Ipv6_wire.set_ipv6_nhdr ipbuf 58; (* ICMP *)
    Ipv6_wire.set_ipv6_hlim ipbuf 255;
    Ipv6_wire.set_ipv6_len ipbuf len;
    let icmpbuf = Cstruct.shift frame (Ipv6_wire.sizeof_ipv6 + Wire_structs.sizeof_ethernet) in
    (* Fill ICMPv6 Header *)
    Ipv6_wire.set_ns_ty icmpbuf 135; (* NS *)
    Ipv6_wire.set_ns_code icmpbuf 0;
    (* Fill ICMPv6 Payload *)
    Ipv6_wire.set_ns_reserved icmpbuf 0l;
    Ipaddr.V6.to_cstruct_raw target (Ipv6_wire.get_ns_target icmpbuf) 0;
    let optbuf = Cstruct.shift icmpbuf Ipv6_wire.sizeof_ns in
    Ipv6_wire.set_opt_ty optbuf 1; (* SLLA *)
    Ipv6_wire.set_opt_len optbuf 1;
    Cstruct.blit (Wire_structs.get_ethernet_src frame) 0 optbuf 2 6;
    (* Fill ICMPv6 Checksum *)
    let src = Ipaddr.V6.of_cstruct (Ipv6_wire.get_ipv6_src ipbuf) in
    let dst = Ipaddr.V6.of_cstruct (Ipv6_wire.get_ipv6_dst ipbuf) in
    let csum = cksum ~src ~dst ~proto:58 (* ICMP *) [ icmpbuf ] in
    Ipv6_wire.set_icmpv6_csum icmpbuf csum;
    [ frame ]

  let alloc_na_data ~target ~solicited frame =
    let len = Ipv6_wire.sizeof_na + Ipv6_wire.sizeof_opt + 6 in
    let frame = Cstruct.add_len frame len in
    let ipbuf = Cstruct.shift frame Wire_structs.sizeof_ethernet in
    Ipv6_wire.set_ipv6_nhdr ipbuf 58;
    Ipv6_wire.set_ipv6_hlim ipbuf 255;
    Ipv6_wire.set_ipv6_len ipbuf len;
    let icmpbuf = Cstruct.shift frame (Wire_structs.sizeof_ethernet + Ipv6_wire.sizeof_ipv6) in
    (* Fill ICMPv6 Header *)
    Ipv6_wire.set_na_ty icmpbuf 136; (* NA *)
    Ipv6_wire.set_na_code icmpbuf 0;
    (* Fill ICMPv6 Payload *)
    Ipv6_wire.set_na_reserved icmpbuf (if solicited then 0x60000000l else 0x20000000l);
    Ipaddr.V6.to_cstruct_raw target (Ipv6_wire.get_na_target icmpbuf) 0;
    let optbuf = Cstruct.shift icmpbuf Ipv6_wire.sizeof_na in
    Ipv6_wire.set_opt_ty optbuf 2; (* TLLA *)
    Ipv6_wire.set_opt_len optbuf 1;
    Cstruct.blit (Wire_structs.get_ethernet_src frame) 0 optbuf 2 6;
    (* Fill ICMPv6 Checksum *)
    let src = Ipaddr.V6.of_cstruct (Ipv6_wire.get_ipv6_src ipbuf) in
    let dst = Ipaddr.V6.of_cstruct (Ipv6_wire.get_ipv6_dst ipbuf) in
    let csum = cksum ~src ~dst ~proto:58 (* ICMP *) [ icmpbuf ] in
    Ipv6_wire.set_icmpv6_csum icmpbuf csum;
    [ frame ]

  let select_source_address st =
    let rec loop = function
      | (_, TENTATIVE _) :: rest -> loop rest
      | (ip, _) :: _             -> ip (* FIXME *)
      | []                       -> Ipaddr.V6.unspecified
    in
    loop st.my_ips

  let next_hop st ip =
    if is_local st ip then
      Some ip
    else if not (List.length st.rt_list = 0) then
       (* TODO Default Router Selection 6.3.6 *)
      Some (fst (List.nth st.rt_list (Random.int (List.length st.rt_list))))
    else
      None

  let rec output ~now st ~src ~dst datav =
    let output_multicast dst datav =
      let dmac = multicast_mac dst in
      let frame = alloc_frame ~smac:st.mac ~dmac ~src ~dst in
      [datav frame]
    in
    if Ipaddr.V6.is_multicast dst then
      output_multicast dst datav, []
    else
      match next_hop st dst with
      | None ->
        raise (No_route_to_host dst) (* FIXME *)
      | Some ip ->
        let msg dmac = datav @@ alloc_frame ~smac:st.mac ~dmac ~src ~dst in
        if Hashtbl.mem st.nb_cache ip then
          let nb = Hashtbl.find st.nb_cache ip in
          match nb.state with
          | INCOMPLETE (t, nt, _) ->
            nb.state <- INCOMPLETE (t, nt, Some msg);
            [], []
          | REACHABLE (_, dmac) | DELAY (_, dmac) | PROBE (_, _, dmac) ->
            [msg dmac], []
          | STALE dmac ->
            (* FIXME int Defaults.delay_first_probe_time *)
            let dt = Time.Span.of_float @@ float Defaults.delay_first_probe_time in
            nb.state <- DELAY (Time.add now dt, dmac);
            [msg dmac], [dt]
        else
          let dt = st.reachable_time in
          let nb = {state = INCOMPLETE (Time.add now dt, 0, Some msg); is_router = false} in
          Hashtbl.add st.nb_cache ip nb;
          let datav = alloc_ns ~target:ip in
          let dst = Ipaddr.V6.Prefix.network_address solicited_node_prefix ip in
          output_multicast dst datav, [dt]

  (* FIXME if node goes from router to host, remove from default router list;
     this could be handled in input_icmp_message *)

  (* val tick : state -> unit Lwt.t *)
  let tick st ~now =
    let process ip nb =
      match nb.state with
      | INCOMPLETE (t, tn, msg) ->
        begin match t <= now, tn < Defaults.max_multicast_solicit with
          | true, true ->
            Printf.printf "NDP: %s INCOMPLETE timeout, retrying\n%!" (Ipaddr.V6.to_string ip);
            let src = select_source_address st in (* FIXME choose src in a paritcular way ? see 7.2.2 *)
            let dst = Ipaddr.V6.Prefix.network_address solicited_node_prefix ip in
            let datav = alloc_ns ~target:ip in
            let dt = st.retrans_timer in
            nb.state <- INCOMPLETE (Time.add now dt, tn + 1, msg);
            let pkts, timers = output ~now st ~src ~dst datav in
            pkts, dt :: timers
          | true, false ->
            Printf.printf "NDP: %s unrachable, discarding\n%!" (Ipaddr.V6.to_string ip);
            (* TODO Generate ICMP error: Destination Unreachable *)
            Hashtbl.remove st.nb_cache ip;
            [], []
          | _ ->
            [], []
        end
      | REACHABLE (t, mac) ->
        begin match t <= now with
          | true ->
            Printf.printf "NDP: %s REACHABLE --> STALE\n%!" (Ipaddr.V6.to_string ip);
            nb.state <- STALE mac;
            [], []
          | false ->
            [], []
        end
      | DELAY (t, dmac) ->
        begin match t <= now with
          | true ->
            Printf.printf "NDP: %s DELAY --> PROBE\n%!" (Ipaddr.V6.to_string ip);
            let src = select_source_address st in
            let datav  = alloc_ns ~target:ip in
            let dt = st.retrans_timer in
            nb.state <- PROBE (Time.add now dt, 0, dmac);
            let pkts, timers = output ~now st ~src ~dst:ip datav in
            pkts, dt :: timers
          | false ->
            [], []
        end
      | PROBE (t, tn, dmac) ->
        begin match t <= now, tn < Defaults.max_unicast_solicit with
          | true, true ->
            Printf.printf "NDP: %s PROBE timeout, retrying\n%!" (Ipaddr.V6.to_string ip);
            let src = select_source_address st in
            let datav = alloc_ns ~target:ip in
            let dt = st.retrans_timer in
            nb.state <- PROBE (Time.add now dt, tn + 1, dmac);
            let pkts, timers = output ~now st ~src ~dst:ip datav in
            pkts, dt :: timers
          | true, false ->
            Printf.printf "NDP: %s PROBE unreachable, discarding\n%!" (Ipaddr.V6.to_string ip);
            Hashtbl.remove st.nb_cache ip;
            [], []
          | _ ->
            [], []
        end
      | _ ->
        [], []
    in

    let pkts, timers =
      Hashtbl.fold (fun ip nb (pkts, timers) ->
          let pkts', timers' = process ip nb in
          pkts' @ pkts, timers' @ timers) st.nb_cache ([], []) in

    if List.exists (fun (_, t) -> t <= now) st.rt_list then
      st.rt_list <- List.filter (fun (_, t) -> t > now) st.rt_list;
    (* TODO expire prefixes *)
    (* FIXME if we are keeping a destination cache, we must remove the stale routers from there as well. *)

    if List.exists
        (function (_, TENTATIVE (_, _, t))
                | (_, PREFERRED (Some (t, _)))
                | (_, DEPRECATED (Some t)) -> t <= now
                | _ -> false)
        st.my_ips
    then begin
      let rec aux = function
        | (ip, TENTATIVE (timeout, n, t)) as addr ->
          begin match t <= now, n + 1 >= Defaults.dup_addr_detect_transmits with
            | true, true ->
              let timeout, timers = match timeout with
                | None -> None, []
                | Some (preferred_lifetime, valid_lifetime) ->
                  Some (Time.add now preferred_lifetime, valid_lifetime), [preferred_lifetime]
              in
              Printf.printf "DAD Sucess : IP address %s is now PREFERRED\n%!" (Ipaddr.V6.to_string ip);
              Some (ip, PREFERRED timeout), [], timers
            | true, false ->
              let datav = alloc_ns ~target:ip in
              let dst = Ipaddr.V6.Prefix.network_address solicited_node_prefix ip in
              let pkts, timers = output ~now st ~src:Ipaddr.V6.unspecified ~dst datav in
              let dt = st.retrans_timer in
              Some (ip, TENTATIVE (timeout, n + 1, Time.add now dt)), pkts, dt :: timers
            | false, _ ->
              Some addr, [], []
          end
        | ip, PREFERRED (Some (preferred_timeout, valid_lifetime)) as addr ->
          begin match preferred_timeout <= now with
            | true ->
              Printf.printf "DAD : Address %s is now DEPRECATED\n%!" (Ipaddr.V6.to_string ip);
              let valid_timeout, timers = match valid_lifetime with
                | None -> None, []
                | Some valid_lifetime -> Some (Time.add now valid_lifetime), [valid_lifetime]
              in
              Some (ip, DEPRECATED valid_timeout), [], timers
            | false ->
              Some addr, [], []
          end
        | ip, DEPRECATED (Some t) as addr ->
          begin match t <= now with
            | true ->
              Printf.printf "DAD : Address %s expired, removing\n%!" (Ipaddr.V6.to_string ip);
              None, [], []
            | false ->
              Some addr, [], []
          end
        | addr ->
          Some addr, [], []
      in
      let my_ips, pkts, timers =
        List.fold_right begin fun ip (ips, pkts, timers) ->
          let addr, pkts', timers' = aux ip in
          let pkts = pkts' @ pkts in
          let timers = timers' @ timers in
          let ips = match addr with Some ip -> ip :: ips | None -> ips in
          ips, pkts, timers
        end st.my_ips ([], pkts, timers) in
      st.my_ips <- my_ips;
      pkts, timers
    end else
      pkts, timers

  let update_prefix ~now st pref ~valid =
    let already_exists = List.mem_assoc pref st.prefix_list in
    match already_exists, Time.Span.to_float valid with
    | false, 0.0 ->
      []
    | true, 0.0 ->
      Printf.printf "NDP: Removing prefix %s\n%!" (Ipaddr.V6.Prefix.to_string pref);
      st.prefix_list <- List.remove_assoc pref st.prefix_list;
      []
    | true, n ->
      Printf.printf "NDP: Refreshing prefix %s, lifetime %f\n%!" (Ipaddr.V6.Prefix.to_string pref) n;
      let prefix_list = List.remove_assoc pref st.prefix_list in
      let dt = Time.Span.of_float n in
      st.prefix_list <- (pref, Some (Time.add now dt)) :: prefix_list;
      [dt]
    | false, n ->
      Printf.printf "NDP: Adding prefix %s, lifetime %f\n%!" (Ipaddr.V6.Prefix.to_string pref) n;
      let dt = Time.Span.of_float n in
      st.prefix_list <- (pref, Some (Time.add now dt)) :: st.prefix_list;
      [dt]

  let compute_reachable_time dt =
    let d = Defaults.(min_random_factor +. Random.float (max_random_factor -. min_random_factor)) in
    Time.Span.of_float (d *. Time.Span.to_float dt)

  let add_nc_entry st ~ip ~is_router ~state =
    Printf.printf "Adding neighbor with ip addr %s\n%!" (Ipaddr.V6.to_string ip);
    let nb = { state; is_router } in
    Hashtbl.replace st.nb_cache ip nb;
    nb

  let lookup_prefix st pref =
    let rec loop = function
      | (ip, _) :: _ when Ipaddr.V6.Prefix.mem ip pref -> Some ip
      | _ :: rest                                      -> loop rest
      | []                                             -> None
    in
    loop st.my_ips

  let add_ip ~now st ?lifetime ip =
    assert (not (List.mem_assq ip st.my_ips));
    let dt = st.retrans_timer in
    st.my_ips <- (ip, TENTATIVE (lifetime, 0, Time.add now dt)) :: st.my_ips;
    let datav = alloc_ns ~target:ip in
    let src = Ipaddr.V6.unspecified in
    let dst = Ipaddr.V6.Prefix.network_address solicited_node_prefix ip in
    let pkts, timers = output ~now st ~src ~dst datav in
    pkts, dt :: timers

  type nd_option_prefix = {
    prf_on_link : bool;
    prf_autonomous : bool;
    prf_valid_lifetime : Time.Span.t;
    prf_preferred_lifetime : Time.Span.t;
    prf_prefix : Ipaddr.V6.Prefix.t
  }

  type nd_option =
    | SLLA of Macaddr.t
    | TLLA of Macaddr.t
    | Prefix of nd_option_prefix
    | MTU of int

  type ra = {
    ra_cur_hop_limit : int;
    ra_router_lifetime : Time.Span.t;
    ra_reachable_time : Time.Span.t;
    ra_retrans_timer : Time.Span.t
  }

  let float_of_uint32 n = Uint32.to_float @@ Uint32.of_int32 n

  let rec parse_nd_options opts =
    if Cstruct.len opts >= Ipv6_wire.sizeof_opt then
      (* TODO check for invalid len == 0 *)
      let opt, opts = Cstruct.split opts (Ipv6_wire.get_opt_len opts * 8) in
      match Ipv6_wire.get_opt_ty opt, Ipv6_wire.get_opt_len opt with
      | 1, 1 ->
        SLLA (Macaddr.of_cstruct (Cstruct.shift opt 2)) :: parse_nd_options opts
      | 2, 1 ->
        TLLA (Macaddr.of_cstruct (Cstruct.shift opt 2)) :: parse_nd_options opts
      | 5, 1 ->
        MTU (Int32.to_int (Cstruct.BE.get_uint32 opt 4)) :: parse_nd_options opts
      | 3, 4 ->
        let prf_prefix =
          Ipaddr.V6.Prefix.make
            (Ipv6_wire.get_opt_prefix_prefix_len opt)
            (Ipaddr.V6.of_cstruct (Ipv6_wire.get_opt_prefix_prefix opt)) in
        let span x = Time.Span.of_float @@ float_of_uint32 x in
        let prf_on_link = Ipv6_wire.get_opt_prefix_on_link opt in
        let prf_autonomous = Ipv6_wire.get_opt_prefix_autonomous opt in
        let prf_valid_lifetime = span @@ Ipv6_wire.get_opt_prefix_valid_lifetime opt in
        let prf_preferred_lifetime = span @@ Ipv6_wire.get_opt_prefix_preferred_lifetime opt in
        Prefix {prf_on_link; prf_autonomous; prf_valid_lifetime; prf_preferred_lifetime; prf_prefix} ::
        parse_nd_options opts
      | ty, len ->
        Printf.printf "NDP: ND option (ty=%d,len=%d) not supported in RA\n%!" ty len;
        parse_nd_options opts
    else
      []

  let parse_ra buf =
    let ra_cur_hop_limit = Ipv6_wire.get_ra_cur_hop_limit buf in
    let ra_router_lifetime =
      Time.Span.of_float @@ float_of_int @@ Ipv6_wire.get_ra_router_lifetime buf in
    let ra_reachable_time =
      Time.Span.of_float @@ (float_of_uint32 @@ Ipv6_wire.get_ra_reachable_time buf) /. 1000.0 in
    let ra_retrans_timer =
      Time.Span.of_float @@ (float_of_uint32 @@ Ipv6_wire.get_ra_retrans_timer buf) /. 1000.0 in
    let opts = parse_nd_options (Cstruct.shift buf Ipv6_wire.sizeof_ra) in
    {ra_cur_hop_limit; ra_router_lifetime; ra_reachable_time; ra_retrans_timer}, opts

  let handle_ra ~now st ~src ~dst ra opts =
    Printf.printf "NDP: Received RA from %s to %s\n%!" (Ipaddr.V6.to_string src) (Ipaddr.V6.to_string dst);

    if ra.ra_cur_hop_limit <> 0 then begin
      st.cur_hop_limit <- ra.ra_cur_hop_limit;
      Printf.printf "NDP: curr_hop_lim %d\n%!" ra.ra_cur_hop_limit
    end;

    if Time.Span.to_float ra.ra_reachable_time <> 0.0 && st.base_reachable_time <> ra.ra_reachable_time then begin
      st.base_reachable_time <- ra.ra_reachable_time;
      st.reachable_time <- compute_reachable_time ra.ra_reachable_time
    end;

    if Time.Span.to_float ra.ra_retrans_timer <> 0.0 then st.retrans_timer <- ra.ra_retrans_timer;

    let rec process_option = function
      | SLLA new_mac ->
        Printf.printf "NDP: Processing SLLA option in RA\n%!";
        let nb =
          try
            Hashtbl.find st.nb_cache src
          with
          | Not_found ->
            add_nc_entry st ~ip:src ~is_router:true ~state:(STALE new_mac)
        in
        nb.is_router <- true;
        begin match nb.state with
          | INCOMPLETE (_, _, pending) ->
            nb.state <- STALE new_mac;
            begin match pending with
              | None   -> [], []
              | Some x -> [x new_mac], []
            end
          | REACHABLE (_, mac) | STALE mac | DELAY (_, mac) | PROBE (_, _, mac) ->
            if mac <> new_mac then nb.state <- STALE new_mac;
            [], []
        end
      | MTU new_mtu ->
        Printf.printf "NDP: Processing MTU option in RA\n%!";
        if Defaults.min_link_mtu <= new_mtu && new_mtu <= Defaults.link_mtu then st.link_mtu <- new_mtu;
        [], []
      | Prefix prf ->
        Printf.printf "NDP: Processing PREFIX option in RA\n%!";
        (* TODO check for 0 (this is checked in update_prefix currently), infinity *)
        if prf.prf_valid_lifetime >= prf.prf_preferred_lifetime && Ipaddr.V6.Prefix.link <> prf.prf_prefix then begin
          let timers =
            if prf.prf_on_link then update_prefix ~now st prf.prf_prefix ~valid:prf.prf_valid_lifetime
            else [] in
          if prf.prf_autonomous && Time.Span.to_float prf.prf_valid_lifetime > 0.0 then begin
            match lookup_prefix st prf.prf_prefix with
            | Some addr ->
              (* TODO handle already configured SLAAC address 5.5.3 e). *)
              [], timers
            | None ->
              let ip = Ipaddr.V6.Prefix.network_address prf.prf_prefix (Macaddr.interface_addr st.mac) in
              let pkts, timers' =
                add_ip ~now st ~lifetime:(prf.prf_preferred_lifetime, Some prf.prf_valid_lifetime) ip in
              pkts, timers' @ timers
          end else
            [], timers
        end else
          [], []
      | _ ->
        [], []
    in

    let pkts, timers =
      List.fold_right
        (fun opt (pkts, timers) ->
          let pkts', timers' = process_option opt in
          pkts' @ pkts, timers @ timers') opts ([], []) in

    (* TODO update the is_router flag even if there was no SLLA *)

    let timers' =
      match List.mem_assoc src st.rt_list with
      | true ->
        let rt_list = List.remove_assoc src st.rt_list in
        if Time.Span.to_float ra.ra_router_lifetime > 0.0 then begin
          Printf.printf "RA: Refreshing Router %s ltime %f\n%!" (Ipaddr.V6.to_string src)
            (Time.Span.to_float ra.ra_router_lifetime);
          let dt = ra.ra_router_lifetime in
          st.rt_list <- (src, Time.add now dt) :: rt_list;
          [dt]
        end else begin
          Printf.printf "RA: Router %s is EOL\n%!" (Ipaddr.V6.to_string src);
          st.rt_list <- rt_list;
          []
        end
      | false ->
        if Time.Span.to_float ra.ra_router_lifetime > 0.0 then begin
          Printf.printf "RA: Adding %s to the Default Router List\n%!" (Ipaddr.V6.to_string src);
          let dt = ra.ra_router_lifetime in
          st.rt_list <- (src, Time.add now dt) :: st.rt_list;
          [dt]
        end else
          []
    in

    pkts, timers' @ timers

  let parse_ns buf =
    let ns_target = Ipaddr.V6.of_cstruct (Ipv6_wire.get_ns_target buf) in
    let opts = parse_nd_options (Cstruct.shift buf Ipv6_wire.sizeof_ns) in
    ns_target, opts

  let handle_ns ~now st ~src ~dst ns_target opts =
    Printf.printf "NDP: Received NS from %s to %s with target address %s\n%!"
      (Ipaddr.V6.to_string src) (Ipaddr.V6.to_string dst) (Ipaddr.V6.to_string ns_target);

    (* TODO check hlim = 255, target not mcast, code = 0 *)

    let rec process_option = function
      | SLLA new_mac :: _ -> (* FIXME fail if DAD (src = unspec) *)
        let nb =
          try
            Hashtbl.find st.nb_cache src
          with
          | Not_found ->
            add_nc_entry st ~ip:src ~is_router:false ~state:(STALE new_mac)
        in
        begin match nb.state with
          | INCOMPLETE (_, _, pending) ->
            nb.state <- STALE new_mac;
            begin match pending with
              | None   -> []
              | Some x -> [x new_mac]
            end
          | REACHABLE (_, mac) | STALE mac | DELAY (_, mac) | PROBE (_, _, mac) ->
            if mac <> new_mac then nb.state <- STALE new_mac;
            []
        end
      | _ :: rest ->
        process_option rest
      | [] ->
        (* Printf.printf "NDP: ND option (ty=%d,len=%d) not supported in NS\n%!" ty len; *)
        []
    in

    let pkts = process_option opts in

    if List.mem_assoc ns_target st.my_ips then begin
      let src = ns_target and dst = src in (* FIXME src & dst *)
      let datav = alloc_na_data ~target:ns_target ~solicited:true in
      Printf.printf "Sending NA to %s from %s with target address %s\n%!"
        (Ipaddr.V6.to_string dst) (Ipaddr.V6.to_string src) (Ipaddr.V6.to_string ns_target);
      let pkts', timers = output ~now st ~src ~dst datav in
      pkts' @ pkts, timers
    end else
      pkts, []

  type na = {
    na_router : bool;
    na_solicited : bool;
    na_override : bool;
    na_target : Ipaddr.V6.t
  }

  let parse_na buf =
    let na_router    = Ipv6_wire.get_na_router buf in
    let na_solicited = Ipv6_wire.get_na_solicited buf in
    let na_override  = Ipv6_wire.get_na_override buf in
    let na_target    = Ipaddr.V6.of_cstruct (Ipv6_wire.get_na_target buf) in
    let opts         = parse_nd_options (Cstruct.shift buf Ipv6_wire.sizeof_na) in
    {na_router; na_solicited; na_override; na_target}, opts

  let handle_na ~now st ~src ~dst na opts =
    Printf.printf "NDP: Received NA from %s to %s with target address %s\n%!"
      (Ipaddr.V6.to_string src) (Ipaddr.V6.to_string dst) (Ipaddr.V6.to_string na.na_target);

    (* TODO check hlim = 255, code = 0, target not mcast, not (solicited && mcast (dst)) *)

    let rec get_tlla = function
      | TLLA mac :: rest -> Some mac
      | _ :: rest        -> get_tlla rest
      | []               -> None
    in
    let new_mac = get_tlla opts in

    (* TODO if target is one of the my_ips then fail.  If my_ip is TENTATIVE then fail DAD. *)

    (* Printf.printf "NDP: %s -> %s\n%!" (Ipaddr.V6.to_string target); *)
    if Hashtbl.mem st.nb_cache na.na_target then begin
      let nb = Hashtbl.find st.nb_cache na.na_target in
      match nb.state, new_mac, na.na_solicited, na.na_override with
      | INCOMPLETE (_, _, pending), Some new_mac, false, _ ->
        Printf.printf "NDP: %s INCOMPLETE --> STALE\n%!" (Ipaddr.V6.to_string na.na_target);
        nb.state <- STALE new_mac;
        begin match pending with
          | None   -> [], []
          | Some x -> [x new_mac], []
        end
      | INCOMPLETE (_, _, pending), Some new_mac, true, _ ->
        Printf.printf "NDP: %s INCOMPLETE --> REACHABLE\n%!" (Ipaddr.V6.to_string na.na_target);
        let dt = st.reachable_time in
        nb.state <- REACHABLE (Time.add now dt, new_mac);
        begin match pending with
          | None   -> [], [dt]
          | Some x -> [x new_mac], [dt]
        end
      | INCOMPLETE _, None, _, _ ->
        nb.is_router <- na.na_router;
        [], []
      | PROBE (_, _, mac), Some new_mac, true, false when mac = new_mac ->
        Printf.printf "NDP: %s PROBE --> REACHABLE\n%!" (Ipaddr.V6.to_string na.na_target);
        let dt = st.reachable_time in
        nb.state <- REACHABLE (Time.add now dt, new_mac);
        [], [dt]
      | PROBE (_, _, mac), None, true, false ->
        Printf.printf "NDP: %s PROBE --> REACHABLE\n%!" (Ipaddr.V6.to_string na.na_target);
        let dt = st.reachable_time in
        nb.state <- REACHABLE (Time.add now dt, mac);
        [], [dt]
      | (REACHABLE _ | STALE _ | DELAY _ | PROBE _), None, _, _ ->
        nb.is_router <- na.na_router;
        [], []
      | REACHABLE (_, mac), Some new_mac, true, false when mac <> new_mac ->
        Printf.printf "NDP: %s REACHABLE --> STALE\n%!" (Ipaddr.V6.to_string na.na_target);
        nb.state <- STALE mac; (* TODO check mac or new_mac *)
        [], []
      | (REACHABLE _ | STALE _ | DELAY _ | PROBE _), Some new_mac, true, true ->
        let dt = st.reachable_time in
        nb.state <- REACHABLE (Time.add now dt, new_mac);
        [], [dt]
      | (REACHABLE (_, mac) | STALE mac | DELAY (_, mac) | PROBE (_, _, mac)),
        Some new_mac, false, true when mac <> new_mac ->
        Printf.printf "NDP: %s REACHABLE --> STALE\n%!" (Ipaddr.V6.to_string na.na_target);
        nb.state <- STALE mac;
        [], []
      | _ ->
        [], []
    end else
      [], []

  let is_icmp_error buf =
    let rec loop hdr buf =
      match hdr with
      | 58 ->
        begin match Ipv6_wire.get_icmpv6_ty buf with
          | 1 | 2 | 3 | 4 | 100 | 101 | 127 -> true
          | _ -> false
        end
      | 0 | 43 | 60 ->
        loop (Ipv6_wire.get_opt_ty buf) (Cstruct.shift buf (Ipv6_wire.get_opt_len buf))
      | _ ->
        false
    in
    loop (Ipv6_wire.get_ipv6_nhdr buf) (Cstruct.shift buf Ipv6_wire.sizeof_ipv6)

  (* buf : packet that caused the error *)
  let icmp_error_output ~now st ~src ~dst ~ty ~code ~reserved buf =
    if not (is_icmp_error buf) && Ipaddr.V6.(compare unspecified src) != 0 then
      let dst = src
      and src = if Ipaddr.V6.is_multicast dst then select_source_address st else dst in
      let datav = alloc_icmp_error ~src ~dst ~ty ~code ~reserved buf in
      Printf.printf "Sending ICMPv6 ERROR message type %d code %d to %s from %s\n%!"
        ty code (Ipaddr.V6.to_string src) (Ipaddr.V6.to_string dst);
      output ~now st ~src ~dst datav
    else
      [], []

  let echo_request_input ~now st ~src ~dst buf =
    Printf.printf "Received Echo Request from %s to %s\n%!" (Ipaddr.V6.to_string src) (Ipaddr.V6.to_string dst);
    let dst = src
    and src = if Ipaddr.V6.is_multicast dst then select_source_address st else dst in
    let datav frame =
      let frame = Cstruct.add_len frame Ipv6_wire.sizeof_icmpv6 in
      let ipbuf = Cstruct.shift frame Wire_structs.sizeof_ethernet in
      Ipv6_wire.set_ipv6_nhdr ipbuf 58; (* ICMP6 *)
      Ipv6_wire.set_ipv6_len ipbuf (Cstruct.len buf);
      let icmpbuf = Cstruct.shift frame (Wire_structs.sizeof_ethernet + Ipv6_wire.sizeof_ipv6) in
      Ipv6_wire.set_icmpv6_ty icmpbuf 129; (* ECHO REPLY *)
      Ipv6_wire.set_icmpv6_code icmpbuf 0;
      Ipv6_wire.set_icmpv6_reserved icmpbuf (Ipv6_wire.get_icmpv6_reserved buf);
      let data = Cstruct.shift buf Ipv6_wire.sizeof_icmpv6 in
      Ipv6_wire.set_icmpv6_csum icmpbuf 0;
      Ipv6_wire.set_icmpv6_csum icmpbuf (cksum ~src ~dst ~proto:58 [icmpbuf; data]);
      [frame; data]
    in
    output ~now st ~src ~dst datav

  (* buf : icmp packet *)
  let icmp_input ~now st ~src ~dst buf poff =
    let buf = Cstruct.shift buf poff in
    let csum = cksum ~src ~dst ~proto:58 (* ICMP *) [ buf ] in
    if not (csum = 0) then begin
      Printf.printf "ICMP6 checksum error (0x%x), dropping packet\n%!" csum;
      [], []
    end else begin
      match Ipv6_wire.get_icmpv6_ty buf with
      | 128 -> (* Echo request *)
        echo_request_input ~now st ~src ~dst buf
      | 129 (* Echo reply *) ->
        Printf.printf "ICMP6: Discarding Echo Reply\n%!";
        [], []
      | 133 (* RS *) ->
        (* RFC 4861, 2.6.2 *)
        [], []
      | 134 (* RA *) ->
        let ra, opts = parse_ra buf in
        handle_ra ~now st ~src ~dst ra opts
      | 135 (* NS *) ->
        let ns, opts = parse_ns buf in
        handle_ns ~now st ~src ~dst ns opts
      | 136 (* NA *) ->
        let na, opts = parse_na buf in
        handle_na ~now st ~src ~dst na opts
      | n ->
        Printf.printf "ICMP6: unrecognized type (%d)\n%!" n;
        [], []
    end

  let is_my_addr st ip =
    List.exists begin function
      | _, TENTATIVE _ -> false
      | ip', _ -> Ipaddr.V6.compare ip' ip = 0
    end st.my_ips

  let handle_packet ~now st buf =
    let src = Ipaddr.V6.of_cstruct (Ipv6_wire.get_ipv6_src buf) in
    let dst = Ipaddr.V6.of_cstruct (Ipv6_wire.get_ipv6_dst buf) in

    (* TODO check version = 6 *)

    Printf.printf "IPv6 packet received from %s to %s\n%!"
      (Ipaddr.V6.to_string src) (Ipaddr.V6.to_string dst);

    let rec process_option st poff =
      let pbuf = Cstruct.shift buf poff in
      let nhdr = Ipv6_wire.get_opt_ty pbuf in
      let olen = Ipv6_wire.get_opt_len pbuf * 8 + 8 in
      let oend = olen + poff in
      let rec loop ooff =
        if ooff < oend then begin
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
            | 0 ->
              loop (ooff+len+2)
            | 0x40 ->
              (* discard the packet *)
              `Stop, ([], [])
            | 0x80 ->
              (* discard, send icmp error *)
              `Stop, icmp_error_output ~now st ~src ~dst ~ty:4 ~code:2 ~reserved:(Int32.of_int ooff) buf
            | 0xc0 ->
              (* discard, send icmp error if dest is not mcast *)
              if Ipaddr.V6.is_multicast dst then
                `Stop, ([], [])
              else
                `Stop, icmp_error_output ~now st ~src ~dst ~ty:4 ~code:2 ~reserved:(Int32.of_int ooff) buf
            | _ ->
              assert false
        end else
          `Continue (nhdr, oend), ([], [])
      in
      loop (poff+2)

    (* See http://en.wikipedia.org/wiki/List_of_IP_protocol_numbers *)
    and process st first hdr poff =
      match hdr with
      | 0 (* HOPTOPT *) ->
        Printf.printf "Processing HOPOPT header\n%!";
        if first then
          match process_option st poff with
          | `Stop, pkts_timers ->
            `None, pkts_timers
          | `Continue (nhdr, oend), (pkts, timers) ->
            let r, (pkts', timers') = process st false nhdr oend in
            r, (pkts @ pkts', timers @ timers')
        else
          `None, ([], [])
      | 60 (* IPv6-Opts *) ->
        Printf.printf "Processing DESTOPT header\n%!";
        begin match process_option st poff with
          | `Stop, pkts_timers ->
            `None, pkts_timers
          | `Continue (nhdr, oend), (pkts, timers) ->
            let r, (pkts', timers') = process st false nhdr oend in
            r, (pkts @ pkts', timers @ timers')
        end
      | 43 (* TODO IPv6-Route *)
      | 44 (* TODO IPv6-Frag *)
      | 50 (* TODO ESP *)
      | 51 (* TODO AH *)
      | 135 (* TODO Mobility Header *)
      | 59 (* NO NEXT HEADER *) ->
        `None, ([], [])
      | 58 (* ICMP *) ->
        `None, icmp_input ~now st ~src ~dst buf poff
      | 17 (* UDP *) ->
        `Udp (src, dst, Cstruct.shift buf poff), ([], [])
      | 6 (* TCP *) ->
        `Tcp (src, dst, Cstruct.shift buf poff), ([], [])
      | n when 143 <= n && n <= 255 ->
        (* UNASSIGNED, EXPERIMENTAL & RESERVED *)
        `None, ([], [])
      | n ->
        `Default (n, src, dst, Cstruct.shift buf poff), ([], [])
    in

    if Ipaddr.V6.Prefix.(mem src multicast) then begin
      Printf.printf "Dropping packet, src is mcast\n%!";
      `None, ([], [])
    end else if not (is_my_addr st dst) && not (Ipaddr.V6.Prefix.(mem dst multicast)) then begin
      Printf.printf "Dropping packet, not for me\n%!";
      `None, ([], [])
    end else
      process st true (Ipv6_wire.get_ipv6_nhdr buf) Ipv6_wire.sizeof_ipv6

  let create mac =
    { nb_cache    = Hashtbl.create 0;
      prefix_list = [Ipaddr.V6.Prefix.make 64 (Ipaddr.V6.make 0xfe80 0 0 0 0 0 0 0), None];
      rt_list     = [];
      mac;
      my_ips      = [];

      link_mtu            = Defaults.link_mtu;
      cur_hop_limit       = 64; (* TODO *)
      base_reachable_time = Defaults.reachable_time;
      reachable_time      = compute_reachable_time Defaults.reachable_time;
      retrans_timer       = Defaults.retrans_timer }

  let get_ipv6_gateways st =
    List.map fst st.rt_list

  let get_ipv6 st =
    List.map fst (List.filter (function (_, TENTATIVE _) -> false | _ -> true) st.my_ips)
end

let (>>=) = Lwt.(>>=)
let (>|=) = Lwt.(>|=)

module Make (E : V2_LWT.ETHIF) (T : V2_LWT.TIME) (C : V2.CLOCK) = struct
  type ethif    = E.t
  type 'a io    = 'a Lwt.t
  type buffer   = Cstruct.t
  type ipv6addr = Ipaddr.V6.t
  type callback = src:ipv6addr -> dst:ipv6addr -> buffer -> unit Lwt.t

  type t =
    { ethif : E.t;
      state : Engine.state }

  let id { ethif } = ethif

  let rec tick state =
    Printf.printf "Ticking...\n%!";
    run state @@ Engine.tick state.state (Time.of_float @@ C.time ())

  and run state (pkts, timers) =
    List.iter (fun dt ->
        let dt = Time.Span.to_float dt in
        Printf.printf "Setting up a timer in %.1fs\n%!" dt;
        Lwt.ignore_result (T.sleep @@ dt >>= fun () -> tick state)) timers;
    Lwt_list.iter_s (E.writev state.ethif) pkts

  let input state ~tcp ~udp ~default buf =
    let r, pkts_timers = Engine.handle_packet (Time.of_float @@ C.time ()) state.state buf in
    run state pkts_timers >>= fun () ->
    match r with
    | `None -> Lwt.return_unit
    | `Tcp (src, dst, pkt) -> tcp ~src ~dst pkt
    | `Udp (src, dst, pkt) -> udp ~src ~dst pkt
    | `Default (proto, src, dst, pkt) -> default ~proto ~src ~dst pkt

  let connect ethif =
    let state = {state = Engine.create (E.mac ethif); ethif} in
    T.sleep 10.0 >>= fun () ->
    Printf.printf "Starting\n%!";
    run state @@
    Engine.add_ip (Time.of_float @@ C.time ()) state.state (Macaddr.link_local_addr (E.mac ethif)) >>= fun () ->
    Lwt.return (`Ok state)
end
