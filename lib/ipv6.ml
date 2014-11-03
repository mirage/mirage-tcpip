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
  let max_rtr_solicitation_delay = 1.0
  let ptr_solicitation_interval  = 4
  let max_rtr_solicitations      = 3
  let max_multicast_solicit      = 3
  let max_unicast_solicit        = 3
  let max_anycast_delay_time     = 1
  let max_neighbor_advertisement = 3
  let reachable_time             = 30.0
  let retrans_timer              = 1.0
  let delay_first_probe_time     = 5
  let min_random_factor          = 0.5
  let max_random_factor          = 1.5

  let link_mtu                   = 1500 (* RFC 2464, 2. *)
  let min_link_mtu               = 1280

  let dup_addr_detect_transmits  = 1
end

module Ipv6_wire = Wire_structs.Ipv6_wire

let (>>=) = Lwt.(>>=)
let (>|=) = Lwt.(>|=)

module Tvar : sig
  type 'a t
  val create : 'a -> 'a t
  val create_empty : unit -> _ t
  val put : 'a t -> 'a -> unit
  val take : 'a t -> 'a Lwt.t
end = struct
  type 'a t =
    { mutable contents : 'a option;
      readers : 'a Lwt.u Lwt_sequence.t }
  let create x =
    { contents = Some x; readers = Lwt_sequence.create () }
  let create_empty () =
    { contents = None; readers = Lwt_sequence.create () }
  let put tvar x =
    match tvar.contents with
    | None ->
      begin match Lwt_sequence.take_opt_l tvar.readers with
        | None ->
          tvar.contents <- Some x
        | Some w ->
          Lwt.wakeup_later w x
      end
    | Some _ ->
      ()
  let take tvar =
    match tvar.contents with
    | Some v ->
      tvar.contents <- None;
      Lwt.return v
    | None ->
      Lwt.add_task_r tvar.readers
end

module Timer (T : V2_LWT.TIME) : sig
  type t
  val create : float -> t
  val expired : t -> bool
  (* val cancel : t -> unit *)
  (* val cancel_all : unit -> unit *)
  (* val wait : t -> unit Lwt.t *)
  (* val wait_any : unit -> unit Lwt.t *)
end = struct
  (* let all = Tvar.create_empty () *)
  (* let cancel_all, do_cancel_all = Lwt.task () *)
  type t = unit Lwt.t
  let create n =
    T.sleep n
    (* let cancel_one, do_cancel_one = Lwt.wait () in *)
    (* let sleep = T.sleep n in *)
    (* Lwt.ignore_result (Lwt.pick [ sleep >|= Tvar.put all; cancel_one; cancel_all ]); *)
    (* sleep, do_cancel_one *)
  let expired t =
    match Lwt.state t with
    | Lwt.Return _ -> true
    | _ -> false
  (* let cancel (_, u) = *)
  (*   Lwt.wakeup u () *)
  (* let cancel_all () = *)
  (*   Lwt.wakeup do_cancel_all () *)
  (* (\* let wait (t, _) = *\) *)
  (* (\*   t *\) *)
  (* let wait_any () = *)
  (*   Tvar.take all *)
end

module Make (Ethif : V2_LWT.ETHIF) (Time : V2_LWT.TIME) = struct
  type ethif = Ethif.t
  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t
  type ipv6addr = Ipaddr.V6.t
  type callback = src:ipv6addr -> dst:ipv6addr -> buffer -> unit Lwt.t

  module Timer     = Timer (Time)
  module IpMap     = Map.Make (Ipaddr.V6)
  module PrefixMap = Map.Make (Ipaddr.V6.Prefix)

  type nd_state =
    | INCOMPLETE of Timer.t * int * (Macaddr.t -> Cstruct.t list) option
    | REACHABLE  of Timer.t * Macaddr.t
    | STALE      of Macaddr.t
    | DELAY      of Timer.t * Macaddr.t
    | PROBE      of Timer.t * int * Macaddr.t

  type nb_info =
    { mutable state               : nd_state;
      mutable is_router           : bool }

  type addr_state =
    | TENTATIVE of (float * float option) option * int * Timer.t
    | PREFERRED of (Timer.t * float option) option
    | DEPRECATED of Timer.t option

  (* TODO add destination cache *)
  type state =
    { nb_cache                    : (Ipaddr.V6.t, nb_info) Hashtbl.t;
      mutable prefix_list         : (Ipaddr.V6.Prefix.t * Timer.t option) list;
      mutable rt_list             : (Ipaddr.V6.t * Timer.t) list; (* invalidation timer *)
      ethif                       : Ethif.t;
      mutable my_ips              : (Ipaddr.V6.t * addr_state) list;
      mutable link_mtu            : int;
      mutable cur_hop_limit       : int;
      mutable base_reachable_time : float; (* default Defaults.reachable_time *)
      mutable reachable_time      : float;
      mutable retrans_timer       : float } (* Defaults.retrans_timer *)

  type t = state

  let id { ethif } = ethif

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
      | (ip, _) :: _ -> ip (* FIXME *)
      | [] -> Ipaddr.V6.unspecified
    in
    loop st.my_ips

  let fresh_nb_entry reachable_time data =
    (* FIXME int reachable_time *)
    { state = INCOMPLETE (Timer.create reachable_time, 0, data);
      is_router = false }

  let get_neighbour st ~ip ~state =
    if Hashtbl.mem st.nb_cache ip then
      Hashtbl.find st.nb_cache ip
    else
      let nb = fresh_nb_entry st.reachable_time None in
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

  let rec output st ~src ~dst datav =
    Printf.printf "output: %s -> %s\n%!" (Ipaddr.V6.to_string src) (Ipaddr.V6.to_string dst);
    if Ipaddr.V6.is_multicast dst then
      let dmac = multicast_mac dst in
      let frame = alloc_frame ~smac:(Ethif.mac st.ethif) ~dmac ~src ~dst in
      [`Write (datav frame)]
    else
      match next_hop st dst with
      | None ->
        raise (No_route_to_host dst) (* FIXME *)
      | Some ip ->
        let msg dmac =
          let frame = alloc_frame ~smac:(Ethif.mac st.ethif) ~dmac ~src ~dst in
          datav frame
        in
        if Hashtbl.mem st.nb_cache ip then
          let nb = Hashtbl.find st.nb_cache ip in
          match nb.state with
          | INCOMPLETE (t, nt, _) ->
            nb.state <- INCOMPLETE (t, nt, Some msg);
            []
          | REACHABLE (_, dmac) | DELAY (_, dmac) | PROBE (_, _, dmac) ->
            [`Write (msg dmac)]
          | STALE dmac ->
            (* FIXME int Defaults.delay_first_probe_time *)
            nb.state <- DELAY (Timer.create (float Defaults.delay_first_probe_time), dmac);
            [`Write (msg dmac)]
        else
          let nb = fresh_nb_entry st.reachable_time (Some msg) in
          Hashtbl.add st.nb_cache ip nb;
          let datav = alloc_ns ~target:ip in
          let dst = Ipaddr.V6.Prefix.network_address solicited_node_prefix ip in
          output st ~src ~dst datav

  (* FIXME if node goes from router to host, remove from default router list;
     this could be handled in input_icmp_message *)

  let rec fmap_p f l =
    let rec loop = function
      | x :: xs ->
        let fxs = fmap_p f xs
        and fx = f x in
        fx >>= begin function
          | None -> fxs
          | Some x ->
            fxs >>= fun xs ->
            Lwt.return (x :: xs)
        end
      | [] ->
        Lwt.return_nil
    in
    loop l

  (* val tick : state -> unit Lwt.t *)
  let tick st =
    let process ip nb pkts =
      match nb.state with
      | INCOMPLETE (t, tn, msg) ->
        begin match Timer.expired t, tn < Defaults.max_multicast_solicit with
          | true, true ->
            Printf.printf "NDP: %s INCOMPLETE timeout, retrying\n%!" (Ipaddr.V6.to_string ip);
            let src = select_source_address st in (* FIXME choose src in a paritcular way ? see 7.2.2 *)
            let dst = Ipaddr.V6.Prefix.network_address solicited_node_prefix ip in
            let datav = alloc_ns ~target:ip in
            (* FIXME int st.retrans_timer *)
            nb.state <- INCOMPLETE (Timer.create st.retrans_timer, tn + 1, msg);
            output st ~src ~dst datav @ pkts
          | true, false ->
            Printf.printf "NDP: %s unrachable, discarding\n%!" (Ipaddr.V6.to_string ip);
            (* TODO Generate ICMP error: Destination Unreachable *)
            Hashtbl.remove st.nb_cache ip;
            pkts
          | _ ->
            pkts
        end
      | REACHABLE (t, mac) ->
        begin match Timer.expired t with
          | true ->
            Printf.printf "NDP: %s REACHABLE --> STALE\n%!" (Ipaddr.V6.to_string ip);
            nb.state <- STALE mac;
            pkts
          | false ->
            pkts
        end
      | DELAY (t, dmac) ->
        begin match Timer.expired t with
          | true ->
            Printf.printf "NDP: %s DELAY --> PROBE\n%!" (Ipaddr.V6.to_string ip);
            let src = select_source_address st in
            let datav  = alloc_ns ~target:ip in
            (* FIXME int st.retrans_timer *)
            nb.state <- PROBE (Timer.create st.retrans_timer, 0, dmac);
            output st ~src ~dst:ip datav @ pkts
          | false ->
            pkts
        end
      | PROBE (t, tn, dmac) ->
        begin match Timer.expired t, tn < Defaults.max_unicast_solicit with
          | true, true ->
            Printf.printf "NDP: %s PROBE timeout, retrying\n%!" (Ipaddr.V6.to_string ip);
            let src = select_source_address st in
            let datav = alloc_ns ~target:ip in
            (* FIXME int st.retrans_timer *)
            nb.state <- PROBE (Timer.create st.retrans_timer, tn + 1, dmac);
            output st ~src ~dst:ip datav @ pkts
          | true, false ->
            Printf.printf "NDP: %s PROBE unreachable, discarding\n%!" (Ipaddr.V6.to_string ip);
            Hashtbl.remove st.nb_cache ip;
            pkts
          | _ ->
            pkts
        end
      | _ ->
        pkts
    in

    let pkts = Hashtbl.fold process st.nb_cache [] in

    if List.exists (fun (_, t) -> Timer.expired t) st.rt_list then
      st.rt_list <- List.filter (fun (_, t) -> not (Timer.expired t)) st.rt_list;
    (* TODO expire prefixes *)
    (* FIXME if we are keeping a destination cache, we must remove the stale routers from there as well. *)

    let pkts =
      if List.exists
          (function (_, TENTATIVE (_, _, t))
                  | (_, PREFERRED (Some (t, _)))
                  | (_, DEPRECATED (Some t)) -> Timer.expired t
                  | _ -> false)
          st.my_ips
      then begin
        let rec loop = function
          | (ip, TENTATIVE (lt, n, t)) as addr :: rest ->
            begin match Timer.expired t, n + 1 >= Defaults.dup_addr_detect_transmits with
              | true, true ->
                let lt = match lt with
                  | None -> None
                  | Some (t, vlt) -> Some (Timer.create t, vlt)
                in
                Printf.printf "DAD Sucess : IP address %s is now PREFERRED\n%!" (Ipaddr.V6.to_string ip);
                let rest, pkts = loop rest in
                (ip, PREFERRED lt) :: rest, pkts
              | true, false ->
                let datav = alloc_ns ~target:ip in
                let dst = Ipaddr.V6.Prefix.network_address solicited_node_prefix ip in
                let rest, pkts = loop rest in
                let pkts = output st ~src:Ipaddr.V6.unspecified ~dst datav @ pkts in
                (ip, TENTATIVE (lt, n + 1, Timer.create st.retrans_timer)) :: rest, pkts
              | false, _ ->
                let rest, pkts = loop rest in
                addr :: rest, pkts
            end
          | ip, PREFERRED (Some (t, vlt)) as addr :: rest ->
            begin match Timer.expired t with
              | true ->
                Printf.printf "DAD : Address %s is now DEPRECATED\n%!" (Ipaddr.V6.to_string ip);
                let rest, pkts = loop rest in
                (ip, DEPRECATED (match vlt with None -> None | Some t -> Some (Timer.create t))) :: rest, pkts
              | false ->
                let rest, pkts = loop rest in
                addr :: rest, pkts
            end
          | ip, DEPRECATED (Some t) as addr :: rest ->
            begin match Timer.expired t with
              | true ->
                Printf.printf "DAD : Address %s expired, removing\n%!" (Ipaddr.V6.to_string ip);
                loop rest
              | false ->
                let rest, pkts = loop rest in
                addr :: rest, pkts
            end
          | addr :: rest ->
            let rest, pkts = loop rest in
            addr :: rest, pkts
          | [] -> [], pkts (* defined above *)
        in
        let my_ips, pkts = loop st.my_ips in
        st.my_ips <- my_ips;
        pkts
      end else
        pkts
    in

    Lwt_list.iter_s (fun (`Write datav) -> Ethif.writev st.ethif datav) pkts

  let rec fold_options f opts i =
    if Cstruct.len opts >= Ipv6_wire.sizeof_opt then
      (* TODO check for invalid len == 0 *)
      let opt, opts = Cstruct.split opts (Ipv6_wire.get_opt_len opts * 8) in
      let i = f (Ipv6_wire.get_opt_ty opt) (Ipv6_wire.get_opt_len opt) opt i in
      fold_options f opts i
    else
      i

  let update_prefix st pref ~valid =
    let already_exists = List.mem_assoc pref st.prefix_list in
    match already_exists, valid with
    | false, 0.0 ->
      ()
    | true, 0.0 ->
      Printf.printf "NDP: Removing prefix %s\n%!" (Ipaddr.V6.Prefix.to_string pref);
      st.prefix_list <- List.remove_assoc pref st.prefix_list
    | true, n ->
      Printf.printf "NDP: Refreshing prefix %s, lifetime %f\n%!" (Ipaddr.V6.Prefix.to_string pref) n;
      let prefix_list = List.remove_assoc pref st.prefix_list in
      st.prefix_list <- (pref, Some (Timer.create n)) :: prefix_list
    | false, n ->
      Printf.printf "NDP: Adding prefix %s, lifetime %f\n%!" (Ipaddr.V6.Prefix.to_string pref) n;
      st.prefix_list <- (pref, Some (Timer.create n)) :: st.prefix_list

  let compute_reachable_time t =
    let d = Defaults.(min_random_factor +. Random.float (max_random_factor -. min_random_factor)) in
    d *. t

  let add_nc_entry st ~ip ~is_router ~state =
    Printf.printf "Adding neighbor with ip addr %s\n%!" (Ipaddr.V6.to_string ip);
    let nb = { state; is_router } in
    Hashtbl.replace st.nb_cache ip nb;
    nb

  let lookup_prefix st pref =
    let rec loop = function
      | (ip, _) :: _ when Ipaddr.V6.Prefix.mem ip pref ->
        Some ip
      | _ :: rest ->
        loop rest
      | [] ->
        None
    in
    loop st.my_ips

  let add_ip st ?lifetime ip =
    assert (not (List.mem_assq ip st.my_ips));
    st.my_ips <- (ip, TENTATIVE (lifetime, 0, Timer.create st.retrans_timer)) :: st.my_ips;
    let datav = alloc_ns ~target:ip in
    let src = Ipaddr.V6.unspecified in
    let dst = Ipaddr.V6.Prefix.network_address solicited_node_prefix ip in
    output st ~src ~dst datav

  type nd_option_prefix = {
    prf_on_link : bool;
    prf_autonomous : bool;
    prf_valid_lifetime : float;
    prf_preferred_lifetime : float;
    prf_prefix : Ipaddr.V6.Prefix.t
  }

  type nd_option =
    | SLLA of Macaddr.t
    | TLLA of Macaddr.t
    | Prefix of nd_option_prefix
    | MTU of int

  type ra = {
    ra_cur_hop_limit : int;
    ra_router_lifetime : float;
    ra_reachable_time : float;
    ra_retrans_timer : float
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
        let prf_on_link = Ipv6_wire.get_opt_prefix_on_link opt in
        let prf_autonomous = Ipv6_wire.get_opt_prefix_autonomous opt in
        let prf_valid_lifetime = float_of_uint32 @@ Ipv6_wire.get_opt_prefix_valid_lifetime opt in
        let prf_preferred_lifetime = float_of_uint32 @@ Ipv6_wire.get_opt_prefix_preferred_lifetime opt in
        Prefix {prf_on_link; prf_autonomous; prf_valid_lifetime; prf_preferred_lifetime; prf_prefix} ::
        parse_nd_options opts
      | ty, len ->
        Printf.printf "NDP: ND option (ty=%d,len=%d) not supported in RA\n%!" ty len;
        parse_nd_options opts
    else
      []

  let parse_ra buf =
    let ra_cur_hop_limit = Ipv6_wire.get_ra_cur_hop_limit buf in
    let ra_router_lifetime = float_of_int @@ Ipv6_wire.get_ra_router_lifetime buf in
    let ra_reachable_time = (float_of_uint32 @@ Ipv6_wire.get_ra_reachable_time buf) /. 1000.0 in
    let ra_retrans_timer = (float_of_uint32 @@ Ipv6_wire.get_ra_retrans_timer buf) /. 1000.0 in
    let opts = parse_nd_options (Cstruct.shift buf Ipv6_wire.sizeof_ra) in
    {ra_cur_hop_limit; ra_router_lifetime; ra_reachable_time; ra_retrans_timer}, opts

  let handle_ra st ~src ~dst ra opts =
    Printf.printf "NDP: Received RA from %s to %s\n%!" (Ipaddr.V6.to_string src) (Ipaddr.V6.to_string dst);

    if ra.ra_cur_hop_limit <> 0 then begin
      st.cur_hop_limit <- ra.ra_cur_hop_limit;
      Printf.printf "NDP: curr_hop_lim %d\n%!" ra.ra_cur_hop_limit
    end;

    if ra.ra_reachable_time <> 0.0 && st.base_reachable_time <> ra.ra_reachable_time then begin
      st.base_reachable_time <- ra.ra_reachable_time;
      st.reachable_time <- compute_reachable_time ra.ra_reachable_time
    end;

    if ra.ra_retrans_timer <> 0.0 then st.retrans_timer <- ra.ra_retrans_timer;

    let rec process_option = function
      | SLLA new_mac :: rest ->
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
              | None ->
                process_option rest
              | Some x ->
                `Write (x new_mac) :: process_option rest
            end
          | REACHABLE (_, mac) | STALE mac | DELAY (_, mac) | PROBE (_, _, mac) ->
            if mac <> new_mac then nb.state <- STALE new_mac;
            process_option rest
        end
      | MTU new_mtu :: rest ->
        Printf.printf "NDP: Processing MTU option in RA\n%!";
        if Defaults.min_link_mtu <= new_mtu && new_mtu <= Defaults.link_mtu then st.link_mtu <- new_mtu;
        process_option rest
      | Prefix prf :: rest ->
        Printf.printf "NDP: Processing PREFIX option in RA\n%!";
        (* TODO check for 0 (this is checked in update_prefix currently), infinity *)
        if prf.prf_valid_lifetime < prf.prf_preferred_lifetime || Ipaddr.V6.Prefix.link = prf.prf_prefix then
          process_option rest
        else begin
          if prf.prf_on_link then update_prefix st prf.prf_prefix ~valid:prf.prf_valid_lifetime;
          if prf.prf_autonomous && prf.prf_valid_lifetime > 0.0 then begin
            match lookup_prefix st prf.prf_prefix with
            | Some addr ->
              (* TODO handle already configured SLAAC address 5.5.3 e). *)
              process_option rest
            | None ->
              let ip = Ipaddr.V6.Prefix.network_address prf.prf_prefix (interface_addr (Ethif.mac st.ethif)) in
              add_ip st ~lifetime:(prf.prf_preferred_lifetime, Some prf.prf_valid_lifetime) ip @ process_option rest
          end else
            process_option rest
        end
      | _ :: rest ->
        process_option rest
      | [] ->
        []
    in

    let pkts = process_option opts in

    (* TODO update the is_router flag even if there was no SLLA *)

    begin match List.mem_assoc src st.rt_list with
      | true ->
        let rt_list = List.remove_assoc src st.rt_list in
        if ra.ra_router_lifetime > 0.0 then begin
          Printf.printf "RA: Refreshing Router %s ltime %f\n%!" (Ipaddr.V6.to_string src) ra.ra_router_lifetime;
          st.rt_list <- (src, Timer.create ra.ra_router_lifetime) :: rt_list
        end else begin
          Printf.printf "RA: Router %s is EOL\n%!" (Ipaddr.V6.to_string src);
          st.rt_list <- rt_list
        end
      | false ->
        if ra.ra_router_lifetime > 0.0 then begin
          Printf.printf "RA: Adding %s to the Default Router List\n%!" (Ipaddr.V6.to_string src);
          st.rt_list <- (src, Timer.create ra.ra_router_lifetime) :: st.rt_list
        end
    end;

    Lwt_list.iter_s begin function
      | `Write pkt ->
        Ethif.writev st.ethif pkt
    end pkts

  let parse_ns buf =
    let ns_target = Ipaddr.V6.of_cstruct (Ipv6_wire.get_ns_target buf) in
    let opts = parse_nd_options (Cstruct.shift buf Ipv6_wire.sizeof_ns) in
    ns_target, opts

  let handle_ns st ~src ~dst ns_target opts =
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
              | None ->
                []
              | Some x ->
                [`Write (x new_mac)]
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

    let pkts =
      if List.mem_assoc ns_target st.my_ips then begin
        let src = ns_target and dst = src in (* FIXME src & dst *)
        let datav = alloc_na_data ~target:ns_target ~solicited:true in
        Printf.printf "Sending NA to %s from %s with target address %s\n%!"
          (Ipaddr.V6.to_string dst) (Ipaddr.V6.to_string src) (Ipaddr.V6.to_string ns_target);
        output st ~src ~dst datav @ pkts
      end else
        pkts
    in

    Lwt_list.iter_s begin function
      | `Write pkt ->
        Ethif.writev st.ethif pkt
      (* | `Output (src, dst, datav) -> *)
        (* output st src dst datav *)
    end pkts

  type na = {
    na_router : bool;
    na_solicited : bool;
    na_override : bool;
    na_target : Ipaddr.V6.t
  }

  let parse_na buf =
    let na_router = Ipv6_wire.get_na_router buf in
    let na_solicited = Ipv6_wire.get_na_solicited buf in
    let na_override = Ipv6_wire.get_na_override buf in
    let na_target = Ipaddr.V6.of_cstruct (Ipv6_wire.get_na_target buf) in
    let opts = parse_nd_options (Cstruct.shift buf Ipv6_wire.sizeof_na) in
    {na_router; na_solicited; na_override; na_target}, opts

  let handle_na st ~src ~dst na opts =
    Printf.printf "NDP: Received NA from %s to %s with target address %s\n%!"
      (Ipaddr.V6.to_string src) (Ipaddr.V6.to_string dst) (Ipaddr.V6.to_string na.na_target);

    (* TODO check hlim = 255, code = 0, target not mcast, not (solicited && mcast (dst)) *)

    let rec get_tlla = function
      | TLLA mac :: rest ->
        Some mac
      | _ :: rest ->
        get_tlla rest
      | [] ->
        None
    in
    let new_mac = get_tlla opts in

    (* TODO if target is one of the my_ips then fail.  If my_ip is TENTATIVE then fail DAD. *)

    (* Printf.printf "NDP: %s -> %s\n%!" (Ipaddr.V6.to_string target); *)
    let pkts =
      if Hashtbl.mem st.nb_cache na.na_target then begin
        let nb = Hashtbl.find st.nb_cache na.na_target in
        match nb.state, new_mac, na.na_solicited, na.na_override with
        | INCOMPLETE (_, _, pending), Some new_mac, false, _ ->
          Printf.printf "NDP: %s INCOMPLETE --> STALE\n%!" (Ipaddr.V6.to_string na.na_target);
          nb.state <- STALE new_mac;
          begin match pending with
            | None -> []
              (* Lwt.return_unit *)
            | Some x ->
              [`Write (x new_mac)]
              (* Ethif.writev st.ethif (x new_mac) *)
          end
        | INCOMPLETE (_, _, pending), Some new_mac, true, _ ->
          Printf.printf "NDP: %s INCOMPLETE --> REACHABLE\n%!" (Ipaddr.V6.to_string na.na_target);
          nb.state <- REACHABLE (Timer.create st.reachable_time, new_mac);
          begin match pending with
            | None -> []
              (* Lwt.return_unit *)
            | Some x ->
              [`Write (x new_mac)]
              (* Ethif.writev st.ethif (x new_mac) *)
          end
        | INCOMPLETE _, None, _, _ ->
          nb.is_router <- na.na_router;
          []
          (* Lwt.return_unit *)
        | PROBE (_, _, mac), Some new_mac, true, false when mac = new_mac ->
          Printf.printf "NDP: %s PROBE --> REACHABLE\n%!" (Ipaddr.V6.to_string na.na_target);
          nb.state <- REACHABLE (Timer.create st.reachable_time, new_mac);
          []
          (* Lwt.return_unit *)
        | PROBE (_, _, mac), None, true, false ->
          Printf.printf "NDP: %s PROBE --> REACHABLE\n%!" (Ipaddr.V6.to_string na.na_target);
          nb.state <- REACHABLE (Timer.create st.reachable_time, mac);
          []
          (* Lwt.return_unit *)
        | (REACHABLE _ | STALE _ | DELAY _ | PROBE _), None, _, _ ->
          nb.is_router <- na.na_router;
          []
          (* Lwt.return_unit *)
        | REACHABLE (_, mac), Some new_mac, true, false when mac <> new_mac ->
          Printf.printf "NDP: %s REACHABLE --> STALE\n%!" (Ipaddr.V6.to_string na.na_target);
          nb.state <- STALE mac; (* TODO check mac or new_mac *)
          []
          (* Lwt.return_unit *)
        | (REACHABLE _ | STALE _ | DELAY _ | PROBE _), Some new_mac, true, true ->
          nb.state <- REACHABLE (Timer.create st.reachable_time, new_mac);
          []
          (* Lwt.return_unit *)
        | (REACHABLE (_, mac) | STALE mac | DELAY (_, mac) | PROBE (_, _, mac)),
          Some new_mac, false, true when mac <> new_mac ->
          Printf.printf "NDP: %s REACHABLE --> STALE\n%!" (Ipaddr.V6.to_string na.na_target);
          nb.state <- STALE mac;
          []
          (* Lwt.return_unit *)
        | _ ->
          []
          (* Lwt.return_unit *)
      end else
        []
        (* Lwt.return_unit *)
    in

    Lwt_list.iter_s begin function
      | `Write pkt ->
        Ethif.writev st.ethif pkt
    end pkts

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
  let icmp_error_output st ~src ~dst ~ty ~code ~reserved buf =
    if is_icmp_error buf || Ipaddr.V6.(compare unspecified src) = 0 then
      Lwt.return_unit
    else
      let dst = src
      and src = if Ipaddr.V6.is_multicast dst then select_source_address st else dst in
      let datav = alloc_icmp_error ~src ~dst ~ty ~code ~reserved buf in
      Printf.printf "Sending ICMPv6 ERROR message type %d code %d to %s from %s\n%!"
        ty code (Ipaddr.V6.to_string src) (Ipaddr.V6.to_string dst);
      let pkts = output st ~src ~dst datav in
      Lwt_list.iter_s (fun (`Write datav) -> Ethif.writev st.ethif datav) pkts (* FIXME *)

  let echo_request_input st ~src ~dst buf =
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
    let pkts = output st ~src ~dst datav in
    Lwt_list.iter_s (fun (`Write datav) -> Ethif.writev st.ethif datav) pkts (* FIXME *)

  (* buf : icmp packet *)
  let icmp_input st ~src ~dst buf poff =
    let buf = Cstruct.shift buf poff in
    let csum = cksum ~src ~dst ~proto:58 (* ICMP *) [ buf ] in
    if not (csum = 0) then begin
      Printf.printf "ICMP6 checksum error (0x%x), dropping packet\n%!" csum;
      Lwt.return_unit
    end else begin
      match Ipv6_wire.get_icmpv6_ty buf with
      | 128 -> (* Echo request *)
        echo_request_input st ~src ~dst buf
      | 129 (* Echo reply *) ->
        Printf.printf "ICMP6: Discarding Echo Reply\n%!";
        Lwt.return_unit
      | 133 (* RS *) ->
        (* RFC 4861, 2.6.2 *)
        Lwt.return_unit
      | 134 (* RA *) ->
        let ra, opts = parse_ra buf in
        handle_ra st ~src ~dst ra opts
      | 135 (* NS *) ->
        let ns, opts = parse_ns buf in
        handle_ns st ~src ~dst ns opts
      | 136 (* NA *) ->
        let na, opts = parse_na buf in
        handle_na st ~src ~dst na opts
      | n ->
        Printf.printf "ICMP6: unrecognized type (%d)\n%!" n;
        Lwt.return_unit
    end

  let is_my_addr st ip =
    List.exists begin function
      | _, TENTATIVE _ -> false
      | ip', _ -> Ipaddr.V6.compare ip' ip = 0
    end st.my_ips

  let input st ~tcp ~udp ~default buf =
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
              Lwt.return_unit
            | 0x80 ->
              (* discard, send icmp error *)
              icmp_error_output st ~src ~dst ~ty:4 ~code:2 ~reserved:(Int32.of_int ooff) buf
            | 0xc0 ->
              (* discard, send icmp error if dest is not mcast *)
              if Ipaddr.V6.is_multicast dst then
                Lwt.return_unit
              else
                icmp_error_output st ~src ~dst ~ty:4 ~code:2 ~reserved:(Int32.of_int ooff) buf
            | _ ->
              assert false
        end else
          process st false nhdr oend
      in
      loop (poff+2)

    (* See http://en.wikipedia.org/wiki/List_of_IP_protocol_numbers *)
    and process st first hdr poff =
      match hdr with
      | 0 (* HOPTOPT *) ->
        Printf.printf "Processing HOPOPT header\n%!";
        if first then
          process_option st poff
        else
          Lwt.return_unit
      | 60 (* IPv6-Opts *) ->
        Printf.printf "Processing DESTOPT header\n%!";
        process_option st poff
      | 43 (* TODO IPv6-Route *)
      | 44 (* TODO IPv6-Frag *)
      | 50 (* TODO ESP *)
      | 51 (* TODO AH *)
      | 135 (* TODO Mobility Header *)
      | 59 (* NO NEXT HEADER *) ->
        Lwt.return_unit
      | 58 (* ICMP *) ->
        icmp_input st ~src ~dst buf poff
      | 17 (* UDP *) ->
        udp ~src ~dst (Cstruct.shift buf poff)
      | 6 (* TCP *) ->
        tcp ~src ~dst (Cstruct.shift buf poff)
      | n when 143 <= n && n <= 255 ->
        (* UNASSIGNED, EXPERIMENTAL & RESERVED *)
        Lwt.return_unit
      | n ->
        default ~proto:n ~src ~dst (Cstruct.shift buf poff)
    in

    if Ipaddr.V6.Prefix.(mem src multicast) then begin
      Printf.printf "Dropping packet, src is mcast\n%!";
      Lwt.return_unit
    end else if not (is_my_addr st dst) && not (Ipaddr.V6.Prefix.(mem dst multicast)) then begin
      Printf.printf "Dropping packet, not for me\n%!";
      Lwt.return_unit
    end else
      process st true (Ipv6_wire.get_ipv6_nhdr buf) Ipv6_wire.sizeof_ipv6

  let connect ethif =
    let st =
      { nb_cache    = Hashtbl.create 0;
        prefix_list = [Ipaddr.V6.Prefix.make 64 (Ipaddr.V6.make 0xfe80 0 0 0 0 0 0 0), None];
        rt_list     = [];
        ethif;
        my_ips      = [];

        link_mtu            = Defaults.link_mtu;
        cur_hop_limit       = 64; (* TODO *)
        base_reachable_time = Defaults.reachable_time;
        reachable_time      = compute_reachable_time Defaults.reachable_time;
        retrans_timer       = Defaults.retrans_timer }
    in
    Time.sleep 10. >>= fun () ->
    Printf.printf "Starting\n%!";
    let rec ticker () = Time.sleep 1.0 >>= fun () -> tick st >>= ticker in
    Lwt.async ticker;
    let pkts = add_ip st (link_local_addr (Ethif.mac ethif)) in
    Lwt_list.iter_s (fun (`Write datav) -> Ethif.writev st.ethif datav) pkts >>= fun () -> (* FIXME *)
    Lwt.return (`Ok st)

  let get_ipv6_gateways st =
    List.map fst st.rt_list

  let get_ipv6 st =
    List.map fst (List.filter (function (_, TENTATIVE _) -> false | _ -> true) st.my_ips)
end
