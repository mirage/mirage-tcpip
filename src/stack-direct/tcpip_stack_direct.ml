(*
 * Copyright (c) 2011-2014 Anil Madhavapeddy <anil@recoil.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

open Lwt.Infix

let src = Logs.Src.create "tcpip-stack-direct" ~doc:"Pure OCaml TCP/IP stack"
module Log = (val Logs.src_log src : Logs.LOG)

type direct_ipv4_input = src:Ipaddr.V4.t -> dst:Ipaddr.V4.t -> Cstruct.t -> unit Lwt.t
module type UDPV4_DIRECT = Mirage_protocols.UDP
  with type ipaddr = Ipaddr.V4.t
   and type ipinput = direct_ipv4_input

module type TCPV4_DIRECT = Mirage_protocols.TCP
  with type ipaddr = Ipaddr.V4.t
   and type ipinput = direct_ipv4_input

module Make
    (Time     : Mirage_time.S)
    (Random   : Mirage_random.S)
    (Netif    : Mirage_net.S)
    (Ethernet : Mirage_protocols.ETHERNET)
    (Arpv4    : Mirage_protocols.ARP)
    (Ipv4     : Mirage_protocols.IP with type ipaddr = Ipaddr.V4.t)
    (Icmpv4   : Mirage_protocols.ICMP with type ipaddr = Ipaddr.V4.t)
    (Udpv4    : UDPV4_DIRECT)
    (Tcpv4    : TCPV4_DIRECT) = struct

  module UDPV4 = Udpv4
  module TCPV4 = Tcpv4
  module IPV4  = Ipv4

  type t = {
    netif : Netif.t;
    ethif : Ethernet.t;
    arpv4 : Arpv4.t;
    ipv4  : Ipv4.t;
    icmpv4: Icmpv4.t;
    udpv4 : Udpv4.t;
    tcpv4 : Tcpv4.t;
    udpv4_listeners: (int, Udpv4.callback) Hashtbl.t;
    tcpv4_listeners: (int, Tcpv4.listener) Hashtbl.t;
    mutable task : unit Lwt.t option;
  }

  let pp fmt t =
    Format.fprintf fmt "mac=%a,ip=%a" Macaddr.pp (Ethernet.mac t.ethif)
      (Fmt.list Ipaddr.V4.pp) (Ipv4.get_ip t.ipv4)

  let tcpv4 { tcpv4; _ } = tcpv4
  let udpv4 { udpv4; _ } = udpv4
  let ipv4 { ipv4; _ } = ipv4

  let err_invalid_port p = Printf.sprintf "invalid port number (%d)" p

  let listen_udpv4 t ~port callback =
    if port < 0 || port > 65535
    then raise (Invalid_argument (err_invalid_port port))
    else Hashtbl.replace t.udpv4_listeners port callback


  let listen_tcpv4 ?keepalive t ~port process =
    if port < 0 || port > 65535
    then raise (Invalid_argument (err_invalid_port port))
    else Hashtbl.replace t.tcpv4_listeners port { Tcpv4.process; keepalive }

  let udpv4_listeners t ~dst_port =
    try Some (Hashtbl.find t.udpv4_listeners dst_port)
    with Not_found -> None

  let tcpv4_listeners t dst_port =
    try Some (Hashtbl.find t.tcpv4_listeners dst_port)
    with Not_found -> None

  let listen t =
    Lwt.catch (fun () ->
        Log.debug (fun f -> f "Establishing or updating listener for stack %a" pp t);
        let ethif_listener = Ethernet.input
            ~arpv4:(Arpv4.input t.arpv4)
            ~ipv4:(
              Ipv4.input
                ~tcp:(Tcpv4.input t.tcpv4
                        ~listeners:(tcpv4_listeners t))
                ~udp:(Udpv4.input t.udpv4
                        ~listeners:(udpv4_listeners t))
                ~default:(fun ~proto ~src ~dst buf ->
                    match proto with
                    | 1 -> Icmpv4.input t.icmpv4 ~src ~dst buf
                    | _ -> Lwt.return_unit)
                t.ipv4)
            ~ipv6:(fun _ -> Lwt.return_unit)
            t.ethif
        in
        Netif.listen t.netif ~header_size:Ethernet_wire.sizeof_ethernet ethif_listener
        >>= function
        | Error e ->
          Log.warn (fun p -> p "%a" Netif.pp_error e) ;
          (* XXX: error should be passed to the caller *)
          Lwt.return_unit
        | Ok _res ->
          let nstat = Netif.get_stats_counters t.netif in
          let open Mirage_net in
          Log.info (fun f ->
              f "listening loop of interface %s terminated regularly:@ %Lu bytes \
                 (%lu packets) received, %Lu bytes (%lu packets) sent@ "
                (Macaddr.to_string (Netif.mac t.netif))
                nstat.rx_bytes nstat.rx_pkts
                nstat.tx_bytes nstat.tx_pkts) ;
          Lwt.return_unit)
      (function
        | Lwt.Canceled ->
          Log.info (fun f -> f "listen of %a cancelled" pp t);
          Lwt.return_unit
        | e -> Lwt.fail e)

  let connect netif ethif arpv4 ipv4 icmpv4 udpv4 tcpv4 =
    let udpv4_listeners = Hashtbl.create 7 in
    let tcpv4_listeners = Hashtbl.create 7 in
    let t = { netif; ethif; arpv4; ipv4; icmpv4; tcpv4; udpv4;
              udpv4_listeners; tcpv4_listeners; task = None } in
    Log.info (fun f -> f "stack assembled: %a" pp t);
    Lwt.async (fun () -> let task = listen t in t.task <- Some task; task);
    Lwt.return t

  let disconnect t =
    Log.info (fun f -> f "disconnect called: %a" pp t);
    (match t.task with None -> () | Some task -> Lwt.cancel task);
    Lwt.return_unit
end

type direct_ipv6_input = src:Ipaddr.V6.t -> dst:Ipaddr.V6.t -> Cstruct.t -> unit Lwt.t
module type UDPV6_DIRECT = Mirage_protocols.UDP
  with type ipaddr = Ipaddr.V6.t
   and type ipinput = direct_ipv6_input

module type TCPV6_DIRECT = Mirage_protocols.TCP
  with type ipaddr = Ipaddr.V6.t
   and type ipinput = direct_ipv6_input

module MakeV6
    (Time     : Mirage_time.S)
    (Random   : Mirage_random.S)
    (Netif    : Mirage_net.S)
    (Ethernet : Mirage_protocols.ETHERNET)
    (Ipv6     : Mirage_protocols.IP with type ipaddr = Ipaddr.V6.t)
    (Udpv6    : UDPV6_DIRECT)
    (Tcpv6    : TCPV6_DIRECT) = struct

  module UDP = Udpv6
  module TCP = Tcpv6
  module IP  = Ipv6

  type t = {
    netif : Netif.t;
    ethif : Ethernet.t;
    ipv6  : Ipv6.t;
    udpv6 : Udpv6.t;
    tcpv6 : Tcpv6.t;
    udpv6_listeners: (int, Udpv6.callback) Hashtbl.t;
    tcpv6_listeners: (int, Tcpv6.listener) Hashtbl.t;
    mutable task : unit Lwt.t option;
  }

  let pp fmt t =
    Format.fprintf fmt "mac=%a,ip=%a" Macaddr.pp (Ethernet.mac t.ethif)
      (Fmt.list Ipaddr.V6.pp) (Ipv6.get_ip t.ipv6)

  let tcp { tcpv6; _ } = tcpv6
  let udp { udpv6; _ } = udpv6
  let ip { ipv6; _ } = ipv6

  let err_invalid_port p = Printf.sprintf "invalid port number (%d)" p

  let listen_udp t ~port callback =
    if port < 0 || port > 65535
    then raise (Invalid_argument (err_invalid_port port))
    else Hashtbl.replace t.udpv6_listeners port callback

  let listen_tcp ?keepalive t ~port process =
    if port < 0 || port > 65535
    then raise (Invalid_argument (err_invalid_port port))
    else Hashtbl.replace t.tcpv6_listeners port { Tcpv6.process; keepalive }

  let udpv6_listeners t ~dst_port =
    try Some (Hashtbl.find t.udpv6_listeners dst_port)
    with Not_found -> None

  let tcpv6_listeners t dst_port =
    try Some (Hashtbl.find t.tcpv6_listeners dst_port)
    with Not_found -> None

  let listen t =
    Lwt.catch (fun () ->
        Log.debug (fun f -> f "Establishing or updating listener for stack %a" pp t);
        let ethif_listener = Ethernet.input
            ~arpv4:(fun _ -> Lwt.return_unit)
            ~ipv4:(fun _ -> Lwt.return_unit)
            ~ipv6:(
              Ipv6.input
                ~tcp:(Tcpv6.input t.tcpv6
                      ~listeners:(tcpv6_listeners t))
                ~udp:(Udpv6.input t.udpv6
                      ~listeners:(udpv6_listeners t))
                ~default:(fun ~proto:_ ~src:_ ~dst:_ _ -> Lwt.return_unit)
                t.ipv6)
            t.ethif
        in
        Netif.listen t.netif ~header_size:Ethernet_wire.sizeof_ethernet ethif_listener
        >>= function
        | Error e ->
          Log.warn (fun p -> p "%a" Netif.pp_error e) ;
          (* XXX: error should be passed to the caller *)
          Lwt.return_unit
        | Ok _res ->
          let nstat = Netif.get_stats_counters t.netif in
          let open Mirage_net in
          Log.info (fun f ->
              f "listening loop of interface %s terminated regularly:@ %Lu bytes \
                 (%lu packets) received, %Lu bytes (%lu packets) sent@ "
                (Macaddr.to_string (Netif.mac t.netif))
                nstat.rx_bytes nstat.rx_pkts
                nstat.tx_bytes nstat.tx_pkts) ;
          Lwt.return_unit)
      (function
        | Lwt.Canceled ->
          Log.info (fun f -> f "listen of %a cancelled" pp t);
          Lwt.return_unit
        | e -> Lwt.fail e)

  let connect netif ethif ipv6 udpv6 tcpv6 =
    let udpv6_listeners = Hashtbl.create 7 in
    let tcpv6_listeners = Hashtbl.create 7 in
    let t = { netif; ethif; ipv6; tcpv6; udpv6;
              udpv6_listeners; tcpv6_listeners; task = None } in
    Log.info (fun f -> f "stack assembled: %a" pp t);
    Lwt.async (fun () -> let task = listen t in t.task <- Some task; task);
    Lwt.return t

  let disconnect t =
    Log.info (fun f -> f "disconnect called: %a" pp t);
    (match t.task with None -> () | Some task -> Lwt.cancel task);
    Lwt.return_unit

end

