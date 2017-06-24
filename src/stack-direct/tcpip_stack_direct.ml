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
open Result

let src = Logs.Src.create "tcpip-stack-direct" ~doc:"Pure OCaml TCP/IP stack"
module Log = (val Logs.src_log src : Logs.LOG)

type direct_ipv4_input = src:Ipaddr.V4.t -> dst:Ipaddr.V4.t -> Cstruct.t -> unit Lwt.t
module type UDPV4_DIRECT = Mirage_protocols_lwt.UDPV4
  with type ipinput = direct_ipv4_input

module type TCPV4_DIRECT = Mirage_protocols_lwt.TCPV4
  with type ipinput = direct_ipv4_input

module Make
    (Time    : Mirage_time.S)
    (Random  : Mirage_random.C)
    (Netif   : Mirage_net_lwt.S)
    (Ethif   : Mirage_protocols_lwt.ETHIF with type netif = Netif.t)
    (Arpv4   : Mirage_protocols_lwt.ARP)
    (Ipv4    : Mirage_protocols_lwt.IPV4 with type ethif = Ethif.t)
    (Icmpv4  : Mirage_protocols_lwt.ICMPV4)
    (Udpv4   : UDPV4_DIRECT with type ip = Ipv4.t)
    (Tcpv4   : TCPV4_DIRECT with type ip = Ipv4.t) = struct
  type +'a io = 'a Lwt.t
  type 'a config = 'a Mirage_stack_lwt.stackv4_config
  type netif = Netif.t
  type id = netif config
  type buffer = Cstruct.t
  type ipv4addr = Ipaddr.V4.t
  type tcpv4 = Tcpv4.t
  type udpv4 = Udpv4.t
  type ipv4 = Ipv4.t

  module UDPV4 = Udpv4
  module TCPV4 = Tcpv4
  module IPV4  = Ipv4

  type t = {
    id    : id;
    netif : Netif.t;
    ethif : Ethif.t;
    arpv4 : Arpv4.t;
    ipv4  : Ipv4.t;
    icmpv4: Icmpv4.t;
    udpv4 : Udpv4.t;
    tcpv4 : Tcpv4.t;
    udpv4_listeners: (int, Udpv4.callback) Hashtbl.t;
    tcpv4_listeners: (int, (Tcpv4.flow -> unit Lwt.t)) Hashtbl.t;
  }

  let pp fmt t =
    Format.fprintf fmt "mac=%s,ip=%a" (Macaddr.to_string (Ethif.mac t.ethif))
      (Fmt.list Ipaddr.V4.pp_hum) (Ipv4.get_ip t.ipv4)

  let tcpv4 { tcpv4; _ } = tcpv4
  let udpv4 { udpv4; _ } = udpv4
  let ipv4 { ipv4; _ } = ipv4

  let err_invalid_port p = Printf.sprintf "invalid port number (%d)" p

  let listen_udpv4 t ~port callback =
    if port < 0 || port > 65535
    then raise (Invalid_argument (err_invalid_port port))
    else Hashtbl.replace t.udpv4_listeners port callback


  let listen_tcpv4 t ~port callback =
    if port < 0 || port > 65535
    then raise (Invalid_argument (err_invalid_port port))
    else Hashtbl.replace t.tcpv4_listeners port callback

  let udpv4_listeners t ~dst_port =
    try Some (Hashtbl.find t.udpv4_listeners dst_port)
    with Not_found -> None

  let tcpv4_listeners t dst_port =
    try Some (Hashtbl.find t.tcpv4_listeners dst_port)
    with Not_found -> None

  let listen t =
    Logs.debug (fun f -> f "Establishing or updating listener for stack %a" pp t);
    let ethif_listener = Ethif.input
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
    Netif.listen t.netif ethif_listener
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
      Lwt.return_unit

  let connect id ethif arpv4 ipv4 icmpv4 udpv4 tcpv4 =
    let { Mirage_stack_lwt.interface = netif; _ } = id in
    let udpv4_listeners = Hashtbl.create 7 in
    let tcpv4_listeners = Hashtbl.create 7 in
    let t = { id; netif; ethif; arpv4; ipv4; icmpv4; tcpv4; udpv4;
              udpv4_listeners; tcpv4_listeners } in
    Log.info (fun f -> f "stack assembled: %a" pp t);
    Lwt.ignore_result (listen t);
    Lwt.return t

  let disconnect t =
    (* TODO: kill the listening thread *)
    Log.info (fun f -> f "disconnect called (currently a noop): %a" pp t);
    Lwt.return_unit
end
