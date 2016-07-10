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
module type UDPV4_DIRECT = V1_LWT.UDPV4
  with type ipinput = direct_ipv4_input

module type TCPV4_DIRECT = V1_LWT.TCPV4
  with type ipinput = direct_ipv4_input

module Make
    (Time    : V1_LWT.TIME)
    (Random  : V1.RANDOM)
    (Netif   : V1_LWT.NETWORK)
    (Ethif   : V1_LWT.ETHIF with type netif = Netif.t)
    (Arpv4   : V1_LWT.ARP)
    (Ipv4    : V1_LWT.IPV4 with type ethif = Ethif.t)
    (Icmpv4  : V1_LWT.ICMPV4)
    (Udpv4   : UDPV4_DIRECT with type ip = Ipv4.t)
    (Tcpv4   : TCPV4_DIRECT with type ip = Ipv4.t) =
struct

  type +'a io = 'a Lwt.t
  type ('a,'b) config = ('a,'b) V1_LWT.stackv4_config
  type netif = Netif.t
  type mode = V1_LWT.direct_stack_config
  type id = (netif, mode) config
  type buffer = Cstruct.t
  type ipv4addr = Ipaddr.V4.t
  type tcpv4 = Tcpv4.t
  type udpv4 = Udpv4.t
  type ipv4 = Ipv4.t

  module UDPV4 = Udpv4
  module TCPV4 = Tcpv4
  module IPV4  = Ipv4
  module Dhcp = Dhcp_clientv4.Make(Time)(Random)(Udpv4)

  type t = {
    id    : id;
    mode  : mode;
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

  type error = [
      `Unknown of string
  ]

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

  let pp_opt pp f = function
    | None -> Format.pp_print_string f "None"
    | Some x -> pp f x

  let configure_dhcp t info =
    Ipv4.set_ip t.ipv4 info.Dhcp.ip_addr
    >>= fun () ->
    (match info.Dhcp.netmask with
     | Some nm -> Ipv4.set_ip_netmask t.ipv4 nm
     | None    -> Lwt.return_unit)
    >>= fun () ->
    Ipv4.set_ip_gateways t.ipv4 info.Dhcp.gateways
    >|= fun () ->
    Log.info (fun f -> f "DHCP offer received and bound to %a nm %a gw [%s]"
      Ipaddr.V4.pp_hum info.Dhcp.ip_addr
      (pp_opt Ipaddr.V4.pp_hum) info.Dhcp.netmask
      (String.concat ", " (List.map Ipaddr.V4.to_string info.Dhcp.gateways))
    )

  let configure t config =
    match config with
    | `DHCP -> begin
        (* TODO: spawn a background thread to reconfigure the interface
           when future offers are received. *)
        let dhcp, offers = Dhcp.create (Ethif.mac t.ethif) t.udpv4 in
        listen_udpv4 t ~port:68 (Dhcp.input dhcp);
        (* TODO: stop listening to this port when done with DHCP. *)
        Lwt_stream.get offers >>= function
        | None -> Log.info (fun f -> f "No DHCP offer received"); Lwt.return ()
        | Some offer -> configure_dhcp t offer
      end
    | `IPv4 (addr, netmask, gateways) ->
      Log.info (fun f -> f "Manager: Interface to %a nm %a gw [%s]"
                           Ipaddr.V4.pp_hum addr
                           Ipaddr.V4.pp_hum netmask
                           (String.concat ", " (List.map Ipaddr.V4.to_string gateways)));
      Ipv4.set_ip t.ipv4 addr
      >>= fun () ->
      Ipv4.set_ip_netmask t.ipv4 netmask
      >>= fun () ->
      Ipv4.set_ip_gateways t.ipv4 gateways

  let udpv4_listeners t ~dst_port =
    try Some (Hashtbl.find t.udpv4_listeners dst_port)
    with Not_found -> None

  let tcpv4_listeners t dst_port =
    try Some (Hashtbl.find t.tcpv4_listeners dst_port)
    with Not_found -> None

  let listen t =
    Netif.listen t.netif (
      Ethif.input
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
        t.ethif)

  let connect id ethif arpv4 ipv4 icmpv4 udpv4 tcpv4 =
    let { V1_LWT.interface = netif; mode; _ } = id in
    Log.info (fun f -> f "Manager: connect");
    let udpv4_listeners = Hashtbl.create 7 in
    let tcpv4_listeners = Hashtbl.create 7 in
    let t = { id; mode; netif; ethif; arpv4; ipv4; icmpv4; tcpv4; udpv4;
              udpv4_listeners; tcpv4_listeners } in
    Log.info (fun f -> f "Manager: configuring");
    let _ = listen t in
    configure t t.mode
    >>= fun () ->
    (* TODO: this is fine for now, because the DHCP state machine isn't fully
       implemented and its thread will terminate after one successful lease
       transaction.  For a DHCP thread that runs forever, `configure` will need
       to spawn a background thread, but we need to consider how to inform the
       application stack that the IP address has changed (perhaps via a control
       Lwt_stream that the application can ignore if it doesn't care). *)
    Log.info (fun f -> f "Manager: configuration done");
    Lwt.return (`Ok t)

  let disconnect _t =
    (* TODO: kill the listening thread *)
    Log.info (fun f -> f "Manager: disconnect");
    Lwt.return_unit
end
