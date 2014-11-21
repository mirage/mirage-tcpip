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

open Lwt

type 'ipaddr direct_ip_input = src:'ipaddr -> dst:'ipaddr -> Cstruct.t -> unit Lwt.t
module type UDPV4_DIRECT = V1_LWT.UDP
  with type ipaddr = Ipaddr.V4.t
   and type ipinput = Ipaddr.V4.t direct_ip_input

module type TCPV4_DIRECT = V1_LWT.TCP
  with type ipaddr = Ipaddr.V4.t
   and type ipinput = Ipaddr.V4.t direct_ip_input

module type UDPV6_DIRECT = V1_LWT.UDP
  with type ipaddr = Ipaddr.V6.t
   and type ipinput = Ipaddr.V6.t direct_ip_input

module type TCPV6_DIRECT = V1_LWT.TCP
  with type ipaddr = Ipaddr.V6.t
   and type ipinput = Ipaddr.V6.t direct_ip_input

module Make
    (Console : V1_LWT.CONSOLE)
    (Time    : V1_LWT.TIME)
    (Random  : V1.RANDOM)
    (Netif   : V1_LWT.NETWORK)
    (Ethif   : V1_LWT.ETHIF with type netif = Netif.t)
    (Ipv4    : V1_LWT.IPV4 with type ethif = Ethif.t)
    (Ipv6    : V1_LWT.IPV6 with type ethif = Ethif.t)
    (Udpv4   : UDPV4_DIRECT with type ip = Ipv4.t)
    (Tcpv4   : TCPV4_DIRECT with type ip = Ipv4.t)
    (Udpv6   : UDPV6_DIRECT with type ip = Ipv6.t)
    (Tcpv6   : TCPV6_DIRECT with type ip = Ipv6.t) =
struct

  type +'a io = 'a Lwt.t
  type ('a,'b,'c) config = ('a,'b,'c) V1_LWT.stack_config
  type console = Console.t
  type netif = Netif.t
  type mode = V1_LWT.direct_stack_config
  type id = (console, netif, mode) config
  type buffer = Cstruct.t
  type ipv4addr = Ipv4.ipaddr
  type ipv6addr = Ipv6.ipaddr
  type tcpv4 = Tcpv4.t
  type udpv4 = Udpv4.t
  type ipv4 = Ipv4.t
  type tcpv6 = Tcpv6.t
  type udpv6 = Udpv6.t
  type ipv6 = Ipv6.t

  module UDPV4 = Udpv4
  module TCPV4 = Tcpv4
  module IPV4  = Ipv4
  module UDPV6 = Udpv6
  module TCPV6 = Tcpv6
  module IPV6  = Ipv6
  module Dhcp = Dhcp_clientv4.Make(Console)(Time)(Random)(Ethif)(Ipv4)(Udpv4)

  type t = {
    id    : id;
    mode  : mode;
    c     : Console.t;
    netif : Netif.t;
    ethif : Ethif.t;
    ipv4  : Ipv4.t;
    ipv6  : Ipv6.t;
    udpv4 : Udpv4.t;
    tcpv4 : Tcpv4.t;
    udpv6 : Udpv6.t;
    tcpv6 : Tcpv6.t;
    udpv4_listeners: (int, Udpv4.callback) Hashtbl.t;
    tcpv4_listeners: (int, (Tcpv4.flow -> unit Lwt.t)) Hashtbl.t;
    udpv6_listeners: (int, Udpv6.callback) Hashtbl.t;
    tcpv6_listeners: (int, (Tcpv6.flow -> unit Lwt.t)) Hashtbl.t;
  }

  type error = [
      `Unknown of string
  ]

  let id { id; _ } = id
  let tcpv4 { tcpv4; _ } = tcpv4
  let udpv4 { udpv4; _ } = udpv4
  let ipv4 { ipv4; _ } = ipv4
  let tcpv6 { tcpv6; _ } = tcpv6
  let udpv6 { udpv6; _ } = udpv6
  let ipv6 { ipv6; _ } = ipv6

  let listen_udpv4 t ~port callback =
    Hashtbl.replace t.udpv4_listeners port callback

  let listen_tcpv4 t ~port callback =
    Hashtbl.replace t.tcpv4_listeners port callback

  let listen_udpv6 t ~port callback =
    Hashtbl.replace t.udpv6_listeners port callback

  let listen_tcpv6 t ~port callback =
    Hashtbl.replace t.tcpv6_listeners port callback

  let configure_ipv4 t config =
    match config with
    | `DHCP -> begin
        (* TODO: spawn a background thread to reconfigure the interface
           when future offers are received. *)
        let dhcp, offers = Dhcp.create t.c t.ipv4 t.udpv4 in
        listen_udpv4 t ~port:68 (Dhcp.input dhcp);
        (* TODO: stop listening to this port when done with DHCP. *)
        Lwt_stream.get offers
        >>= function
        | None -> fail (Failure "No DHCP offer received")
        | Some _ -> Console.log_s t.c "DHCP offer received and bound"
      end
    | `IPv4 (addr, netmask, gateways) ->
      Console.log_s t.c (Printf.sprintf "Manager: Interface to %s nm %s gw [%s]\n%!"
                           (Ipaddr.V4.to_string addr)
                           (Ipaddr.V4.to_string netmask)
                           (String.concat ", " (List.map Ipaddr.V4.to_string gateways)))
      >>= fun () ->
      Ipv4.set_ipv4 t.ipv4 addr
      >>= fun () ->
      Ipv4.set_ipv4_netmask t.ipv4 netmask
      >>= fun () ->
      Ipv4.set_ip_gateways t.ipv4 gateways

  let configure_ipv6 t config =
    match config with
    | `DHCP -> fail (Failure "DHCPv6 not implemented")
    | `SLAAC ->
      Lwt.return_unit
    | `IPv6 (addr, prefixes, gateways) ->
      Console.log_s t.c (Printf.sprintf "Manager: Interface to %s prfx %s gw [%s]\n%!"
                           (Ipaddr.V6.to_string addr)
                           (String.concat ", " (List.map Ipaddr.V6.Prefix.to_string prefixes))
                           (String.concat ", " (List.map Ipaddr.V6.to_string gateways)))
      >>= fun () ->
      Ipv6.set_ipv6 t.ipv6 addr
      >>= fun () ->
      Lwt_list.iter_s (Ipv6.set_prefix t.ipv6) prefixes
      >>= fun () ->
      Ipv6.set_ip_gateways t.ipv6 gateways

  let configure t (ipv4, ipv6) =
    Lwt.join [ configure_ipv4 t ipv4; configure_ipv6 t ipv6 ]

  let udpv4_listeners t ~dst_port =
    try Some (Hashtbl.find t.udpv4_listeners dst_port)
    with Not_found -> None

  let tcpv4_listeners t dst_port =
    try Some (Hashtbl.find t.tcpv4_listeners dst_port)
    with Not_found -> None

  let udpv6_listeners t ~dst_port =
    try Some (Hashtbl.find t.udpv6_listeners dst_port)
    with Not_found -> None

  let tcpv6_listeners t dst_port =
    try Some (Hashtbl.find t.tcpv6_listeners dst_port)
    with Not_found -> None

  let listen t =
    Netif.listen t.netif (
      Ethif.input
        ~arpv4:(Ipv4.input_arpv4 t.ipv4)
        ~ipv4:(
          Ipv4.input
            ~tcp:(Tcpv4.input t.tcpv4
                    ~listeners:(tcpv4_listeners t))
            ~udp:(Udpv4.input t.udpv4
                    ~listeners:(udpv4_listeners t))
            ~default:(fun ~proto:_ ~src:_ ~dst:_ _ -> return_unit)
            t.ipv4)
        ~ipv6:(Ipv6.input t.ipv6
                 ~tcp:(Tcpv6.input t.tcpv6
                         ~listeners:(tcpv6_listeners t))
                 ~udp:(Udpv6.input t.udpv6
                         ~listeners:(udpv6_listeners t))
                 ~default:(fun ~proto:_ ~src:_ ~dst:_ _ -> return_unit))
        t.ethif)

  let connect id =
    let { V1_LWT.console = c; interface = netif; mode; _ } = id in
    let or_error fn t err =
      fn t
      >>= function
      | `Error _ -> fail (Failure err)
      | `Ok r -> return r
    in
    Console.log_s c "Manager: connect"
    >>= fun () ->
    or_error Ethif.connect netif "ethif"
    >>= fun ethif ->
    or_error Ipv4.connect ethif "ipv4"
    >>= fun ipv4 ->
    or_error Udpv4.connect ipv4 "udpv4"
    >>= fun udpv4 ->
    or_error Tcpv4.connect ipv4 "tcpv4"
    >>= fun tcpv4 ->
    or_error Ipv6.connect ethif "ipv6"
    >>= fun ipv6 ->
    or_error Udpv6.connect ipv6 "udpv6"
    >>= fun udpv6 ->
    or_error Tcpv6.connect ipv6 "tcpv6"
    >>= fun tcpv6 ->
    let udpv4_listeners = Hashtbl.create 7 in
    let tcpv4_listeners = Hashtbl.create 7 in
    let udpv6_listeners = Hashtbl.create 7 in
    let tcpv6_listeners = Hashtbl.create 7 in
    let t = { id; c; mode; netif; ethif; ipv4; tcpv4; udpv4; ipv6; tcpv6; udpv6;
              udpv4_listeners; tcpv4_listeners; udpv6_listeners; tcpv6_listeners } in
    Console.log_s t.c "Manager: configuring"
    >>= fun () ->
    let _ = listen t in
    configure t t.mode
    >>= fun () ->
    (* TODO: this is fine for now, because the DHCP state machine isn't fully
       implemented and its thread will terminate after one successful lease
       transaction.  For a DHCP thread that runs forever, `configure` will need
       to spawn a background thread, but we need to consider how to inform the
       application stack that the IP address has changed (perhaps via a control
       Lwt_stream that the application can ignore if it doesn't care). *)
    Console.log_s t.c "Manager: configuration done"
    >>= fun () ->
    return (`Ok t)

  let disconnect t =
    (* TODO: kill the listening thread *)
    Console.log_s t.c "Manager: disconnect"
end
