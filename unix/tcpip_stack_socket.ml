(*
 * Copyright (c) 2014 Anil Madhavapeddy <anil@recoil.org>
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

type socket_ipv4_input = unit Lwt.t

module type UDPV4_SOCKET = V1_LWT.UDPV4
  with type ipv4input = socket_ipv4_input
   and type ipv4 = Ipaddr.V4.t option

module type TCPV4_SOCKET = V1_LWT.TCPV4
  with type ipv4input = socket_ipv4_input
   and type ipv4 = Ipaddr.V4.t option

module Make
    (Console : V1_LWT.CONSOLE)
    (Time    : V1_LWT.TIME)
    (Random  : V1.RANDOM)
    (Udpv4   : UDPV4_SOCKET)
    (Tcpv4   : TCPV4_SOCKET) = struct

  type +'a io = 'a Lwt.t
  type ('a,'b,'c) config = ('a,'b,'c) V1_LWT.stackv4_config
  type console = Console.t
  type netif = Netif.t
  type mode = V1_LWT.socket_stack_config
  type id = (console, netif, mode) config

  type t = {
    id    : id;
    c     : Console.t;
    udpv4 : Udpv4.t;
    tcpv4 : Tcpv4.t;
    udpv4_listeners: (int, Udpv4.callback) Hashtbl.t;
    tcpv4_listeners: (int, (Tcpv4.flow -> unit Lwt.t)) Hashtbl.t;
  }

  type error = [
      `Unknown of string
  ]

  let id {id} = id

  let listen_udpv4 t port callback =
    Hashtbl.replace t.udpv4_listeners port callback

  (* List of IP addresses to bind to *)
  let configure t addrs =
    match addrs with
    | [] -> return ()
    | _ -> Console.log_s t.c "Manager: socket config currently ignored (TODO)"

  let udpv4_listeners t ~dst_port =
    try Some (Hashtbl.find t.udpv4_listeners dst_port)
    with Not_found -> None

  let tcpv4_listeners t dst_port =
    try Some (Hashtbl.find t.tcpv4_listeners dst_port)
    with Not_found -> None

  let listen t =
    return () (* TODO *)

  let connect id =
    let {V1_LWT.console = c; interface = netif; mode; name } = id in
    let or_error fn t err =
      fn t
      >>= function
      | `Error e -> fail (Failure err)
      | `Ok r -> return r
    in
    Console.log_s c "Manager: connect"
    >>= fun () ->
    or_error Udpv4.connect None "udpv4"
    >>= fun udpv4 ->
    or_error Tcpv4.connect None "tcpv4"
    >>= fun tcpv4 ->
    let udpv4_listeners = Hashtbl.create 7 in
    let tcpv4_listeners = Hashtbl.create 7 in
    let t = { id; c; tcpv4; udpv4; udpv4_listeners; tcpv4_listeners } in
    Console.log_s c "Manager: configuring"
    >>= fun () ->
    configure t mode
    >>= fun () ->
    return (`Ok t)

  let disconnect t =
    return ()

end

include Make
    (Console)
    (OS.Time)
    (Random)
    (Udpv4_socket)
    (Tcpv4_socket)

