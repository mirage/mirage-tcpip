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

module Tcpv4 = Tcpv4_socket
module Udpv4 = Udpv4_socket

module Make(Console:V1_LWT.CONSOLE) = struct
  type +'a io = 'a Lwt.t
  type ('a,'b,'c) config = ('a,'b,'c) V1_LWT.stackv4_config
  type console = Console.t
  type netif = Ipaddr.V4.t list
  type mode = unit
  type id = (console, netif, mode) config
  type buffer = Cstruct.t
  type ipv4addr = Ipaddr.V4.t

  module TCPV4 = Tcpv4_socket
  module UDPV4 = Udpv4_socket

  type udpv4 = Udpv4_socket.t
  type tcpv4 = Tcpv4_socket.t

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
  let udpv4 {udpv4} = udpv4
  let tcpv4 {tcpv4} = tcpv4

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

  let listen_udpv4 t ~port callback =
    let fd = Udpv4.get_udpv4_listening_fd t.udpv4 port in
    let buf = Cstruct.create 4096 in
    let _t = 
      while_lwt true do (* TODO cancellation *)
        Lwt_cstruct.recvfrom fd buf []
        >>= fun (len, sa) ->
        let buf = Cstruct.sub buf 0 len in
        match sa with
        | Lwt_unix.ADDR_INET (addr, src_port) ->
          let src = Ipaddr_unix.V4.of_inet_addr_exn addr in
          let dst = Ipaddr.V4.any in (* TODO *)
          ignore_result (callback ~src ~dst ~src_port buf);
          return ()
        | _ -> return ()
      done
    in
    ()

  let listen_tcpv4 t ~port callback =
    let open Lwt_unix in
    let fd = socket PF_INET SOCK_STREAM 0 in
    let interface = Ipaddr_unix.V4.to_inet_addr Ipaddr.V4.any in (* TODO *)
    bind fd (ADDR_INET (interface, port));
    listen fd 10;
    let _t = 
      while_lwt true do (* TODO cancellation *)
        Lwt_unix.accept fd
        >>= fun (afd, sa) ->
        ignore_result (callback afd >>= fun () -> return_unit);
        return ();
      done
    in
    ()

  let listen t =
    let t,u = Lwt.task () in
    t (* TODO cancellation *)

  let connect id =
    let {V1_LWT.console = c; interface; mode; name } = id in
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
    configure t interface
    >>= fun () ->
    return (`Ok t)

  let disconnect t =
    return ()
end
