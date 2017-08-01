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

let src = Logs.Src.create "tcpip-stack-socket" ~doc:"Platform's native TCP/IP stack"
module Log = (val Logs.src_log src : Logs.LOG)

type socket_ipv4_input = unit Lwt.t

module type UDPV4_SOCKET = Mirage_protocols_lwt.UDP
  with type ipinput = socket_ipv4_input
   and type ip = Ipaddr.V4.t option

module type TCPV4_SOCKET = Mirage_protocols_lwt.TCP
  with type ipinput = socket_ipv4_input
   and type ip = Ipaddr.V4.t option

module Tcpv4 = Tcpv4_socket
module Udpv4 = Udpv4_socket

type +'a io = 'a Lwt.t
type 'a config = 'a Mirage_stack_lwt.stackv4_config
type netif = Ipaddr.V4.t list
type id = netif config
type buffer = Cstruct.t
type ipv4addr = Ipaddr.V4.t

module TCPV4 = Tcpv4_socket
module UDPV4 = Udpv4_socket
module IPV4  = Ipv4_socket

type udpv4 = Udpv4_socket.t
type tcpv4 = Tcpv4_socket.t
type ipv4  = Ipaddr.V4.t option

type t = {
  id    : id;
  udpv4 : Udpv4.t;
  tcpv4 : Tcpv4.t;
  udpv4_listeners: (int, Udpv4.callback) Hashtbl.t;
  tcpv4_listeners: (int, (Tcpv4.flow -> unit Lwt.t)) Hashtbl.t;
}

let udpv4 { udpv4; _ } = udpv4
let tcpv4 { tcpv4; _ } = tcpv4
let ipv4 _ = None

(* List of IP addresses to bind to *)
let configure _t addrs =
  match addrs with
  | [] -> return_unit
  | [ip] when (Ipaddr.V4.compare Ipaddr.V4.any ip) = 0 -> return_unit
  | l ->
    let pp_iplist fmt l = Format.pp_print_list Ipaddr.V4.pp_hum fmt l in
    Log.warn (fun f -> f
              "Manager: sockets currently bind to all available IPs. IPs %a were specified, but this will be ignored" pp_iplist l);
    return_unit

let err_invalid_port p = Printf.sprintf "invalid port number (%d)" p

let listen_udpv4 t ~port callback =
  if port < 0 || port > 65535 then
    raise (Invalid_argument (err_invalid_port port))
  else
    (* FIXME: we should not ignore the result *)
    ignore_result (
      Udpv4.get_udpv4_listening_fd t.udpv4 port
      >>= fun fd ->
      let buf = Cstruct.create 4096 in
      let rec loop () =
        let continue () =
          (* TODO cancellation *)
          if true then loop () else return_unit in
        Lwt_cstruct.recvfrom fd buf []
        >>= fun (len, sa) ->
        let buf = Cstruct.sub buf 0 len in
        begin match sa with
              | Lwt_unix.ADDR_INET (addr, src_port) ->
                 let src = Ipaddr_unix.V4.of_inet_addr_exn addr in
                 let dst = Ipaddr.V4.any in (* TODO *)
                 callback ~src ~dst ~src_port buf
              | _ -> return_unit
        end >>= fun () ->
        continue ()
      in
      loop ()
    )

let listen_tcpv4 _t ~port callback =
  if port < 0 || port > 65535 then
    raise (Invalid_argument (err_invalid_port port))
  else
    let fd = Lwt_unix.(socket PF_INET SOCK_STREAM 0) in
    Lwt_unix.setsockopt fd Lwt_unix.SO_REUSEADDR true;
    (* TODO: as elsewhere in the module, we bind all available addresses; it would be better not to do so if the user has requested it *)
    let interface = Ipaddr_unix.V4.to_inet_addr Ipaddr.V4.any in
    (* FIXME: we should not ignore the result *)
    ignore_result (
      Lwt_unix.bind fd (Lwt_unix.ADDR_INET (interface, port))
      >>= fun () ->
      Lwt_unix.listen fd 10;
      let rec loop () =
        let continue () =
          (* TODO cancellation *)
          if true then loop () else return_unit in
        Lwt_unix.accept fd
        >>= fun (afd, _) ->
        Lwt.async (fun () ->
                   Lwt.catch
                     (fun () -> callback afd)
                     (fun _ -> return_unit)
                  );
        return_unit
        >>= fun () ->
        continue () in
      loop ()
    )

let listen _t =
  let t, _ = Lwt.task () in
  t (* TODO cancellation *)

let connect id udpv4 tcpv4 =
  let { Mirage_stack_lwt.interface; _ } = id in
  Log.info (fun f -> f "Manager: connect");
  let udpv4_listeners = Hashtbl.create 7 in
  let tcpv4_listeners = Hashtbl.create 7 in
  let t = { id; tcpv4; udpv4; udpv4_listeners; tcpv4_listeners } in
  Log.info (fun f -> f "Manager: configuring");
  configure t interface
  >>= fun () ->
  return t

let disconnect _ = return_unit
