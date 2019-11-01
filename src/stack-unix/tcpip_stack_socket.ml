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

open Lwt.Infix

let src = Logs.Src.create "tcpip-stack-socket" ~doc:"Platform's native TCP/IP stack"
module Log = (val Logs.src_log src : Logs.LOG)

type socket_ipv4_input = unit Lwt.t

module type UDPV4_SOCKET = Mirage_protocols.UDP
  with type ipinput = socket_ipv4_input

module type TCPV4_SOCKET = Mirage_protocols.TCP
  with type ipinput = socket_ipv4_input

module Tcpv4 = Tcpv4_socket
module Udpv4 = Udpv4_socket

module TCPV4 = Tcpv4_socket
module UDPV4 = Udpv4_socket
module IPV4  = Ipv4_socket

type t = {
  udpv4 : Udpv4.t;
  tcpv4 : Tcpv4.t;
}

let udpv4 { udpv4; _ } = udpv4
let tcpv4 { tcpv4; _ } = tcpv4
let ipv4 _ = None

(* List of IP addresses to bind to *)
let configure _t addrs =
  match addrs with
  | [] -> Lwt.return_unit
  | [ip] when (Ipaddr.V4.compare Ipaddr.V4.any ip) = 0 -> Lwt.return_unit
  | l ->
    let pp_iplist fmt l = Format.pp_print_list Ipaddr.V4.pp fmt l in
    Log.warn (fun f -> f
              "Manager: sockets currently bind to all available IPs. IPs %a were specified, but this will be ignored" pp_iplist l);
    Lwt.return_unit

let err_invalid_port p = Printf.sprintf "invalid port number (%d)" p

let listen_udpv4 t ~port callback =
  if port < 0 || port > 65535 then
    raise (Invalid_argument (err_invalid_port port))
  else
    (* FIXME: we should not ignore the result *)
    Lwt.async (fun () ->
      Udpv4.get_udpv4_listening_fd t.udpv4 port >>= fun fd ->
      let buf = Cstruct.create 4096 in
      let rec loop () =
        (* TODO cancellation *)
        Lwt.catch (fun () ->
            Lwt_cstruct.recvfrom fd buf [] >>= fun (len, sa) ->
            let buf = Cstruct.sub buf 0 len in
            (match sa with
             | Lwt_unix.ADDR_INET (addr, src_port) ->
               let src = Ipaddr_unix.V4.of_inet_addr_exn addr in
               let dst = Ipaddr.V4.any in (* TODO *)
               callback ~src ~dst ~src_port buf
             | _ -> Lwt.return_unit))
          (fun exn ->
             Log.warn (fun m -> m "exception %s in recvfrom" (Printexc.to_string exn)) ;
             Lwt.return_unit) >>= fun () ->
        loop ()
      in
      loop ())

let listen_tcpv4 ?keepalive _t ~port callback =
  if port < 0 || port > 65535 then
    raise (Invalid_argument (err_invalid_port port))
  else
    let fd = Lwt_unix.(socket PF_INET SOCK_STREAM 0) in
    Lwt_unix.setsockopt fd Lwt_unix.SO_REUSEADDR true;
    (* TODO: as elsewhere in the module, we bind all available addresses; it would be better not to do so if the user has requested it *)
    let interface = Ipaddr_unix.V4.to_inet_addr Ipaddr.V4.any in
    (* FIXME: we should not ignore the result *)
    Lwt.async (fun () ->
      Lwt_unix.bind fd (Lwt_unix.ADDR_INET (interface, port)) >>= fun () ->
      Lwt_unix.listen fd 10;
      (* TODO cancellation *)
      let rec loop () =
        Lwt.catch (fun () ->
            Lwt_unix.accept fd >|= fun (afd, _) ->
            (match keepalive with
             | None -> ()
             | Some { Mirage_protocols.Keepalive.after; interval; probes } ->
               Tcp_socket_options.enable_keepalive ~fd:afd ~after ~interval ~probes);
            Lwt.async
              (fun () ->
                 Lwt.catch
                   (fun () -> callback afd)
                   (fun exn ->
                      Log.warn (fun m -> m "error %s in callback" (Printexc.to_string exn)) ;
                      Lwt.return_unit)))
          (fun exn ->
             Log.warn (fun m -> m "error %s in accept" (Printexc.to_string exn)) ;
             Lwt.return_unit) >>= fun () ->
        loop ()
      in
      loop ())

let listen _t =
  let t, _ = Lwt.task () in
  t (* TODO cancellation *)

let connect ips udpv4 tcpv4 =
  Log.info (fun f -> f "Manager: connect");
  let t = { tcpv4; udpv4 } in
  Log.info (fun f -> f "Manager: configuring");
  configure t ips >|= fun () ->
  t

let disconnect _ = Lwt.return_unit
