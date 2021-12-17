(*
 * Copyright (c) 2014 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (c) 2014 Nicolas Ojeda Bar <n.oje.bar@gmail.com>
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

let src = Logs.Src.create "tcpv4v6-socket" ~doc:"TCP socket v4v6 (platform native)"
module Log = (val Logs.src_log src : Logs.LOG)

open Lwt.Infix

type ipaddr = Ipaddr.t
type flow = Lwt_unix.file_descr

type t = {
  interface: [ `Any | `Ip of Unix.inet_addr * Unix.inet_addr | `V4_only of Unix.inet_addr | `V6_only of Unix.inet_addr ];    (* source ip to bind to *)
  mutable active_connections : Lwt_unix.file_descr list;
  listen_sockets : (int, Lwt_unix.file_descr list) Hashtbl.t;
  mutable switched_off : unit Lwt.t;
}

let set_switched_off t switched_off =
  t.switched_off <- Lwt.pick [ switched_off; t.switched_off ]

let any_v6 = Ipaddr_unix.V6.to_inet_addr Ipaddr.V6.unspecified

include Tcp_socket

let connect ~ipv4_only ~ipv6_only ipv4 ipv6 =
  let interface =
    let v4 = Ipaddr.V4.Prefix.address ipv4 in
    let v4_unix = Ipaddr_unix.V4.to_inet_addr v4 in
    if ipv4_only then
      `V4_only v4_unix
    else if ipv6_only then
      `V6_only (match ipv6 with
          | None ->  any_v6
          | Some x -> Ipaddr_unix.V6.to_inet_addr (Ipaddr.V6.Prefix.address x))
    else
      match ipv6, Ipaddr.V4.(compare v4 any) with
      | None, 0 -> `Any
      | None, _ -> `Ip (v4_unix, any_v6)
      | Some x, v4_any ->
        let v6 = Ipaddr.V6.Prefix.address x in
        if Ipaddr.V6.(compare v6 unspecified = 0) && v4_any = 0 then
          `Any
        else
          `Ip (v4_unix, Ipaddr_unix.V6.to_inet_addr v6)
  in
  Lwt.return {interface; active_connections = []; listen_sockets = Hashtbl.create 7; switched_off = fst (Lwt.wait ())}

let disconnect t =
  Lwt_list.iter_p close t.active_connections >>= fun () ->
  Lwt_list.iter_p close
    (Hashtbl.fold (fun _ fd acc -> fd @ acc) t.listen_sockets []) >>= fun () ->
  Lwt.cancel t.switched_off ; Lwt.return_unit

let dst fd =
  match Lwt_unix.getpeername fd with
  | Unix.ADDR_UNIX _ ->
    raise (Failure "unexpected: got a unix instead of tcp sock")
  | Unix.ADDR_INET (ia,port) ->
    let ip = Ipaddr_unix.of_inet_addr ia in
    let ip = match Ipaddr.to_v4 ip with
      | None -> ip
      | Some v4 -> Ipaddr.V4 v4
    in
    ip, port

let create_connection ?keepalive t (dst,dst_port) =
  match
    match dst, t.interface with
    | Ipaddr.V4 _, (`Any | `Ip _ | `V4_only _) -> Ok (Lwt_unix.PF_INET, fst)
    | Ipaddr.V6 _, (`Any | `Ip _ | `V6_only _) -> Ok (Lwt_unix.PF_INET6, snd)
    | Ipaddr.V4 _, `V6_only _ ->
      Error (`Msg "Attempted to connect to an IPv4 host, but stack is IPv6 only")
    | Ipaddr.V6 _, `V4_only _ ->
      Error (`Msg "Attempted to connect to an IPv6 host, but stack is IPv4 only")
  with
  | Error (`Msg m) -> Lwt.return (Error (`Exn (Invalid_argument m)))
  | Ok (family, proj) ->
    let fd = Lwt_unix.(socket family SOCK_STREAM 0) in
    Lwt.catch (fun () ->
        (match t.interface with
         | `Any -> Lwt.return_unit
         | `Ip p -> Lwt_unix.bind fd (Lwt_unix.ADDR_INET (proj p, 0))
         | `V4_only ip -> Lwt_unix.bind fd (Lwt_unix.ADDR_INET (ip, 0))
         | `V6_only ip -> Lwt_unix.bind fd (Lwt_unix.ADDR_INET (ip, 0))) >>= fun () ->
        Lwt_unix.connect fd
          (Lwt_unix.ADDR_INET ((Ipaddr_unix.to_inet_addr dst), dst_port))
        >>= fun () ->
        ( match keepalive with
          | None -> ()
          | Some { Tcpip.Tcp.Keepalive.after; interval; probes } ->
            Tcp_socket_options.enable_keepalive ~fd ~after ~interval ~probes );
        t.active_connections <- fd :: t.active_connections;
        Lwt.return (Ok fd))
      (fun exn ->
         close fd >>= fun () ->
         Lwt.return (Error (`Exn exn)))

let unlisten t ~port =
  match Hashtbl.find_opt t.listen_sockets port with
  | None -> ()
  | Some fds ->
    Hashtbl.remove t.listen_sockets port;
    try List.iter (fun fd -> Unix.close (Lwt_unix.unix_file_descr fd)) fds with _ -> ()

let listen t ~port ?keepalive callback =
  if port < 0 || port > 65535 then
    raise (Invalid_argument (Printf.sprintf "invalid port number (%d)" port));
  unlisten t ~port;
  let fds =
    match t.interface with
    | `Any ->
      let fd = Lwt_unix.(socket PF_INET6 SOCK_STREAM 0) in
      Lwt_unix.(setsockopt fd SO_REUSEADDR true);
      Lwt_unix.(setsockopt fd IPV6_ONLY false);
      [ (fd, Lwt_unix.ADDR_INET (any_v6, port)) ]
    | `Ip (v4, v6) ->
      let fd = Lwt_unix.(socket PF_INET SOCK_STREAM 0) in
      Lwt_unix.(setsockopt fd SO_REUSEADDR true);
      let fd' = Lwt_unix.(socket PF_INET6 SOCK_STREAM 0) in
      Lwt_unix.(setsockopt fd' SO_REUSEADDR true);
      Lwt_unix.(setsockopt fd' IPV6_ONLY true);
      [ (fd, Lwt_unix.ADDR_INET (v4, port)) ; (fd', Lwt_unix.ADDR_INET (v6, port)) ]
    | `V4_only ip ->
      let fd = Lwt_unix.(socket PF_INET SOCK_STREAM 0) in
      Lwt_unix.setsockopt fd Lwt_unix.SO_REUSEADDR true;
      [ (fd, Lwt_unix.ADDR_INET (ip, port)) ]
    | `V6_only ip ->
      let fd = Lwt_unix.(socket PF_INET6 SOCK_STREAM 0) in
      Lwt_unix.(setsockopt fd SO_REUSEADDR true);
      Lwt_unix.(setsockopt fd IPV6_ONLY true);
      [ (fd, Lwt_unix.ADDR_INET (ip, port)) ]
  in
  List.iter (fun (fd, addr) ->
      Unix.bind (Lwt_unix.unix_file_descr fd) addr;
      Hashtbl.replace t.listen_sockets port (List.map fst fds);
      Lwt_unix.listen fd 10;
      (* FIXME: we should not ignore the result *)
      Lwt.async (fun () ->
          (* TODO cancellation *)
          let rec loop () =
            if not (Lwt.is_sleeping t.switched_off) then raise Lwt.Canceled ;
            Lwt.catch (fun () ->
                Lwt_unix.accept fd >|= fun (afd, _) ->
                t.active_connections <- afd :: t.active_connections;
                (match keepalive with
                 | None -> ()
                 | Some { Tcpip.Tcp.Keepalive.after; interval; probes } ->
                   Tcp_socket_options.enable_keepalive ~fd:afd ~after ~interval ~probes);
                Lwt.async
                  (fun () ->
                     Lwt.catch
                       (fun () -> callback afd)
                       (fun exn ->
                          Log.warn (fun m -> m "error %s in callback" (Printexc.to_string exn)) ;
                          close afd));
                `Continue)
              (function
                | Unix.Unix_error (Unix.EBADF, _, _) ->
                  Log.warn (fun m -> m "error bad file descriptor in accept") ;
                  Lwt.return `Stop
                | exn ->
                  Log.warn (fun m -> m "error %s in accept" (Printexc.to_string exn)) ;
                  Lwt.return `Continue) >>= function
            | `Continue -> loop ()
            | `Stop -> Lwt.return_unit
          in
          Lwt.catch loop ignore_canceled >>= fun () -> close fd)) fds
