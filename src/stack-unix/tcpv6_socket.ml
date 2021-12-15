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

let src = Logs.Src.create "tcpv6-socket" ~doc:"TCP socket v6 (platform native)"
module Log = (val Logs.src_log src : Logs.LOG)

open Lwt.Infix

type ipaddr = Ipaddr.V6.t
type flow = Lwt_unix.file_descr

type t = {
  interface: Unix.inet_addr;    (* source ip to bind to *)
  mutable active_connections : Lwt_unix.file_descr list;
  listen_sockets : (int, Lwt_unix.file_descr) Hashtbl.t;
  mutable switched_off : unit Lwt.t;
}

let set_switched_off t switched_off =
  t.switched_off <- Lwt.pick [ switched_off;  t.switched_off ]

include Tcp_socket

let connect addr =
  let ip =
    match addr with
    | None -> Ipaddr.V6.unspecified
    | Some ip -> Ipaddr.V6.Prefix.address ip
  in
  Lwt.return {
    interface = Ipaddr_unix.V6.to_inet_addr ip;
    active_connections = [];
    listen_sockets = Hashtbl.create 7;
    switched_off = fst (Lwt.wait ())
  }

let disconnect t =
  Lwt_list.iter_p close t.active_connections >>= fun () ->
  Lwt_list.iter_p close
    (Hashtbl.fold (fun _ fd acc -> fd :: acc) t.listen_sockets []) >>= fun () ->
  Lwt.cancel t.switched_off ; Lwt.return_unit

let dst fd =
  match Lwt_unix.getpeername fd with
  | Unix.ADDR_UNIX _ ->
    raise (Failure "unexpected: got a unix instead of tcp sock")
  | Unix.ADDR_INET (ia,port) -> begin
      match Ipaddr_unix.V6.of_inet_addr ia with
      | None -> raise (Failure "got a ipv4 sock instead of a tcpv6 one")
      | Some ip -> ip,port
    end

let create_connection ?keepalive t (dst,dst_port) =
  let fd = Lwt_unix.(socket PF_INET6 SOCK_STREAM 0) in
  Lwt_unix.(setsockopt fd IPV6_ONLY true);
  Lwt.catch (fun () ->
      Lwt_unix.bind fd (Lwt_unix.ADDR_INET (t.interface, 0)) >>= fun () ->
      Lwt_unix.connect fd
        (Lwt_unix.ADDR_INET ((Ipaddr_unix.V6.to_inet_addr dst), dst_port))
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
  | Some fd ->
    Hashtbl.remove t.listen_sockets port;
    try Unix.close (Lwt_unix.unix_file_descr fd) with _ -> ()

let listen t ~port ?keepalive callback =
  if port < 0 || port > 65535 then
    raise (Invalid_argument (Printf.sprintf "invalid port number (%d)" port));
  unlisten t ~port;
  let fd = Lwt_unix.(socket PF_INET6 SOCK_STREAM 0) in
  Lwt_unix.setsockopt fd Lwt_unix.SO_REUSEADDR true;
  Lwt_unix.(setsockopt fd IPV6_ONLY true);
  Unix.bind (Lwt_unix.unix_file_descr fd) (Lwt_unix.ADDR_INET (t.interface, port));
  Hashtbl.replace t.listen_sockets port fd;
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
      Lwt.catch loop ignore_canceled >>= fun () -> close fd)
