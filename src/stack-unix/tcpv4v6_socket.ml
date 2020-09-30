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

open Lwt.Infix

type ipaddr = Ipaddr.t
type flow = Lwt_unix.file_descr
type ipinput = unit Lwt.t

type t = {
  interface: Unix.inet_addr option;    (* source ip to bind to *)
}

include Tcp_socket

let connect ipv4 ipv6 =
  let t =
    let interface =
      match ipv4, ipv6 with
      | None, None -> None
      | _, Some ip -> Some (Ipaddr_unix.V6.to_inet_addr ip)
      | Some ip, _ -> Some (Ipaddr_unix.V4.to_inet_addr ip)
    in
    { interface }
  in
  Lwt.return t

let dst fd =
  match Lwt_unix.getpeername fd with
  | Unix.ADDR_UNIX _ ->
    raise (Failure "unexpected: got a unix instead of tcp sock")
  | Unix.ADDR_INET (ia,port) -> Ipaddr_unix.of_inet_addr ia,port

let create_connection ?keepalive _t (dst,dst_port) =
  let family = match dst with
    | Ipaddr.V4 _ -> Lwt_unix.PF_INET
    | Ipaddr.V6 _ -> Lwt_unix.PF_INET6
  in
  let fd = Lwt_unix.(socket family SOCK_STREAM 0) in
  Lwt.catch (fun () ->
      Lwt_unix.connect fd
        (Lwt_unix.ADDR_INET ((Ipaddr_unix.to_inet_addr dst), dst_port))
      >>= fun () ->
      ( match keepalive with
        | None -> ()
        | Some { Mirage_protocols.Keepalive.after; interval; probes } ->
          Tcp_socket_options.enable_keepalive ~fd ~after ~interval ~probes );
      Lwt.return (Ok fd))
    (fun exn ->
       Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit) >>= fun () ->
       Lwt.return (Error (`Exn exn)))
