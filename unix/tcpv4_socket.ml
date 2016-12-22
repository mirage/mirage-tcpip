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
open Result

type buffer = Cstruct.t
type ipaddr = Ipaddr.V4.t
type flow = Lwt_unix.file_descr
type +'a io = 'a Lwt.t
type ip = Ipaddr.V4.t option (* interface *)
type ipinput = unit io
type callback = flow -> unit io

type t = {
  interface: Unix.inet_addr option;    (* source ip to bind to *)
}

include Tcp_socket

let connect id =
  let t =
    match id with
    | None -> { interface=None }
    | Some ip -> { interface=Some (Ipaddr_unix.V4.to_inet_addr ip) }
  in
  return t

let dst fd =
  match Lwt_unix.getpeername fd with
  | Unix.ADDR_UNIX _ ->
    raise (Failure "unexpected: got a unix instead of tcp sock")
  | Unix.ADDR_INET (ia,port) -> begin
      match Ipaddr_unix.V4.of_inet_addr ia with
      | None -> raise (Failure "got a ipv6 sock instead of a tcpv4 one")
      | Some ip -> ip,port
    end

let create_connection _t (dst,dst_port) =
  let fd = Lwt_unix.socket Lwt_unix.PF_INET Lwt_unix.SOCK_STREAM 0 in
  Lwt.catch (fun () ->
      Lwt_unix.connect fd
        (Lwt_unix.ADDR_INET ((Ipaddr_unix.V4.to_inet_addr dst), dst_port))
      >>= fun () ->
      return (Ok fd))
    (fun exn -> return (Error (`Exn exn)))
