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
  interface: [ `Any | `Ip of Unix.inet_addr * Unix.inet_addr | `V4_only of Unix.inet_addr | `V6_only of Unix.inet_addr ];    (* source ip to bind to *)
}

include Tcp_socket

let connect ~ipv4_only ~ipv6_only ipv4 ipv6 =
  let interface =
    let v4 = Ipaddr.V4.Prefix.address ipv4 in
    let v4_unix = Ipaddr_unix.V4.to_inet_addr v4 in
    let any_v6 = Ipaddr_unix.V6.to_inet_addr Ipaddr.V6.unspecified in
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
  Lwt.return {interface}

let dst fd =
  match Lwt_unix.getpeername fd with
  | Unix.ADDR_UNIX _ ->
    raise (Failure "unexpected: got a unix instead of tcp sock")
  | Unix.ADDR_INET (ia,port) -> Ipaddr_unix.of_inet_addr ia,port

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
          | Some { Mirage_protocols.Keepalive.after; interval; probes } ->
            Tcp_socket_options.enable_keepalive ~fd ~after ~interval ~probes );
        Lwt.return (Ok fd))
      (fun exn ->
         Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit) >>= fun () ->
         Lwt.return (Error (`Exn exn)))
