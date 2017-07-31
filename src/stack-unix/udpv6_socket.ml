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

open Lwt

type buffer = Cstruct.t
type ipaddr = Ipaddr.V6.t
type flow = Lwt_unix.file_descr
type +'a io = 'a Lwt.t
type ip = Ipaddr.V6.t option (* source ip and port *)
type ipinput = unit Lwt.t
type callback = src:ipaddr -> dst:ipaddr -> src_port:int -> buffer -> unit io

type t = {
  interface: Unix.inet_addr; (* source ip to bind to *)
  listen_fds: ((Unix.inet_addr * int),Lwt_unix.file_descr) Hashtbl.t; (* UDPv6 fds bound to a particular source ip/port *)
}

let get_udpv6_listening_fd {listen_fds;interface} port =
  try
    Lwt.return @@ Hashtbl.find listen_fds (interface,port)
  with Not_found ->
    let fd = Lwt_unix.(socket PF_INET6 SOCK_DGRAM 0) in
    Lwt_unix.bind fd (Lwt_unix.ADDR_INET (interface,port))
    >>= fun () ->
    Hashtbl.add listen_fds (interface,port) fd;
    Lwt.return fd

(** IO operation errors *)
type error = [
  | `Unknown of string (** an undiagnosed error *)
]

let connect (id:ip) =
  let t =
    let listen_fds = Hashtbl.create 7 in
    let interface =
      match id with
      | None -> Ipaddr_unix.V6.to_inet_addr Ipaddr.V6.unspecified
      | Some ip -> Ipaddr_unix.V6.to_inet_addr ip
    in { interface; listen_fds }
  in return t

let disconnect _ =
  return_unit

let id { interface; _ } =
  Some (Ipaddr_unix.V6.of_inet_addr_exn interface)

(* FIXME: how does this work at all ?? *)
 let input ~listeners:_ _ =
  (* TODO terminate when signalled by disconnect *)
  let t, _ = Lwt.task () in
  t

let write ?source_port ~dest_ip ~dest_port t buf =
  let open Lwt_unix in
  ( match source_port with
    | None -> get_udpv6_listening_fd t 0
    | Some port -> get_udpv6_listening_fd t port )
  >>= fun fd ->
  Lwt_cstruct.sendto fd buf [] (ADDR_INET ((Ipaddr_unix.V6.to_inet_addr dest_ip), dest_port))
  >>= fun _ ->
  return_unit
