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
type ipinput = unit Lwt.t
type callback = src:ipaddr -> dst:ipaddr -> src_port:int -> Cstruct.t -> unit Lwt.t

type t = {
  interface: Unix.inet_addr; (* source ip to bind to *)
  listen_fds: ((Unix.inet_addr * int),Lwt_unix.file_descr) Hashtbl.t; (* UDPv6 fds bound to a particular source ip/port *)
}

let get_udpv4v6_listening_fd {listen_fds;interface} ?dst port =
  try
    Lwt.return @@ Hashtbl.find listen_fds (interface,port)
  with Not_found ->
    let family, sockopt =
      match dst with
      | Some (Ipaddr.V4 _) -> Lwt_unix.PF_INET, false
      | Some (Ipaddr.V6 _) -> Lwt_unix.PF_INET6, false
      | None -> Lwt_unix.PF_INET6, true
    in
    let fd = Lwt_unix.(socket family SOCK_DGRAM 0) in
    if sockopt then Lwt_unix.(setsockopt fd IPV6_ONLY false);
    Lwt_unix.bind fd (Lwt_unix.ADDR_INET (interface, port))
    >>= fun () ->
    Hashtbl.add listen_fds (interface, port) fd;
    Lwt.return fd


type error = [`Sendto_failed]

let pp_error ppf = function
  | `Sendto_failed -> Fmt.pf ppf "sendto failed to write any bytes"

let connect ipv4 ipv6 =
  let t =
    let listen_fds = Hashtbl.create 7 in
    let interface =
      (* TODO handle Some _, Some _ case appropriately? *)
      match ipv4, ipv6 with
      | None, None -> Ipaddr_unix.V6.to_inet_addr Ipaddr.V6.unspecified
      | _, Some ip -> Ipaddr_unix.V6.to_inet_addr ip
      | Some ip, _ -> Ipaddr_unix.V4.to_inet_addr ip
    in { interface; listen_fds }
  in Lwt.return t

let disconnect _ = Lwt.return_unit

let input ~listeners:_ _ = Lwt.return_unit

let write ?src:_ ?src_port ?ttl:_ttl ~dst ~dst_port t buf =
  let open Lwt_unix in
  let rec write_to_fd fd buf =
    Lwt_cstruct.sendto fd buf [] (ADDR_INET ((Ipaddr_unix.to_inet_addr dst), dst_port))
    >>= function
    | n when n = Cstruct.len buf -> Lwt.return @@ Ok ()
    | 0 -> Lwt.return @@ Error `Sendto_failed
    | n -> write_to_fd fd (Cstruct.sub buf n (Cstruct.len buf - n)) (* keep trying *)
  in
  ( match src_port with
    | None -> get_udpv4v6_listening_fd t ~dst 0
    | Some port -> get_udpv4v6_listening_fd t ~dst port )
  >>= fun fd ->
  write_to_fd fd buf
