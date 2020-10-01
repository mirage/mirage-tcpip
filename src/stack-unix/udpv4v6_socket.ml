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

let any_v6 = Ipaddr_unix.V6.to_inet_addr Ipaddr.V6.unspecified

type t = {
  interface: [ `Any | `Ip of Unix.inet_addr * Unix.inet_addr | `V4_only of Unix.inet_addr | `V6_only of Unix.inet_addr ]; (* source ip to bind to *)
  listen_fds: (int,Lwt_unix.file_descr * Lwt_unix.file_descr option) Hashtbl.t; (* UDP fds bound to a particular port *)
}

let get_udpv4v6_listening_fd {listen_fds;interface} port =
  try
    Lwt.return
      (match Hashtbl.find listen_fds port with
       | fd, None -> [ fd ]
       | fd, Some fd' -> [ fd ; fd' ])
  with Not_found ->
    (match interface with
     | `Any ->
       let fd = Lwt_unix.(socket PF_INET6 SOCK_DGRAM 0) in
       Lwt_unix.(setsockopt fd IPV6_ONLY false);
       Lwt_unix.bind fd (Lwt_unix.ADDR_INET (any_v6, port)) >|= fun () ->
       ((fd, None), [ fd ])
     | `Ip (v4, v6) ->
       let fd = Lwt_unix.(socket PF_INET SOCK_DGRAM 0) in
       Lwt_unix.bind fd (Lwt_unix.ADDR_INET (v4, port)) >>= fun () ->
       let fd' = Lwt_unix.(socket PF_INET6 SOCK_DGRAM 0) in
       Lwt_unix.(setsockopt fd' IPV6_ONLY true);
       Lwt_unix.bind fd' (Lwt_unix.ADDR_INET (v6, port)) >|= fun () ->
       ((fd, Some fd'), [ fd ; fd' ])
     | `V4_only ip ->
       let fd = Lwt_unix.(socket PF_INET SOCK_DGRAM 0) in
       Lwt_unix.bind fd (Lwt_unix.ADDR_INET (ip, port)) >|= fun () ->
       ((fd, None), [ fd ])
     | `V6_only ip ->
       let fd = Lwt_unix.(socket PF_INET6 SOCK_DGRAM 0) in
       Lwt_unix.bind fd (Lwt_unix.ADDR_INET (ip, port)) >|= fun () ->
       ((fd, None), [ fd ])) >|= fun (fds, r) ->
    Hashtbl.add listen_fds port fds;
    r


type error = [`Sendto_failed | `Different_ip_version]

let pp_error ppf = function
  | `Sendto_failed -> Fmt.pf ppf "sendto failed to write any bytes"
  | `Different_ip_version ->
    Fmt.string ppf "attempting to send to a destination with a different IP protocol version"

let connect ~ipv4_only ~ipv6_only ipv4 ipv6 =
  let v4 = Ipaddr.V4.Prefix.address ipv4 in
  let v4_unix = Ipaddr_unix.V4.to_inet_addr v4 in
  let interface =
    if ipv4_only then
      `V4_only v4_unix
    else if ipv6_only then
      `V6_only (
        match ipv6 with
        | None -> any_v6
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
  let listen_fds = Hashtbl.create 7 in
  Lwt.return { interface; listen_fds }

let disconnect _ = Lwt.return_unit

let input ~listeners:_ _ = Lwt.return_unit

let create_socket t ?port dst =
  let bind fd proj dfl =
    let p = match port with None -> 0 | Some p -> p in
    match t.interface, port with
    | `Any, None -> Lwt.return_unit
    | `Any, Some p -> Lwt_unix.bind fd (Lwt_unix.ADDR_INET (dfl, p))
    | `Ip ip, _ -> Lwt_unix.bind fd (Lwt_unix.ADDR_INET (proj ip, p))
    | `V4_only ip, _ -> Lwt_unix.bind fd (Lwt_unix.ADDR_INET (ip, p))
    | `V6_only ip, _ -> Lwt_unix.bind fd (Lwt_unix.ADDR_INET (ip, p))
  in
  match dst, t.interface with
  | Ipaddr.V4 _, (`Any | `Ip _ | `V4_only _) ->
    let fd = Lwt_unix.(socket PF_INET SOCK_DGRAM 0) in
    bind fd fst (Ipaddr_unix.V4.to_inet_addr Ipaddr.V4.any) >|= fun () ->
    Ok fd
  | Ipaddr.V6 _, (`Any | `Ip _ | `V6_only _) ->
    let fd = Lwt_unix.(socket PF_INET6 SOCK_DGRAM 0) in
    Lwt_unix.(setsockopt fd IPV6_ONLY true);
    bind fd snd any_v6 >|= fun () ->
    Ok fd
  | _ -> Lwt.return (Error `Different_ip_version)

let write ?src:_ ?src_port ?ttl:_ttl ~dst ~dst_port t buf =
  let open Lwt_unix in
  let rec write_to_fd fd buf =
    Lwt_cstruct.sendto fd buf [] (ADDR_INET ((Ipaddr_unix.to_inet_addr dst), dst_port))
    >>= function
    | n when n = Cstruct.len buf -> Lwt.return @@ Ok ()
    | 0 -> Lwt.return @@ Error `Sendto_failed
    | n -> write_to_fd fd (Cstruct.sub buf n (Cstruct.len buf - n)) (* keep trying *)
  in
  create_socket t ?port:src_port dst >>= function
  | Error e -> Lwt.return (Error e)
  | Ok fd ->
    write_to_fd fd buf >>= fun r ->
    Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit) >|= fun () ->
    r
