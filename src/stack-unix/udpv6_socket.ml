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

let src = Logs.Src.create "udpv6-socket" ~doc:"UDP socket v6 (platform native)"
module Log = (val Logs.src_log src : Logs.LOG)

open Lwt.Infix

type ipaddr = Ipaddr.V6.t
type callback = src:ipaddr -> dst:ipaddr -> src_port:int -> Cstruct.t -> unit Lwt.t

type t = {
  interface: Unix.inet_addr; (* source ip to bind to *)
  listen_fds: ((Unix.inet_addr * int),Lwt_unix.file_descr) Hashtbl.t; (* UDPv6 fds bound to a particular source ip/port *)
  mutable switched_off : unit Lwt.t;
}

let set_switched_off t switched_off =
  t.switched_off <- Lwt.pick [ switched_off; t.switched_off ]

let ignore_canceled = function
  | Lwt.Canceled -> Lwt.return_unit
  | exn -> raise exn

let get_udpv6_listening_fd ?(preserve = true) {listen_fds;interface;_} port =
  try
    Lwt.return (false, Hashtbl.find listen_fds (interface,port))
  with Not_found ->
    let fd = Lwt_unix.(socket PF_INET6 SOCK_DGRAM 0) in
    Lwt_unix.(setsockopt fd IPV6_ONLY true);
    Lwt_unix.bind fd (Lwt_unix.ADDR_INET (interface, port)) >|= fun () ->
    if preserve then Hashtbl.add listen_fds (interface, port) fd;
    (true, fd)

type error = [`Sendto_failed]

let pp_error ppf = function
  | `Sendto_failed -> Fmt.pf ppf "sendto failed to write any bytes"

let close fd =
  Lwt.catch
    (fun () -> Lwt_unix.close fd)
    (function
      | Unix.Unix_error (Unix.EBADF, _, _) -> Lwt.return_unit
      | e -> Lwt.fail e)

let connect id =
  let t =
    let listen_fds = Hashtbl.create 7 in
    let interface =
      match id with
      | None -> Ipaddr_unix.V6.to_inet_addr Ipaddr.V6.unspecified
      | Some ip -> Ipaddr_unix.V6.to_inet_addr (Ipaddr.V6.Prefix.address ip)
    in
    { interface; listen_fds; switched_off = fst (Lwt.wait ()) }
  in
  Lwt.return t

let disconnect t =
  Hashtbl.fold (fun _ fd r -> r >>= fun () -> close fd) t.listen_fds Lwt.return_unit >>= fun () ->
  Lwt.cancel t.switched_off ; Lwt.return_unit

let input _t ~src:_ ~dst:_ _buf = Lwt.return_unit

let write ?src:_ ?src_port ?ttl:_ttl ~dst ~dst_port t buf =
  let open Lwt_unix in
  let rec write_to_fd fd buf =
    Lwt.catch (fun () ->
      Lwt_cstruct.sendto fd buf [] (ADDR_INET ((Ipaddr_unix.V6.to_inet_addr dst), dst_port))
      >>= function
      | n when n = Cstruct.length buf -> Lwt.return (Ok ())
      | 0 -> Lwt.return (Error `Sendto_failed)
      | n -> write_to_fd fd (Cstruct.sub buf n (Cstruct.length buf - n))) (* keep trying *)
    (fun _exn -> Lwt.return (Error `Sendto_failed))
  in
  let port = match src_port with None -> 0 | Some x -> x in
  get_udpv6_listening_fd ~preserve:false t port >>= fun (created, fd) ->
  write_to_fd fd buf >>= fun r ->
  (if created then close fd else Lwt.return_unit) >|= fun () ->
  r

let unlisten t ~port =
  try
    let fd = Hashtbl.find t.listen_fds (t.interface, port) in
    Hashtbl.remove t.listen_fds (t.interface, port);
    Unix.close (Lwt_unix.unix_file_descr fd)
  with _ -> ()

let listen t ~port callback =
  if port < 0 || port > 65535 then
    raise (Invalid_argument (Printf.sprintf "invalid port number (%d)" port));
  unlisten t ~port;
  (* FIXME: we should not ignore the result *)
  Lwt.async (fun () ->
      get_udpv6_listening_fd t port >>= fun (_, fd) ->
      let buf = Cstruct.create 4096 in
      let rec loop () =
        if not (Lwt.is_sleeping t.switched_off) then raise Lwt.Canceled ;
        Lwt.catch (fun () ->
            Lwt_cstruct.recvfrom fd buf [] >>= fun (len, sa) ->
            let buf = Cstruct.sub buf 0 len in
            (match sa with
             | Lwt_unix.ADDR_INET (addr, src_port) ->
               let src = Ipaddr_unix.V6.of_inet_addr_exn addr in
               let dst = Ipaddr.V6.unspecified in (* TODO *)
               callback ~src ~dst ~src_port buf
             | _ -> Lwt.return_unit) >|= fun () ->
            `Continue)
          (function
            | Unix.Unix_error (Unix.EBADF, _, _) ->
              Log.warn (fun m -> m "error bad file descriptor in accept") ;
              Lwt.return `Stop
            | exn ->
              Log.warn (fun m -> m "exception %s in recvfrom" (Printexc.to_string exn)) ;
              Lwt.return `Continue) >>= function
        | `Continue -> loop ()
        | `Stop -> Lwt.return_unit
      in
      Lwt.catch loop ignore_canceled >>= fun () -> close fd)
