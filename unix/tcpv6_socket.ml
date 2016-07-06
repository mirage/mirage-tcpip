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
type ip = Ipaddr.V6.t option (* interface *)
type ipinput = unit io
type callback = flow -> unit io

type t = {
  interface: Unix.inet_addr option;    (* source ip to bind to *)
}

(** IO operation errors *)
type error = [
  | `Unknown of string (** an undiagnosed error *)
  | `Timeout
  | `Refused
]

let error_message = function
  | `Unknown msg -> msg
  | `Timeout -> "Timeout while attempting to connect"
  | `Refused -> "Connection refused"

let connect addr =
  let t =
    match addr with
    | None -> { interface=None }
    | Some ip -> { interface=Some (Ipaddr_unix.V6.to_inet_addr ip) }
  in
  return (`Ok t)

let disconnect _ =
  return_unit

let dst fd =
  match Lwt_unix.getpeername fd with
  | Unix.ADDR_UNIX _ ->
    raise (Failure "unexpected: got a unix instead of tcp sock")
  | Unix.ADDR_INET (ia,port) -> begin
      match Ipaddr_unix.V6.of_inet_addr ia with
      | None -> raise (Failure "got a ipv4 sock instead of a tcpv6 one")
      | Some ip -> ip,port
    end

let create_connection _t (dst,dst_port) =
  let fd = Lwt_unix.socket Lwt_unix.PF_INET6 Lwt_unix.SOCK_STREAM 0 in
  Lwt.catch (fun () ->
      Lwt_unix.connect fd
        (Lwt_unix.ADDR_INET ((Ipaddr_unix.V6.to_inet_addr dst), dst_port))
      >>= fun () ->
      return (`Ok fd))
    (fun exn -> return (`Error (`Unknown (Printexc.to_string exn))))

let read fd =
  let buflen = 4096 in
  let buf = Cstruct.create buflen in
  Lwt.catch (fun () ->
      Lwt_cstruct.read fd buf
      >>= function
      | 0 -> return `Eof
      | n when n = buflen -> return (`Ok buf)
      | n -> return (`Ok (Cstruct.sub buf 0 n)))
    (fun exn -> return (`Error (`Unknown (Printexc.to_string exn))))

let rec write fd buf =
  Lwt.catch
    (fun () ->
      Lwt_cstruct.write fd buf
      >>= function
      | n when n = Cstruct.len buf -> return (`Ok ())
      | 0 -> return `Eof
      | n -> write fd (Cstruct.sub buf n (Cstruct.len buf - n))
    ) (function
      | Unix.Unix_error(Unix.EPIPE, _, _) -> return `Eof
      | e -> Lwt.fail e)

let writev fd bufs =
  Lwt_list.fold_left_s
    (fun res buf ->
       match res with
       |`Error _ as e -> return e
       |`Eof as e -> return e
       |`Ok () -> write fd buf
    ) (`Ok ()) bufs

(* TODO make nodelay a flow option *)
let write_nodelay fd buf =
  write fd buf
  >>= fun _ -> return_unit

(* TODO make nodelay a flow option *)
let writev_nodelay fd bufs =
  writev fd bufs
  >>= fun _ -> return_unit

let close fd =
  Lwt_unix.close fd

(* FIXME: how does this work at all ?? *)
let input _t ~listeners:_ =
  (* TODO terminate when signalled by disconnect *)
  let t, _ = Lwt.task () in
  t
