(*
 * Copyright (c) 2010-2011 Anil Madhavapeddy <anil@recoil.org>
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

(* TCP channel that uses the UNIX runtime to retrieve fds *)

open Nettypes
open Lwt
open OS

exception Listen_error of string
exception Accept_error of string
exception Connect_error of string
exception Read_error of string
exception Write_error of string

let close fd = Lwt_unix.close fd

let close_on_exit t fn =
  try_lwt 
    lwt x = fn t in
    close t >>
    return x
  with exn -> 
    close t >>
    fail exn

let listen_tcpv4 addr port fn =
  let open Lwt_unix in
  let fd = socket PF_INET SOCK_STREAM 0 in
  let _ = setsockopt fd SO_REUSEADDR true in 
  bind fd (ADDR_INET (inet_addr_of_ipaddr addr,port));
  listen fd 10;
  (* XXX use accept_n *)
  while_lwt true do
    lwt (afd, asa) = accept fd in
    let caddr, cport = match asa with
      |ADDR_INET (x,y) -> ipaddr_of_inet_addr x,y |_ -> assert false in
    Lwt.ignore_result (
      close_on_exit afd (fun t ->
        try_lwt
          fn (caddr, cport) t
        with exn ->
          return (Printf.printf "EXN: %s\n%!" (Printexc.to_string exn))
      )
    );
    return ()
  done

(* Read a buffer off the wire *)
let rec read_buf fd buf =
  Lwt_cstruct.read fd buf

let rec write_buf fd buf =
  let len = Cstruct.len buf in
  lwt amt = Lwt_cstruct.write fd buf in
  if amt = len then return () else write_buf fd (Cstruct.shift buf amt)

let read t =
  let buf = Cstruct.of_bigarray (OS.Io_page.get 1) in
  lwt len = read_buf t buf in
  match len with
  |0 -> return None
  |len -> return (Some (Cstruct.sub buf 0 len))

let write t bs =
  write_buf t bs

(* TODO use writev: but do a set of writes for now *)
let writev t pages =
  Lwt_list.iter_s (write t) pages
 
module TCPv4 = struct
  type t = Lwt_unix.file_descr
  type mgr = Manager.t
  type src = Ipaddr.V4.t option * int
  type dst = Ipaddr.V4.t * int

  (* TODO put an istring pool in the manager? *)

  let read = read
  let writev = writev
  let close = close
  let write = write

  let listen mgr src fn =
    let addr, port = match src with
      |None, port -> Ipaddr.V4.any, port
      |Some addr, port -> addr, port in
    listen_tcpv4 addr port fn

  let connect mgr ?src ((addr,port):ipv4_dst) (fn: t -> 'a Lwt.t) =
    let open Lwt_unix in
    let fd = socket PF_INET SOCK_STREAM 0 in
    lwt () = connect fd (ADDR_INET (inet_addr_of_ipaddr addr,port)) in
    (* Wait for the connect to complete *)
    fn fd
end

type t =
  | TCPv4 of TCPv4.t

type mgr = Manager.t

let read = function
  | TCPv4 t -> TCPv4.read t

let write = function
  | TCPv4 t -> TCPv4.write t

let writev = function
  | TCPv4 t -> TCPv4.writev t

let close = function
  | TCPv4 t -> TCPv4.close t

let connect mgr = function
  |`TCPv4 (src, dst, fn) ->
     TCPv4.connect mgr ?src dst (fun t -> fn (TCPv4 t))
  |_ -> fail (Failure "unknown protocol")

let listen mgr = function
  |`TCPv4 (src, fn) ->
     TCPv4.listen mgr src (fun dst t -> fn dst (TCPv4 t))
  |_ -> fail (Failure "unknown protocol")

