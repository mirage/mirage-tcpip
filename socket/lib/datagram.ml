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

(* UDP channel that uses the UNIX runtime to retrieve fds *)

open Nettypes
open Lwt
open OS

exception Error of string

module UDPv4 = struct
  type mgr = Manager.t
  type src = ipv4_addr option * int
  type dst = ipv4_addr * int

  type msg = Cstruct.t

  let rec send mgr ?src (dstaddr, dstport) buf =
    lwt fd = match src with
      |None -> return (Manager.get_udpv4 mgr)
      |Some src -> Manager.get_udpv4_listener mgr src
    in
    let dst = Unix.ADDR_INET (dstaddr, dstport) in
    (* TODO check short write *)
    lwt _ = Lwt_cstruct.sendto fd buf [] dst in
    return ()

  let recv mgr (addr,port) fn =
    lwt lfd = Manager.get_udpv4_listener mgr (addr,port) in
    let buf = Cstruct.of_bigarray (OS.Io_page.get 1) in
    let rec listen () =
      lwt (len, frm_sa) = Lwt_cstruct.recvfrom lfd buf [] in
      let frm_addr, frm_port =
        match frm_sa with
        |Unix.ADDR_UNIX x -> ipv4_localhost, 0
        |Unix.ADDR_INET (addr, port) -> (* XXX TODO *) ipv4_localhost, port 
      in
      let dst = (frm_addr, frm_port) in
      let req = Cstruct.sub buf 0 len in
      (* Be careful to catch an exception here, as otherwise
         ignore_result may raise it at some other random point *)
      Lwt.ignore_result (
        try_lwt
          fn dst req
        with exn ->
          return (Printf.printf "EXN: %s\n%!" (Printexc.to_string exn))
      );
      listen ()
    in 
    listen ()
end
