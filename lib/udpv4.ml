(*
 * Copyright (c) 2010-2014 Anil Madhavapeddy <anil@recoil.org>
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
open Printf
open Wire_structs

module Make(Ipv4: V1_LWT.IPV4) = struct

  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t
  type ipv4 = Ipv4.t
  type ipv4addr = Ipaddr.V4.t
  type ipv4input = src:ipv4addr -> dst:ipv4addr -> buffer -> unit io
  type callback = src:Ipaddr.V4.t -> dst:Ipaddr.V4.t -> src_port:int -> Cstruct.t -> unit Lwt.t

  (** IO operation errors *)
  type error = [
    | `Unknown of string (** an undiagnosed error *)
  ]

  type t = {
    ip : Ipv4.t;
  }

  let id {ip} = ip

  let input ~listeners t ~src ~dst buf =
    let dst_port = get_udpv4_dest_port buf in
    let data = Cstruct.sub buf sizeof_udpv4 (get_udpv4_length buf - sizeof_udpv4) in
    match listeners ~dst_port with
    | None -> return ()
    | Some fn ->
      let src_port = get_udpv4_source_port buf in
      fn ~src ~dst ~src_port data

  let writev ?source_port ~dest_ip ~dest_port t bufs =
    begin match source_port with
      | None -> fail (Failure "TODO; random source port")
      | Some p -> return p
    end >>= fun source_port ->
    Ipv4.allocate_frame ~proto:`UDP ~dest_ip t.ip
    >>= fun (ipv4_frame, ipv4_len) ->
    let udp_buf = Cstruct.shift ipv4_frame ipv4_len in
    set_udpv4_source_port udp_buf source_port;
    set_udpv4_dest_port udp_buf dest_port;
    set_udpv4_checksum udp_buf 0;
    set_udpv4_length udp_buf (sizeof_udpv4 + Cstruct.lenv bufs);
    let ipv4_frame = Cstruct.set_len ipv4_frame (ipv4_len + sizeof_udpv4) in
    Ipv4.writev t.ip ipv4_frame bufs

  let write ?source_port ~dest_ip ~dest_port t buf =
    writev ?source_port ~dest_ip ~dest_port t [buf]

  let connect ip =
    return (`Ok { ip })

  let disconnect ip = return ()
end
