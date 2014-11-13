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

module Make(Ip: V2_LWT.IP) = struct

  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t
  type ip = Ip.t
  type ipaddr = Ip.ipaddr
  type ipinput = src:ipaddr -> dst:ipaddr -> buffer -> unit io
  type callback = src:ipaddr -> dst:ipaddr -> src_port:int -> Cstruct.t -> unit Lwt.t

  (** IO operation errors *)
  type error = [
    | `Unknown of string (** an undiagnosed error *)
  ]

  type t = {
    ip : Ip.t;
  }

  let id {ip} = ip

  (* FIXME: [t] is not taken into account at all? *)
  let input ~listeners _t ~src ~dst buf =
    let dst_port = Wire_structs.get_udp_dest_port buf in
    let data =
      Cstruct.sub buf Wire_structs.sizeof_udp
        (Wire_structs.get_udp_length buf - Wire_structs.sizeof_udp)
    in
    match listeners ~dst_port with
    | None -> return_unit
    | Some fn ->
      let src_port = Wire_structs.get_udp_source_port buf in
      fn ~src ~dst ~src_port data

  let writev ?source_port ~dest_ip ~dest_port t bufs =
    begin match source_port with
      | None -> fail (Failure "TODO; random source port")
      | Some p -> return p
    end >>= fun source_port ->
    Ip.writev t.ip ~dst:dest_ip ~proto:`UDP begin fun ethernet_frame header_len ->
      let udp_buf = Cstruct.shift ethernet_frame header_len in
      let ipv4_frame = Cstruct.shift ethernet_frame Wire_structs.sizeof_ethernet in
      Wire_structs.set_udp_source_port udp_buf source_port;
      Wire_structs.set_udp_dest_port udp_buf dest_port;
      let csum = Ip.checksum ~proto:`UDP ipv4_frame (udp_buf :: bufs) in
      Wire_structs.set_udp_checksum udp_buf csum;
      Wire_structs.set_udp_length udp_buf
        (Wire_structs.sizeof_udp + Cstruct.lenv bufs);
      let frame =
        Cstruct.set_len ethernet_frame (header_len + Wire_structs.sizeof_udp)
      in
      frame :: bufs
    end

  let write ?source_port ~dest_ip ~dest_port t buf =
    writev ?source_port ~dest_ip ~dest_port t [buf]

  let connect ip =
    return (`Ok { ip })

  let disconnect _ = return_unit
end
