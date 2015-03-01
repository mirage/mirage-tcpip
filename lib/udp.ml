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

module Make(Ip: V1_LWT.IP) = struct

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
    (* TODO: allow zero checksum only for IPv4! *)
    match
      if Wire_structs.get_udp_checksum buf = 0 then
        0
      else
        Ip.checksum ~proto:`UDP ~src ~dst [buf]
    with
    | 0 ->
      let dst_port = Wire_structs.get_udp_dest_port buf in
      let data =
        Cstruct.sub buf Wire_structs.sizeof_udp
          (Wire_structs.get_udp_length buf - Wire_structs.sizeof_udp)
      in
      ( match listeners ~dst_port with
        | None -> return_unit
        | Some fn ->
          let src_port = Wire_structs.get_udp_source_port buf in
          fn ~src ~dst ~src_port data )
    | _ -> Printf.printf "input: checksum error\n%!"; return_unit

  let writev ?source_port ~dest_ip ~dest_port t bufs =
    begin match source_port with
      | None -> fail (Failure "TODO; random source port")
      | Some p -> return p
    end >>= fun source_port ->
    let frame, header_len = Ip.allocate_frame t.ip ~dst:dest_ip ~proto:`UDP in
    let frame = Cstruct.set_len frame (header_len + Wire_structs.sizeof_udp) in
    let udp_buf = Cstruct.shift frame header_len in
    let src = Ip.get_source t.ip ~dst:dest_ip in
    Wire_structs.set_udp_source_port udp_buf source_port;
    Wire_structs.set_udp_dest_port udp_buf dest_port;
    Wire_structs.set_udp_length udp_buf (Wire_structs.sizeof_udp + Cstruct.lenv bufs);
    (* Wire_structs.set_udp_checksum udp_buf 0; *)
    let csum = Ip.checksum ~src ~dst:dest_ip ~proto:`UDP (udp_buf :: bufs) in
    Wire_structs.set_udp_checksum udp_buf csum;
    Ip.writev t.ip frame bufs

  let write ?source_port ~dest_ip ~dest_port t buf =
    writev ?source_port ~dest_ip ~dest_port t [buf]

  let connect ip =
    return (`Ok { ip })

  let disconnect _ = return_unit
end
