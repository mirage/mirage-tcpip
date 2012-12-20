(*
 * Copyright (c) 2011 Anil Madhavapeddy <anil@recoil.org>
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
open Nettypes

module UDPv4 = struct

  type mgr = Manager.t
  type src = ipv4_src
  type dst = ipv4_dst
  type msg = Cstruct.t

  let send mgr ?src (dest_ip, dest_port) msg =
    (* TODO: set src addr here also *)
    let source_port = match src with
      |None -> 37 (* XXX eventually random *)
      |Some (_,p) -> p in
    let udps = Manager.udpv4_of_addr mgr None in
    (* TODO: select the right interface to route from *)
    match udps with
    |hd :: tl -> Udp.write hd ~dest_ip ~source_port ~dest_port msg
    |[] -> Printf.printf "UDP: no route to send packet, discarding\n%!"; return ()

  let recv mgr (src_addr, src_port) fn =
    let udps = Manager.udpv4_of_addr mgr src_addr in
    Lwt_list.iter_p (fun udp ->
      Udp.listen udp src_port (fun ~src ~dst ~source_port pkt ->
        fn (src,source_port) pkt
      )
    ) udps
end
