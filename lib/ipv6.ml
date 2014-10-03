(*
 * Copyright (c) 2014 Nicolas Ojeda Bar <n.oje.bar@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS l SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

module Make (Ethif : V1_LWT.ETHIF) = struct
  type ethif = Ethif.t
  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t
  type ipv6addr = Ipaddr.V6.t
  type callback = src:ipv6addr -> dst:ipv6addr -> buffer -> unit Lwt.t

  type t = {
    ethif : Ethif.t
  }

  (* This is temporary. See https://github.com/mirage/ocaml-ipaddr/pull/36 *)
  let ipaddr_of_cstruct cs =
    let hihi = Cstruct.BE.get_uint32 cs 0 in
    let hilo = Cstruct.BE.get_uint32 cs 4 in
    let lohi = Cstruct.BE.get_uint32 cs 8 in
    let lolo = Cstruct.BE.get_uint32 cs 12 in
    Ipaddr.V6.of_int32 (hihi, hilo, lohi, lolo)
      
  (* This will have to be moved somewhere else later, since the same computation
     is needed for UDP, TCP, ICMP, etc. over IPv6. Also, [Tcpip_checksum] is a
     bad name since it is used for other protocols as well. *)
  let pbuf =
     Cstruct.sub (Cstruct.of_bigarray (Io_page.get 1)) 0 8
      
  let checksum ~src ~dst ~proto data =
    Cstruct.BE.set_uint32 pbuf 0 (Int32.of_int (Cstruct.len data));
    Cstruct.BE.set_uint32 pbuf 4 (Int32.of_int proto);
    Tcpip_checksum.ones_complement_list [ src; dst; pbuf; data ]
  
  let icmp_input t src dst buf =
    let csum = Wire_structs.get_icmpv6_csum buf in
    if csum != checksum src dst 58 buf then
      Lwt.return_unit (* checksum does not match, discard packet *)
    else
      match Wire_structs.get_icmpv6_ty buf with
      | _ ->
        Lwt.return_unit (* TODO *)
  
  let input ~tcp ~udp ~default _t buf =
    let src = Wire_structs.get_ipv6_src buf in
    let dst = Wire_structs.get_ipv6_dst buf in
    (* See http://en.wikipedia.org/wiki/List_of_IP_protocol_numbers *)
    let rec loop first hdr buf =
      match hdr with
      | 0 when first -> (* HOPOPT *)
        loop false
          (Cstruct.get_uint8 buf 0) (Cstruct.shift buf (8 + 8 * Cstruct.get_uint8 buf 1))
      | 0 ->
        (* HOPOPT should only appear in first position. So we drop this packet. *)
        Lwt.return_unit
      | 60 -> (* TODO IPv6-Opts *)
        Lwt.return_unit
      | 43 -> (* TODO IPv6-Route *)
        Lwt.return_unit
      | 44 (* TODO IPv6-Frag *)
      | 50 (* TODO ESP *)
      | 51 (* TODO AH *)
      | 135 -> (* TODO Mobility Header *)
        Lwt.return_unit
      | 59 (* NO NEXT HEADER *) ->
        Lwt.return_unit
      | 58 (* ICMP *) ->
        icmp_input _t src dst buf
      | 17 (* UDP *) ->
        udp buf
      | 6 (* TCP *) ->
        tcp buf
      | n when 143 <= n && n <= 255 ->
        (* UNASSIGNED, EXPERIMENTAL & RESERVED *)
        Lwt.return_unit
      | n ->
        let src = ipaddr_of_cstruct src in
        let dst = ipaddr_of_cstruct dst in
        default ~proto:n ~src ~dst buf
    in
    loop true
      (Wire_structs.get_ipv6_nhdr buf) (Cstruct.shift buf Wire_structs.sizeof_ipv6)
end
