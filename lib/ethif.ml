(*
 * Copyright (c) 2010-2011 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (c) 2011 Richard Mortier <richard.mortier@nottingham.ac.uk>
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
 *
 *)
open Lwt

module Make(Netif : V1_LWT.NETWORK) = struct

  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t
  type ipv4addr = Ipaddr.V4.t
  type macaddr = Macaddr.t
  type netif = Netif.t

  type error = [
    | `Unknown of string
    | `Unimplemented
    | `Disconnected
  ]

  type t = {
    netif: Netif.t;
  }

  let id t = t.netif
  let mac t = Netif.mac t.netif

  let input ~arpv4 ~ipv4 ~ipv6 t frame =
    MProf.Trace.label "ethif.input";
    let broadcast_mac = Macaddr.to_bytes Macaddr.broadcast in
    let local_mac = Macaddr.to_bytes (mac t) in
    let frame_mac = Wire_structs.copy_ethernet_dst frame in
    if (((Bytes.compare frame_mac local_mac) == 0) || ((Bytes.compare frame_mac broadcast_mac) == 0)) then
      match Wire_structs.get_ethernet_ethertype frame with
      | 0x0806 ->
        arpv4 frame (* ARP *)
      | 0x0800 -> (* IPv4 *)
        let payload = Cstruct.shift frame Wire_structs.sizeof_ethernet in
        ipv4 payload
      | 0x86dd ->
        let payload = Cstruct.shift frame Wire_structs.sizeof_ethernet in
        ipv6 payload
      | _etype ->
        let _payload = Cstruct.shift frame Wire_structs.sizeof_ethernet in
        (* TODO default etype payload *)
        return_unit
    else
      return_unit

  let write t frame =
    MProf.Trace.label "ethif.write";
    Netif.write t.netif frame

  let writev t bufs =
    MProf.Trace.label "ethif.writev";
    Netif.writev t.netif bufs

  let connect netif =
    MProf.Trace.label "ethif.connect";
    return (`Ok { netif })

  let disconnect _ = return_unit
end
