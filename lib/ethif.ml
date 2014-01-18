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
open Wire_structs

module Make(Netif : T.LWT_NETWORK) = struct

  type id = Netif.t
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
    arp: Arpv4.t;
  }

  let id t = t.netif

  let input ~ipv4 ~ipv6 t frame =
    match get_ethernet_ethertype frame with
    | 0x0806 -> Arpv4.input t.arp frame (* ARP *)
    | 0x0800 -> (* IPv4 *)
      let payload = Cstruct.shift frame sizeof_ethernet in
      ipv4 payload
    | 0x86dd -> return ()
    | etype  -> return ()

  let write t frame =
    Netif.write t.netif frame

  let writev t bufs =
    Netif.writev t.netif bufs

  let connect netif =
    let arp =
      let get_mac () = Netif.mac netif in
      let get_etherbuf () = return (Io_page.to_cstruct (Io_page.get 1)) in
      let output buf = Netif.write netif buf in
      Arpv4.create ~output ~get_mac ~get_etherbuf in
    return (`Ok { netif; arp })

  let disconnect nf = return ()
  let mac {netif} = Netif.mac netif

  let add_ipv4 t = Arpv4.add_ip t.arp
  let remove_ipv4 t = Arpv4.remove_ip t.arp
  let query_arpv4 t = Arpv4.query t.arp

  let mac t = Netif.mac t.netif
  let get_netif t = t.netif
end
