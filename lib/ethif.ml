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
open Lwt.Infix

module Make(Netif : V1_LWT.NETWORK) = struct

  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t
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
    let of_interest dest =
      Macaddr.compare dest (mac t) = 0 || not (Macaddr.is_unicast dest)
    in
    match Wire_structs.parse_ethernet_frame frame with
    | Some (typ, destination, payload) when of_interest destination ->
      begin
        match typ with
        | Some Wire_structs.ARP -> arpv4 payload
        | Some Wire_structs.IPv4 -> ipv4 payload
        | Some Wire_structs.IPv6 -> ipv6 payload
        | None -> Lwt.return_unit (* TODO: default ethertype payload handler *)
      end
    | _ -> Lwt.return_unit

  let write t frame =
    MProf.Trace.label "ethif.write";
    Netif.write t.netif frame

  let writev t bufs =
    MProf.Trace.label "ethif.writev";
    Netif.writev t.netif bufs

  let connect netif =
    MProf.Trace.label "ethif.connect";
    Lwt.return (`Ok { netif })

  let disconnect _ = Lwt.return_unit
end
