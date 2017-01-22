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
open Result
open Lwt.Infix

let src = Logs.Src.create "ethif" ~doc:"Mirage Ethernet"
module Log = (val Logs.src_log src : Logs.LOG)

let default_mtu = 1500

module Make(Netif : Mirage_net_lwt.S) = struct

  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t
  type macaddr = Macaddr.t
  type netif = Netif.t

  type error = Netif.error
  let pp_error = Netif.pp_error

  type t = {
    netif: Netif.t;
    mtu: int;
  }

  let mac t = Netif.mac t.netif
  let mtu t = t.mtu

  let input ~arpv4 ~ipv4 ~ipv6 t frame =
    let open Ethif_packet in
    MProf.Trace.label "ethif.input";
    let of_interest dest =
      Macaddr.compare dest (mac t) = 0 || not (Macaddr.is_unicast dest)
    in
    match Unmarshal.of_cstruct frame with
    | Ok (header, payload) when of_interest header.destination ->
      begin
        let open Ethif_wire in
        match header.ethertype with
        | ARP -> arpv4 payload
        | IPv4 -> ipv4 payload
        | IPv6 -> ipv6 payload
      end
    | Ok _ -> Lwt.return_unit
    | Error s ->
      Log.debug (fun f -> f "Dropping Ethernet frame: %s" s);
      Lwt.return_unit

  let write t frame =
    MProf.Trace.label "ethif.write";
    Netif.write t.netif frame >|= function
    | Ok () -> Ok ()
    | Error e ->
      Log.warn (fun f -> f "netif write errored %a" Netif.pp_error e) ;
      Error e

  let writev t bufs =
    MProf.Trace.label "ethif.writev";
    Netif.writev t.netif bufs >|= function
    | Ok () -> Ok ()
    | Error e ->
      Log.warn (fun f -> f "netif writev errored %a" Netif.pp_error e) ;
      Error e

  let connect ?(mtu = default_mtu) netif =
    MProf.Trace.label "ethif.connect";
    let t = { netif; mtu } in
    Log.info (fun f -> f "Connected Ethernet interface %s" (Macaddr.to_string (mac t)));
    Lwt.return t

  let disconnect t =
    Log.info (fun f -> f "Disconnected Ethernet interface %s" (Macaddr.to_string (mac t)));
    Lwt.return_unit
end
