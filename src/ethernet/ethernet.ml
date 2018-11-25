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

let src = Logs.Src.create "ethernet" ~doc:"Mirage Ethernet"
module Log = (val Logs.src_log src : Logs.LOG)

module Make(Netif : Mirage_net_lwt.S) = struct

  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t
  type macaddr = Macaddr.t

  type error = Netif.error
  let pp_error = Netif.pp_error

  type callback = source:macaddr -> macaddr -> buffer -> unit io

  module M = Map.Make(Mirage_protocols.Ethernet.Proto)

  type t = {
    netif: Netif.t;
    mutable callbacks : callback M.t
  }

  let header_size _t = Ethernet_wire.sizeof_ethernet

  let mac t = Netif.mac t.netif
  let mtu t = Netif.mtu t.netif - Ethernet_wire.sizeof_ethernet

  let allocate_frame ?size t =
    let size = match size with None -> None | Some x -> Some (x + Ethernet_wire.sizeof_ethernet) in
    Netif.allocate_frame ?size t.netif, Ethernet_wire.sizeof_ethernet

  let register t proto callback =
    match M.find_opt proto t.callbacks with
    | None ->
      Log.info (fun m -> m "registering new callback for %a" Mirage_protocols.Ethernet.Proto.pp proto) ;
      t.callbacks <- M.add proto callback t.callbacks ;
      Ok ()
    | Some _ ->
      Log.err (fun m -> m "callback for %a already registered" Mirage_protocols.Ethernet.Proto.pp proto) ;
      Error `Conflict

  let process t frame =
    MProf.Trace.label "ethernet.process";
    let open Ethernet_packet in
    let of_interest dest =
      Macaddr.compare dest (mac t) = 0 || not (Macaddr.is_unicast dest)
    in
    match Unmarshal.of_cstruct frame with
    | Ok (header, payload) ->
      if of_interest header.destination then
        Some (header, payload)
      else begin
        Log.debug (fun m -> m "ignoring ethernet frame %a (not of interest)" Ethernet_packet.pp header);
        None
      end
    | Error s ->
      Log.debug (fun f -> f "dropping Ethernet frame: %s" s);
      None

  let receive t frame =
    match process t frame with
    | None -> Lwt.return_unit
    | Some (hdr, payload) ->
      match M.find_opt hdr.ethertype t.callbacks with
      | None ->
        Log.debug (fun m -> m "received frame %a, but nobody is listening" Ethernet_packet.pp hdr);
        Lwt.return_unit
      | Some f ->
        f ~source:hdr.source hdr.destination payload

  let input t f frame =
    match process t frame with
    | None -> Lwt.return_unit
    | Some ({ ethertype ; source ; destination }, payload) ->
        f ethertype ~source destination payload

  let write t ethertype ?source destination frame =
    MProf.Trace.label "ethif.write";
    let source = match source with None -> mac t | Some s -> s in
    let hdr = Ethernet_packet.{ source ; destination ; ethertype } in
    match Ethernet_packet.Marshal.into_cstruct hdr frame with
    | Error e ->
      Log.warn (fun f -> f "encapsulate errored %s" e) ;
      Lwt.return (Error `Unimplemented)
    | Ok () ->
      Netif.write t.netif frame >|= function
      | Ok () -> Ok ()
      | Error e ->
        Log.warn (fun f -> f "netif write errored %a" Netif.pp_error e) ;
        Error e

  let connect netif =
    MProf.Trace.label "ethif.connect";
    let t = { netif ; callbacks = M.empty } in
    Lwt.async (fun () -> Netif.listen netif (receive t) >|= function
      | Error e -> Log.err (fun p -> p "%a" Netif.pp_error e)
      | Ok () -> ()) ;
    Log.info (fun f -> f "Connected Ethernet interface %s" (Macaddr.to_string (mac t)));
    Lwt.return t

  let disconnect t =
    Log.info (fun f -> f "Disconnected Ethernet interface %s" (Macaddr.to_string (mac t)));
    Lwt.return_unit
end
