(*
 * Copyright (c) 2015 Magnus Skjegstad <magnus@skjegstad.com>
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
open Common

(* TODO Some of these modules and signatures could eventually be moved to mirage-vnetif *)

module Time = struct
  type 'a io = 'a Lwt.t
  include Lwt_unix
end

module Clock = Unix
module Console = Console_unix

module type VNETIF_STACK =
sig
  type backend
  type buffer
  type 'a io
  type id
  module Stackv4 : V1_LWT.STACKV4
  (** Create a new backend *)
  val create_backend : unit -> backend
  (** Create a new stack connected to an existing backend *)
  val create_stack : Console.t -> backend -> Ipaddr.V4.t -> Ipaddr.V4.t -> Ipaddr.V4.t list -> Stackv4.t Lwt.t
  (** Add a listener function to the backend *)
  val create_backend_listener : backend -> (buffer -> unit io) -> id
  (** Disable a listener function *)
  val disable_backend_listener : backend -> id -> unit
  (** Records pcap data from the backend while running the specified function. Disables the pcap recorder when the function exits. *)
  val record_pcap : backend -> string -> (unit -> unit Lwt.t) -> unit Lwt.t
end

module VNETIF_STACK ( B : Vnetif_backends.Backend) : VNETIF_STACK = struct
  type backend = B.t
  type buffer = B.buffer
  type 'a io = 'a B.io
  type id = B.id

  module V = Vnetif.Make(B)
  module E = Ethif.Make(V)
  module A = Arpv4.Make(E)(Clock)(Time)
  module I = Ipv4.Make(E)(A)
  module U = Udp.Make(I)
  module T = Tcp.Flow.Make(I)(Time)(Clock)(Random)
  module Stackv4 = Tcpip_stack_direct.Make(Console)(Time)(Random)(V)(E)(A)(I)(U)(T)

  let create_backend () =
    B.create ()

  let create_stack c backend ip netmask gw =
    or_error "backend" V.connect backend >>= fun netif ->
    or_error "ethif" E.connect netif >>= fun ethif ->
    or_error "arpv4" A.connect ethif >>= fun arpv4 ->
    or_error "ipv4" (I.connect ethif) arpv4 >>= fun ipv4 ->
    or_error "udpv4" U.connect ipv4 >>= fun udpv4 ->
    or_error "tcpv4" T.connect ipv4 >>= fun tcpv4 ->
    let config = {
      V1_LWT.name = "stack";
      console = c;
      interface = netif;
      mode = `IPv4 (ip, netmask, gw);
    } in
    or_error "stack" (Stackv4.connect config ethif arpv4 ipv4 udpv4) tcpv4

  let create_backend_listener backend listenf =
    match (B.register backend) with
    | `Error e -> fail "Error occured while registering to backend"
    | `Ok id -> (B.set_listen_fn backend id listenf); id

  let disable_backend_listener backend id =
    B.set_listen_fn backend id (fun buf -> Lwt.return_unit)

  let create_pcap_recorder backend channel =
    let header_buf = Cstruct.create Pcap.sizeof_pcap_header in
    Pcap.LE.set_pcap_header_magic_number header_buf Pcap.magic_number;
    Pcap.LE.set_pcap_header_network header_buf Pcap.Network.(to_int32 Ethernet);
    Pcap.LE.set_pcap_header_sigfigs header_buf 0l;
    Pcap.LE.set_pcap_header_snaplen header_buf 0xffffl;
    Pcap.LE.set_pcap_header_thiszone header_buf 0l;
    Pcap.LE.set_pcap_header_version_major header_buf Pcap.major_version;
    Pcap.LE.set_pcap_header_version_minor header_buf Pcap.minor_version;
    Lwt_io.write channel (Cstruct.to_string header_buf) >>= fun () ->
    let pcap_record channel buffer =
      let pcap_buf = Cstruct.create Pcap.sizeof_pcap_packet in
      let time = Unix.gettimeofday () in
      Pcap.LE.set_pcap_packet_incl_len pcap_buf (Int32.of_int (Cstruct.len buffer));
      Pcap.LE.set_pcap_packet_orig_len pcap_buf (Int32.of_int (Cstruct.len buffer));
      Pcap.LE.set_pcap_packet_ts_sec pcap_buf (Int32.of_float time);
      let frac = (time -. (float_of_int (truncate time))) *. 1000000.0 in
      Pcap.LE.set_pcap_packet_ts_usec pcap_buf (Int32.of_float frac);
      (try
          Lwt_io.write channel ((Cstruct.to_string pcap_buf) ^ (Cstruct.to_string buffer))
      with
          Lwt_io.Channel_closed msg -> Printf.printf "Warning: Pcap output channel already closed: %s.\n" msg; Lwt.return_unit)
      >>= fun () ->
      Lwt.return_unit
    in
    let recorder_id = create_backend_listener backend (pcap_record channel) in
    Lwt.return recorder_id

  let record_pcap backend pcap_file fn =
    Lwt_io.with_file ~mode:Lwt_io.output pcap_file (fun oc ->
        create_pcap_recorder backend oc >>= fun recorder_id ->
        fn () >>= fun () ->
        disable_backend_listener backend recorder_id;
        Lwt.return_unit
      )
end
