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

open Common
open Lwt.Infix

(* TODO Some of these modules and signatures could eventually be moved
   to mirage-vnetif *)

module Time = struct
  include Lwt_unix
  let sleep_ns ns = sleep (Duration.to_f ns)
end
module Clock = Mclock

module type VNETIF_STACK =
sig
  type backend
  module Stack : Tcpip.Stack.V4V6

  (** Create a new backend *)
  val create_backend : unit -> backend

  (** Create a new stack connected to an existing backend *)
  val create_stack : ?mtu:int -> cidr:Ipaddr.V4.Prefix.t ->
    ?gateway:Ipaddr.V4.t -> ?cidr6:Ipaddr.V6.Prefix.t ->
    ?gateway6:Ipaddr.V6.t -> backend -> Stack.t Lwt.t

  val create_backend_listener : backend -> (Cstruct.t -> unit Lwt.t) -> int

  (** Disable a listener function *)
  val disable_backend_listener : backend -> int -> unit Lwt.t

  (** Records pcap data from the backend while running the specified
      function. Disables the pcap recorder when the function exits. *)
  val record_pcap : backend -> string -> (unit -> unit Lwt.t) -> unit Lwt.t
end

module VNETIF_STACK (B: Vnetif_backends.Backend): sig
  include VNETIF_STACK with type backend = B.t

  module T : sig
    val num_open_channels : Stack.TCP.t -> int
  end
end
= struct
  type backend = B.t
  module V = Vnetif.Make(B)
  module E = Ethernet.Make(V)

  module A = Arp.Make(E)
  module Ip4 = Static_ipv4.Make(Mirage_crypto_rng)(Clock)(E)(A)
  module Icmp4 = Icmpv4.Make(Ip4)
  module Ip6 = Ipv6.Make(V)(E)(Mirage_crypto_rng)(Clock)
  module Ip46 = Tcpip_stack_direct.IPV4V6(Ip4)(Ip6)
  module U = Udp.Make(Ip46)(Mirage_crypto_rng)
  module T = Tcp.Flow.Make(Ip46)(Clock)(Mirage_crypto_rng)

  module Stack =
    Tcpip_stack_direct.MakeV4V6(Mirage_crypto_rng)(V)(E)(A)(Ip46)(Icmp4)(U)(T)

  let create_backend () =
    B.create ()

  let create_stack ?mtu ~cidr ?gateway ?cidr6 ?gateway6 backend =
    let size_limit = match mtu with None -> None | Some x -> Some x in
    V.connect ?size_limit backend >>= fun netif ->
    E.connect netif >>= fun ethif ->
    A.connect ethif >>= fun arpv4 ->
    Ip4.connect ~cidr ?gateway ethif arpv4 >>= fun ipv4 ->
    Icmp4.connect ipv4 >>= fun icmpv4 ->
    Ip6.connect ?cidr:cidr6 ?gateway:gateway6 netif ethif >>= fun ipv6 ->
    Ip46.connect ~ipv4_only:false ~ipv6_only:false ipv4 ipv6 >>= fun ip ->
    U.connect ip >>= fun udp ->
    T.connect ip >>= fun tcp ->
    Stack.connect netif ethif arpv4 ip icmpv4 udp tcp

  let create_backend_listener backend listenf =
    match (B.register backend) with
    | Error _ -> failf "Error occurred while registering to backend"
    | Ok id -> (B.set_listen_fn backend id listenf); id

  let disable_backend_listener backend id =
    B.unregister_and_flush backend id

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
      Pcap.LE.set_pcap_packet_incl_len pcap_buf (Int32.of_int (Cstruct.length buffer));
      Pcap.LE.set_pcap_packet_orig_len pcap_buf (Int32.of_int (Cstruct.length buffer));
      Pcap.LE.set_pcap_packet_ts_sec pcap_buf (Int32.of_float time);
      let frac = (time -. (float_of_int (truncate time))) *. 1000000.0 in
      Pcap.LE.set_pcap_packet_ts_usec pcap_buf (Int32.of_float frac);
      (try
          Lwt_io.write channel ((Cstruct.to_string pcap_buf) ^ (Cstruct.to_string buffer))
      with
        Lwt_io.Channel_closed msg -> Printf.printf "Warning: Pcap output channel already closed: %s.\n" msg; Lwt.return_unit
      )
      >>= fun () ->
      Lwt.return_unit
    in
    let recorder_id = create_backend_listener backend (pcap_record channel) in
    Lwt.return recorder_id

  let record_pcap backend pcap_file fn =
    Lwt.catch
      (fun _ ->
        Lwt_io.with_file ~mode:Lwt_io.output pcap_file (fun oc ->
        create_pcap_recorder backend oc >>= fun recorder_id ->
        fn () >>= fun () ->
        disable_backend_listener backend recorder_id >>= fun () ->
        Lwt.return_unit
        )
      )
      (function
        | Unix.Unix_error _ ->
          Printf.printf "Could not create pcap file %s - something along the way doesn't exist.\n" pcap_file;
          fn ()
        | e -> Lwt.fail e
      )
end
