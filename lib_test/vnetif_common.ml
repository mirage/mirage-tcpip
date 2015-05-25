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

module Time = struct
  type 'a io = 'a Lwt.t
  include Lwt_unix
end

module Clock = Unix

module Console = Console_unix

module S = struct
  module B = Basic_backend.Make
  module V = Vnetif.Make(B)
  module E = Ethif.Make(V)
  module I = Ipv4.Make(E)(Clock)(Time)
  module U = Udp.Make(I)
  module T = Tcp.Flow.Make(I)(Time)(Clock)(Random)
  module S = Tcpip_stack_direct.Make(Console)(Time)(Random)(V)(E)(I)(U)(T)
  include S
end

let create_stack c backend ip netmask gw =
  or_error "backend" S.V.connect backend >>= fun netif ->
  (* Printf.printf (Printf.sprintf "Connected to backend with mac %s" (Macaddr.to_string (S.V.mac netif))) *)
  or_error "ethif" S.E.connect netif >>= fun ethif ->
  or_error "ipv4" S.I.connect ethif >>= fun ipv4 ->
  or_error "udpv4" S.U.connect ipv4 >>= fun udpv4 ->
  or_error "tcpv4" S.T.connect ipv4 >>= fun tcpv4 ->
  let config = {
    V1_LWT.name = "stack";
    console = c; 
    interface = netif;
    mode = `IPv4 (ip, netmask, gw);
  } in
  or_error "stack" (S.connect config ethif ipv4 udpv4) tcpv4

let create_backend_listener backend listenf =
  match (S.B.register backend) with
  | `Error e -> fail "Error occured while registering to backend" 
  | `Ok id -> (S.B.set_listen_fn backend id listenf); id

let disable_backend_listener backend id =
  S.B.set_listen_fn backend id (fun buf -> Lwt.return_unit)

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
  Lwt_io.flush channel >>= fun () ->
  let pcap_record channel buffer =
    let pcap_buf = Cstruct.create Pcap.sizeof_pcap_packet in
    let time = Unix.gettimeofday () in
    Pcap.LE.set_pcap_packet_incl_len pcap_buf (Int32.of_int (Cstruct.len buffer));
    Pcap.LE.set_pcap_packet_orig_len pcap_buf (Int32.of_int (Cstruct.len buffer));
    Pcap.LE.set_pcap_packet_ts_sec pcap_buf (Int32.of_float time); 
    Pcap.LE.set_pcap_packet_ts_usec pcap_buf (Int32.rem (Int32.of_float (time *. 1000000.0)) 1000000l);
    Lwt_io.write channel ((Cstruct.to_string pcap_buf) ^ (Cstruct.to_string buffer)) >>= fun () ->
    Lwt_io.flush channel (* always flush *)
  in
  let recorder_id = create_backend_listener backend (pcap_record channel) in
  Lwt.return recorder_id
