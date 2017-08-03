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
open Vnetif_common

let (>>=) = Lwt.(>>=)

let src = Logs.Src.create "test_connect" ~doc:"connect tests"
module Log = (val Logs.src_log src : Logs.LOG)

module Test_connect (B : Vnetif_backends.Backend) = struct
  module V = VNETIF_STACK (B)

  let netmask = 24
  let gw = Some (Ipaddr.V4.of_string_exn "10.0.0.1")
  let client_ip = Ipaddr.V4.of_string_exn "10.0.0.101"
  let server_ip = Ipaddr.V4.of_string_exn "10.0.0.100"
  let test_string = "Hello world from Mirage 123456789...."
  let backend = V.create_backend ()

  let err_read_eof () = failf "accept got EOF while reading"
  let err_write_eof () = failf "client tried to write, got EOF"

  let err_read e =
    let err = Format.asprintf "%a" V.Stackv4.TCPV4.pp_error e in
    failf "Error while reading: %s" err

  let err_write e =
    let err = Format.asprintf "%a" V.Stackv4.TCPV4.pp_write_error e in
    failf "client tried to write, got %s" err

  let accept flow expected =
    let ip, port = V.Stackv4.TCPV4.dst flow in
    Logs.debug (fun f -> f "Accepted connection from %s:%d" (Ipaddr.V4.to_string ip) port);
    V.Stackv4.TCPV4.read flow >>= function
    | Error e      -> err_read e
    | Ok `Eof      -> err_read_eof ()
    | Ok (`Data b) ->
      Lwt_unix.sleep 0.1 >>= fun () ->
      (* sleep first to capture data in pcap *)
      Alcotest.(check string) "accept" expected (Cstruct.to_string b);
      Logs.debug (fun f -> f "Connection closed");
      Lwt.return_unit

  let test_tcp_connect_two_stacks () =
    let timeout = 15.0 in
    Lwt.pick [
      (Lwt_unix.sleep timeout >>= fun () ->
       failf "connect test timedout after %f seconds" timeout) ;

      (V.create_stack backend server_ip netmask gw >>= fun s1 ->
       V.Stackv4.listen_tcpv4 s1 ~port:80 (fun f -> accept f test_string);
       V.Stackv4.listen s1) ;

      (Lwt_unix.sleep 0.1 >>= fun () ->
       V.create_stack backend client_ip netmask gw >>= fun s2 ->
       Lwt.pick [
       V.Stackv4.listen s2;
       (let conn = V.Stackv4.TCPV4.create_connection (V.Stackv4.tcpv4 s2) in
       or_error "connect" conn (server_ip, 80) >>= fun flow ->
       Logs.debug (fun f -> f "Connected to other end...");
       V.Stackv4.TCPV4.write flow (Cstruct.of_string test_string) >>= function
       | Error `Closed -> err_write_eof ()
       | Error e -> err_write e
       | Ok ()   ->
         Logs.debug (fun f -> f "wrote hello world");
         V.Stackv4.TCPV4.close flow >>= fun () ->
         Lwt_unix.sleep 1.0 >>= fun () -> (* record some traffic after close *)
         Lwt.return_unit)]) ] >>= fun () ->

    Lwt.return_unit

  let record_pcap =
    V.record_pcap backend

end

let test_tcp_connect_two_stacks_basic () =
  let module Test = Test_connect(Vnetif_backends.Basic) in
  Test.record_pcap
    "tcp_connect_two_stacks_basic.pcap"
    Test.test_tcp_connect_two_stacks

let test_tcp_connect_two_stacks_x100_uniform_no_payload_packet_loss () =
  let rec loop = function
      | 0 -> Lwt.return_unit
      | n -> Logs.info (fun f -> f "%d/100" (101-n));
             let module Test = Test_connect(Vnetif_backends.Uniform_no_payload_packet_loss) in
             Test.record_pcap
               (Printf.sprintf
               "tcp_connect_two_stacks_no_payload_packet_loss_%d_of_100.pcap" n)
               Test.test_tcp_connect_two_stacks >>= fun () ->
             loop (n - 1)
  in
  loop 100

let test_tcp_connect_two_stacks_trailing_bytes () =
  let module Test = Test_connect(Vnetif_backends.Trailing_bytes) in
  Test.record_pcap
    "tcp_connect_two_stacks_trailing_bytes.pcap"
    Test.test_tcp_connect_two_stacks

let suite = [

  "connect two stacks, basic test", `Quick,
  test_tcp_connect_two_stacks_basic;

  "connect two stacks, uniform packet loss of packets with no payload x 100", `Slow,
  test_tcp_connect_two_stacks_x100_uniform_no_payload_packet_loss;

  "connect two stacks, with trailing bytes", `Quick,
  test_tcp_connect_two_stacks_trailing_bytes;

]
