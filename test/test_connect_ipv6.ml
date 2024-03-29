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

module Test_connect_ipv6 (B : Vnetif_backends.Backend) = struct
  module V = VNETIF_STACK (B)

  let client_address = Ipaddr.V6.of_string_exn "fc00::23"
  let client_cidr = Ipaddr.V6.Prefix.make 64 client_address
  let server_address = Ipaddr.V6.of_string_exn "fc00::45"
  let server_cidr = Ipaddr.V6.Prefix.make 64 server_address
  let test_string = "Hello world from Mirage 123456789...."
  let backend = V.create_backend ()

  let err_read_eof () = failf "accept got EOF while reading"
  let err_write_eof () = failf "client tried to write, got EOF"

  let err_read e =
    let err = Format.asprintf "%a" V.Stack.TCP.pp_error e in
    failf "Error while reading: %s" err

  let err_write e =
    let err = Format.asprintf "%a" V.Stack.TCP.pp_write_error e in
    failf "client tried to write, got %s" err

  let accept flow expected =
    let ip, port = V.Stack.TCP.dst flow in
    Log.debug (fun f -> f "Accepted connection from %s:%d" (Ipaddr.to_string ip) port);
    V.Stack.TCP.read flow >>= function
    | Error e      -> err_read e
    | Ok `Eof      -> err_read_eof ()
    | Ok (`Data b) ->
      Lwt_unix.sleep 0.1 >>= fun () ->
      (* sleep first to capture data in pcap *)
      Alcotest.(check string) "accept" expected (Cstruct.to_string b);
      Log.debug (fun f -> f "Connection closed");
      Lwt.return_unit

  let cidr = Ipaddr.V4.Prefix.of_string_exn "10.0.0.2/24"

  let test_tcp_connect_two_stacks () =
    let timeout = 15.0 in
    Lwt.pick [
      (Lwt_unix.sleep timeout >>= fun () ->
       failf "connect test timedout after %f seconds" timeout) ;

      (V.create_stack ~cidr ~cidr6:server_cidr backend >>= fun s1 ->
       V.Stack.TCP.listen (V.Stack.tcp s1) ~port:80 (fun f -> accept f test_string);
       V.Stack.listen s1) ;

      (Lwt_unix.sleep 0.1 >>= fun () ->
       V.create_stack ~cidr ~cidr6:client_cidr backend >>= fun s2 ->
       Lwt.pick [
       V.Stack.listen s2;
       (let conn = V.Stack.TCP.create_connection (V.Stack.tcp s2) in
       or_error "connect" conn (Ipaddr.V6 server_address, 80) >>= fun flow ->
       Log.debug (fun f -> f "Connected to other end...");

       V.Stack.TCP.write flow (Cstruct.of_string test_string) >>= function
       | Error `Closed -> err_write_eof ()
       | Error e -> err_write e
       | Ok ()   ->
         Log.debug (fun f -> f "wrote hello world");
         V.Stack.TCP.close flow >>= fun () ->
         Lwt_unix.sleep 1.0 >>= fun () -> (* record some traffic after close *)
         Lwt.return_unit)]) ] >>= fun () ->

    Lwt.return_unit

  let record_pcap =
    V.record_pcap backend

end

let test_tcp_connect_two_stacks_basic () =
  let module Test = Test_connect_ipv6(Vnetif_backends.Basic) in
  Test.record_pcap
    "tcp_connect_ipv6_two_stacks_basic.pcap"
    Test.test_tcp_connect_two_stacks

let test_tcp_connect_two_stacks_x100_uniform_no_payload_packet_loss () =
  let rec loop = function
      | 0 -> Lwt.return_unit
      | n -> Log.info (fun f -> f "%d/100" (101-n));
             let module Test = Test_connect_ipv6(Vnetif_backends.Uniform_no_payload_packet_loss) in
             Test.record_pcap
               (Printf.sprintf
               "tcp_connect_ipv6_two_stacks_no_payload_packet_loss_%d_of_100.pcap" n)
               Test.test_tcp_connect_two_stacks >>= fun () ->
             loop (n - 1)
  in
  loop 100

let test_tcp_connect_two_stacks_trailing_bytes () =
  let module Test = Test_connect_ipv6(Vnetif_backends.Trailing_bytes) in
  Test.record_pcap
    "tcp_connect_ipv6_two_stacks_trailing_bytes.pcap"
    Test.test_tcp_connect_two_stacks

let suite = [

  "connect two stacks, basic test", `Quick,
  test_tcp_connect_two_stacks_basic;

  "connect two stacks, uniform packet loss of packets with no payload x 100", `Slow,
  test_tcp_connect_two_stacks_x100_uniform_no_payload_packet_loss;

  "connect two stacks, with trailing bytes", `Quick,
  test_tcp_connect_two_stacks_trailing_bytes;

]
