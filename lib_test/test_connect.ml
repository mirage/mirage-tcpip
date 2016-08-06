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

  let netmask = Ipaddr.V4.of_string_exn "255.255.255.0"
  let gw = Ipaddr.V4.of_string_exn "10.0.0.1"
  let client_ip = Ipaddr.V4.of_string_exn "10.0.0.101"
  let server_ip = Ipaddr.V4.of_string_exn "10.0.0.100"
  let test_string = "Hello world from Mirage 123456789...."
  let backend = V.create_backend ()

  let err_read_eof () = fail "accept got EOF while reading"
  let err_write_eof () = fail "client tried to write, got EOF"

  let err_read e =
    let err = V.Stackv4.TCPV4.error_message e in
    fail "Error while reading: %s" err

  let err_write e =
    let err = V.Stackv4.TCPV4.error_message e in
    fail "client tried to write, got %s" err

  let accept flow expected =
    let ip, port = V.Stackv4.TCPV4.dst flow in
    Logs.debug (fun f -> f "Accepted connection from %s:%d" (Ipaddr.V4.to_string ip) port);
    V.Stackv4.TCPV4.read flow >>= function
    | `Eof     -> err_read_eof ()
    | `Error e -> err_read e
    | `Ok b    ->
      Lwt_unix.sleep 0.1 >>= fun () ->
      (* sleep first to capture data in pcap *)
      assert_string "accept" expected (Cstruct.to_string b);
      Logs.debug (fun f -> f "Connection closed");
      Lwt.return_unit

  let test_tcp_connect_two_stacks () =
    let timeout = 15.0 in
    Lwt.pick [
      (Lwt_unix.sleep timeout >>= fun () ->
       fail "connect test timedout after %f seconds" timeout) ;

      (V.create_stack backend server_ip netmask [gw] >>= fun s1 ->
       V.Stackv4.listen_tcpv4 s1 ~port:80 (fun f -> accept f test_string);
       V.Stackv4.listen s1) ;

      (Lwt_unix.sleep 0.1 >>= fun () ->
       V.create_stack backend client_ip netmask [gw] >>= fun s2 ->
       let conn = V.Stackv4.TCPV4.create_connection (V.Stackv4.tcpv4 s2) in
       or_error "connect" conn (server_ip, 80) >>= fun flow ->
       Logs.debug (fun f -> f "Connected to other end...");
       V.Stackv4.TCPV4.write flow (Cstruct.of_string test_string) >>= function
       | `Error e -> err_write e
       | `Eof     -> err_write_eof ()
       | `Ok ()   ->
         Logs.debug (fun f -> f "wrote hello world");
         V.Stackv4.TCPV4.close flow >>= fun () ->
         Lwt_unix.sleep 1.0 >>= fun () -> (* record some traffic after close *)
         Lwt.return_unit) ]
    >>= fun () ->

    Lwt.return_unit

  let test_tcp_connect_one_stack () =
    or_error "console" Console.connect "console" >>= fun c ->
    V.create_stack c backend server_ip netmask [gw] >>= fun s1 ->
    let timeout = 15.0 in
    Lwt.pick [
      (Lwt_unix.sleep timeout >>= fun () ->
       fail "connect test timedout after %f seconds" timeout) ;

      (V.Stackv4.listen_tcpv4 s1 ~port:80 (fun f -> accept c f test_string);
       V.Stackv4.listen s1) ;

      (Lwt_unix.sleep 1.0 >>= fun () ->
       or_error "connect" (V.Stackv4.TCPV4.create_connection (V.Stackv4.tcpv4 s1)) (server_ip, 80) >>= fun flow ->
       C.log_s c "Connected to other end...%!" >>= fun () ->
       V.Stackv4.TCPV4.write flow (Cstruct.of_string test_string) >>= (function
           | `Ok () -> C.log_s c "wrote hello world%!"
           | `Error _ -> fail "client tried to write, got error%!"
           | `Eof -> fail "client tried to write, got eof%!") >>= fun () ->
       V.Stackv4.TCPV4.close flow >>= fun () ->
       Lwt.return_unit) ] >>= fun () ->
    Lwt.return_unit

  let record_pcap =
    V.record_pcap backend

end

let test_tcp_connect_two_stacks_basic () =
  let module Test = Test_connect(Vnetif_backends.Basic) in
  Test.record_pcap
    "tests/pcap/tcp_connect_two_stacks_basic.pcap"
    Test.test_tcp_connect_two_stacks

let test_tcp_connect_one_stack_basic () =
  let module Test = Test_connect(Vnetif_backends.Basic) in
  Test.record_pcap
    "tests/pcap/tcp_connect_one_stack_basic.pcap"
    Test.test_tcp_connect_one_stack

let test_tcp_connect_two_stacks_trailing_bytes () =
  let module Test = Test_connect(Vnetif_backends.Trailing_bytes) in
  Test.record_pcap
    "tests/pcap/tcp_connect_two_stacks_trailing_bytes.pcap"
    Test.test_tcp_connect_two_stacks

let suite = [
  "test_tcp_connect_two_stacks_basic" , `Quick, test_tcp_connect_two_stacks_basic;
  "test_tcp_connect_two_stacks_trailing_bytes" , `Quick, test_tcp_connect_two_stacks_trailing_bytes;
  "test_tcp_connect_one_stack_basic" , `Quick, test_tcp_connect_one_stack_basic;
]
