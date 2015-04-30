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
open Vnetif_common

let netmask = Ipaddr.V4.of_string_exn "255.255.255.0" 
let gw = Ipaddr.V4.of_string_exn "10.0.0.1" 
let client_ip = Ipaddr.V4.of_string_exn "10.0.0.101"
let server_ip = Ipaddr.V4.of_string_exn "10.0.0.100"
let test_string = "Hello world from Mirage 123456789...."

module C = Console

let accept c flow expected =
  let ip, port = S.T.get_dest flow in
  C.log_s c (Printf.sprintf "Accepted connection from %s:%d%!" (Ipaddr.V4.to_string ip) port) >>= fun () ->
  S.T.read flow >>= (function
      | `Ok b -> expect "accept" expected (Cstruct.to_string b)
      | `Eof | `Error _ -> fail "Error while reading%!")
  >>= fun () ->
  C.log_s c "Connection closed%!"

let tcp_connect_two_stacks backend =
    or_error "console" Console.connect "console" >>= fun c ->
    let timeout = 15.0 in
    Lwt.pick [
        (Lwt_unix.sleep timeout >>= fun () ->
         fail "connect test timedout after %f seconds" timeout) ;

        (create_stack c backend server_ip netmask [gw] >>= fun s1 ->
        S.listen_tcpv4 s1 ~port:80 (fun f -> accept c f test_string);
        S.listen s1) ;

        (Lwt_unix.sleep 1.0 >>= fun () ->
        create_stack c backend client_ip netmask [gw] >>= fun s2 ->
        or_error "connect" (S.T.create_connection (S.tcpv4 s2)) (server_ip, 80) >>= fun flow ->
        C.log_s c "Connected to other end...%!" >>= fun () ->
        S.T.write flow (Cstruct.of_string test_string) >>= (function
            | `Ok () -> C.log_s c "wrote hello world%!"
            | `Error _ -> fail "client tried to write, got error%!"
            | `Eof -> fail "client tried to write, got eof%!") >>= fun () ->
        S.T.close flow >>= fun () ->
        Lwt.return_unit) ] >>= fun () ->
    Lwt.return_unit

let test_tcp_connect_two_stacks_basic () =
    let backend = S.B.create ~use_async_readers:true ~yield:(fun() -> Lwt_main.yield () ) () in (* use_async_readers must be true with tcpip *)
    tcp_connect_two_stacks backend

let test_tcp_connect_two_stacks_trailing_bytes () =
    let backend = Vnetif_backends.Trailing_bytes.create ~use_async_readers:true ~yield:(fun() -> Lwt_main.yield () ) () in (* use_async_readers must be true with tcpip *)
    tcp_connect_two_stacks backend

let suite = [
  "test_tcp_connect_two_stacks_basic" , test_tcp_connect_two_stacks_basic;
  "test_tcp_connect_two_stacks_trailing_bytes" , test_tcp_connect_two_stacks_trailing_bytes;
]
