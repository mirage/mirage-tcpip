(*
 * Copyright (c) 2011 Richard Mortier <mort@cantab.net>
 * Copyright (c) 2012 Balraj Singh <balraj.singh@cl.cam.ac.uk>
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

module Test_iperf ( B : Vnetif_backends.Backend ) = struct
  module C = Console
  module V = VNETIF_STACK (B)

  let backend = V.create_backend ()

  let netmask = Ipaddr.V4.of_string_exn "255.255.255.0" 
  let gw = Ipaddr.V4.of_string_exn "10.0.0.1" 
  let client_ip = Ipaddr.V4.of_string_exn "10.0.0.101"
  let server_ip = Ipaddr.V4.of_string_exn "10.0.0.100"

  type stats = {
    mutable bytes: int64;
    mutable packets: int64;
    mutable bin_bytes:int64;
    mutable bin_packets: int64;
    mutable start_time: float;
    mutable last_time: float;
  }

  let msg = "01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890"

  let mlen = String.length msg

  let write_and_check flow buf =
    V.Stackv4.TCPV4.write flow buf >>= function
    | `Ok () -> Lwt.return_unit
    | `Eof -> V.Stackv4.TCPV4.close flow >>= fun () -> raise (Failure "EOF while writing to TCP flow")
    | `Error _ -> V.Stackv4.TCPV4.close flow >>= fun () -> raise (Failure "Error while writing to TCP flow")

  let tcp_connect t (ip, port) =
    V.Stackv4.TCPV4.create_connection t (ip, port) >>= function
    | `Error e -> raise (Failure (Printf.sprintf "Unable to connect to %s:%d" (Ipaddr.V4.to_string ip) port))
    | `Ok f -> Lwt.return f

  let iperfclient c s dest_ip dport =
    let iperftx flow =
      C.log_s c (Printf.sprintf "Iperf client: Made connection to server.%!") >>= fun () ->
      let a = Cstruct.sub (Io_page.(to_cstruct (get 1))) 0 mlen in
      Cstruct.blit_from_string msg 0 a 0 mlen;
      let amt = 25000000 in
      let rec loop = function
        | 0 -> Lwt.return_unit
        | n -> write_and_check flow a >>= fun () -> loop (n-1)
      in
      loop (amt / mlen) >>= fun () ->
      let a = Cstruct.sub a 0 (amt - (mlen * (amt/mlen))) in
      write_and_check flow a >>= fun () ->
      V.Stackv4.TCPV4.close flow
    in
    OS.Time.sleep 1. >>= fun () ->
    C.log_s c (Printf.sprintf "Iperf client: Attempting connection.%!") >>= fun () ->
    tcp_connect (V.Stackv4.tcpv4 s) (dest_ip, dport) >>= fun flow ->
    iperftx flow >>= fun () ->
    C.log_s c (Printf.sprintf "Iperf client: Done.%!")

  let print_data c st ts_now = 
    C.log_s c (Printf.sprintf "Iperf server: t = %f, rate = %Ld KBits/s, totbytes = %Ld, live_words = %d%!"
                 (ts_now -. st.start_time)
                 (Int64.of_float (((Int64.to_float st.bin_bytes) /. (ts_now -. st.last_time)) /. 125.))
                 st.bytes Gc.((stat()).live_words)) >>= fun () ->
    st.last_time <- ts_now;
    st.bin_bytes <- 0L;
    st.bin_packets <- 0L;
    Lwt.return_unit

  let iperf c s server_done_u flow =
    C.log_s c (Printf.sprintf "Iperf server: Received connection.%!") >>= fun () ->
    let t0 = Clock.time () in
    let st = {bytes=0L; packets=0L; bin_bytes=0L; bin_packets=0L; start_time = t0; last_time = t0} in
    let rec iperf_h flow =
      V.Stackv4.TCPV4.read flow >>= fun f ->
      match f with
      | `Error _ -> raise (Failure "Unknown error in server while reading")
      | `Eof ->
        let ts_now = (Clock.time ()) in 
        st.bin_bytes <- st.bytes;
        st.bin_packets <- st.packets;
        st.last_time <- st.start_time;
        print_data c st ts_now >>= fun () ->
        V.Stackv4.TCPV4.close flow >>= fun () ->
        C.log_s c "Iperf server: Done - closed connection."
      | `Ok data -> 
        begin
          let l = Cstruct.len data in
          st.bytes <- (Int64.add st.bytes (Int64.of_int l));
          st.packets <- (Int64.add st.packets 1L);
          st.bin_bytes <- (Int64.add st.bin_bytes (Int64.of_int l));
          st.bin_packets <- (Int64.add st.bin_packets 1L);
          let ts_now = (Clock.time ()) in 
          (if ((ts_now -. st.last_time) >= 1.0) then
             print_data c st ts_now
           else
             Lwt.return_unit) >>= fun () ->
          iperf_h flow
        end
    in
    iperf_h flow >>= fun () ->
    Lwt.wakeup server_done_u ();
    Lwt.return_unit

  let tcp_iperf () =
    or_error "console" Console.connect "console" >>= fun c ->
    let port = 5001 in

    let server_ready, server_ready_u = Lwt.wait () in
    let server_done, server_done_u = Lwt.wait () in
    let timeout = 120.0 in

    Lwt.pick [
      (Lwt_unix.sleep timeout >>= fun () -> (* timeout *)
       fail "iperf test timed out after %f seconds" timeout) ;

      (server_ready >>= fun () ->
       Lwt_unix.sleep 1.0 >>= fun() ->
       C.log_s c (Printf.sprintf "I am client with IP %s, trying to connect to server @ %s:%d" (Ipaddr.V4.to_string client_ip) (Ipaddr.V4.to_string server_ip) port) >>= fun () ->
       V.create_stack c backend client_ip netmask [gw] >>= fun client_s ->
       iperfclient c client_s server_ip port) ;

      (Lwt_unix.sleep 1.0 >>= fun () ->
       C.log_s c (Printf.sprintf "I am server with IP %s, expecting connections on port %d" (Ipaddr.V4.to_string server_ip) port) >>= fun () ->
       V.create_stack c backend server_ip netmask [gw] >>= fun server_s ->
       V.Stackv4.listen_tcpv4 server_s ~port (iperf c server_s server_done_u);
       Lwt.wakeup server_ready_u ();
       V.Stackv4.listen server_s) ] >>= fun () ->
    C.log_s c "Waiting for server_done..." >>= fun () ->
    server_done >>= fun () ->
    Lwt.return_unit (* exit cleanly *)

  let record_pcap =
    V.record_pcap backend
end

let test_tcp_iperf_two_stacks_basic () =
  let module Test = Test_iperf (Vnetif_backends.Basic) in
  Test.record_pcap "tests/pcap/tcp_iperf_two_stacks_basic.pcap" Test.tcp_iperf

let test_tcp_iperf_two_stacks_trailing_bytes () =
  let module Test = Test_iperf (Vnetif_backends.Trailing_bytes) in
  Test.record_pcap "tests/pcap/tcp_iperf_two_stacks_trailing_bytes.pcap" Test.tcp_iperf

let suite = [
  "test_tcp_iperf_two_stacks_basic" , test_tcp_iperf_two_stacks_basic;
  "test_tcp_iperf_two_stacks_trailing_bytes" , test_tcp_iperf_two_stacks_trailing_bytes;
]
