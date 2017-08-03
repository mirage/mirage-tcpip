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

open Common
open Vnetif_common
open Lwt.Infix

module Test_iperf (B : Vnetif_backends.Backend) = struct

  module V = VNETIF_STACK (B)

  let netmask = 24
  let gw = Some (Ipaddr.V4.of_string_exn "10.0.0.1")
  let client_ip = Ipaddr.V4.of_string_exn "10.0.0.101"
  let server_ip = Ipaddr.V4.of_string_exn "10.0.0.100"

  type stats = {
    mutable bytes: int64;
    mutable packets: int64;
    mutable bin_bytes:int64;
    mutable bin_packets: int64;
    mutable start_time: int64;
    mutable last_time: int64;
  }

  type network = {
    backend : B.t;
    server : V.Stackv4.t;
    client : V.Stackv4.t;
  }

  let default_network ?(backend = B.create ()) () =
    V.create_stack backend client_ip netmask gw >>= fun client ->
    V.create_stack backend server_ip netmask gw >>= fun server ->
      Lwt.return {backend; server; client}

  let msg =
    let m = "01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" in
    let rec build l = function
            | 0 -> l
            | n -> build (m :: l) (n - 1)
    in
    String.concat "" @@ build [] 60

  let mlen = String.length msg

  let err_eof () = failf "EOF while writing to TCP flow"

  let err_connect e ip port () =
    let err = Format.asprintf "%a" V.Stackv4.TCPV4.pp_error e in
    let ip  = Ipaddr.V4.to_string ip in
    failf "Unable to connect to %s:%d: %s" ip port err

  let err_write e () =
    let err = Format.asprintf "%a" V.Stackv4.TCPV4.pp_write_error e in
    failf "Error while writing to TCP flow: %s" err

  let err_read e () =
    let err = Format.asprintf "%a" V.Stackv4.TCPV4.pp_error e in
    failf "Error in server while reading: %s" err

  let write_and_check flow buf =
    V.Stackv4.TCPV4.write flow buf >>= function
    | Ok ()          -> Lwt.return_unit
    | Error `Closed -> V.Stackv4.TCPV4.close flow >>= err_eof
    | Error e -> V.Stackv4.TCPV4.close flow >>= err_write e

  let tcp_connect t (ip, port) =
    V.Stackv4.TCPV4.create_connection t (ip, port) >>= function
    | Error e -> err_connect e ip port ()
    | Ok f    -> Lwt.return f

  let iperfclient s amt dest_ip dport =
    let iperftx flow =
      Logs.info (fun f -> f  "Iperf client: Made connection to server.");
      let a = Cstruct.sub (Io_page.(to_cstruct (get 1))) 0 mlen in
      Cstruct.blit_from_string msg 0 a 0 mlen;
      let rec loop = function
        | 0 -> Lwt.return_unit
        | n -> write_and_check flow a >>= fun () -> loop (n-1)
      in
      loop (amt / mlen) >>= fun () ->
      let a = Cstruct.sub a 0 (amt - (mlen * (amt/mlen))) in
      write_and_check flow a >>= fun () ->
      V.Stackv4.TCPV4.close flow
    in
    Logs.info (fun f -> f  "Iperf client: Attempting connection.");
    tcp_connect (V.Stackv4.tcpv4 s) (dest_ip, dport) >>= fun flow ->
    iperftx flow >>= fun () ->
    Logs.debug (fun f -> f  "Iperf client: Done.");
    Lwt.return_unit

  let print_data st ts_now =
    let server = Int64.sub ts_now st.start_time in
    let rate =
      Int64.(div (div st.bin_bytes (sub ts_now st.last_time))) 125L
    in
    let live_words = Gc.((stat()).live_words) in
    Logs.debug (fun f -> f  "Iperf server: t = %.0Lu, rate = %.0Lu KBits/ns, totbytes = %Ld, \
                             live_words = %d" server rate st.bytes live_words);
    st.last_time <- ts_now;
    st.bin_bytes <- 0L;
    st.bin_packets <- 0L;
    Lwt.return_unit

  let iperf clock _s server_done_u flow =
    (* debug is too much for us here *)
    Logs.set_level ~all:true (Some Logs.Info);
    Logs.info (fun f -> f  "Iperf server: Received connection.");
    let t0 = Clock.elapsed_ns clock in
    let st = {
      bytes=0L; packets=0L; bin_bytes=0L; bin_packets=0L; start_time = t0;
      last_time = t0
    } in
    let rec iperf_h flow =
      V.Stackv4.TCPV4.read flow >|= Rresult.R.get_ok >>= function
      | `Eof ->
        let ts_now = Clock.elapsed_ns clock in
        st.bin_bytes <- st.bytes;
        st.bin_packets <- st.packets;
        st.last_time <- st.start_time;
        print_data st ts_now >>= fun () ->
        V.Stackv4.TCPV4.close flow >>= fun () ->
        Logs.info (fun f -> f  "Iperf server: Done - closed connection.");
        Lwt.return_unit
      | `Data data ->
        begin
          let l = Cstruct.len data in
          st.bytes <- (Int64.add st.bytes (Int64.of_int l));
          st.packets <- (Int64.add st.packets 1L);
          st.bin_bytes <- (Int64.add st.bin_bytes (Int64.of_int l));
          st.bin_packets <- (Int64.add st.bin_packets 1L);
          let ts_now = Clock.elapsed_ns clock in
          (if (Int64.sub ts_now st.last_time >= 1L) then
             print_data st ts_now
           else
             Lwt.return_unit) >>= fun () ->
          iperf_h flow
        end
    in
    iperf_h flow >>= fun () ->
    Lwt.wakeup server_done_u ();
    Lwt.return_unit

  let tcp_iperf ~server ~client amt timeout () =
    let port = 5001 in

    let server_ready, server_ready_u = Lwt.wait () in
    let server_done, server_done_u = Lwt.wait () in
    let server_s, client_s = server, client in

    let ip_of s = V.Stackv4.IPV4.get_ip (V.Stackv4.ipv4 s) |> List.hd in

    Lwt.pick [
      (Lwt_unix.sleep timeout >>= fun () -> (* timeout *)
       failf "iperf test timed out after %f seconds" timeout);

      (server_ready >>= fun () ->
       Lwt_unix.sleep 0.1 >>= fun () -> (* Give server 0.1 s to call listen *)
       Logs.info (fun f -> f  "I am client with IP %a, trying to connect to server @ %a:%d"
         Ipaddr.V4.pp_hum (ip_of client_s) Ipaddr.V4.pp_hum (ip_of server_s) port);
       Lwt.async (fun () -> V.Stackv4.listen client_s);
       iperfclient client_s amt (ip_of server) port);

      (Logs.info (fun f -> f  "I am server with IP %a, expecting connections on port %d"
         Ipaddr.V4.pp_hum (V.Stackv4.IPV4.get_ip (V.Stackv4.ipv4 server_s) |> List.hd)
         port);
       Mclock.connect () >>= fun clock ->
       V.Stackv4.listen_tcpv4 server_s ~port (iperf clock server_s server_done_u);
       Lwt.wakeup server_ready_u ();
       V.Stackv4.listen server_s) ] >>= fun () ->

    Logs.info (fun f -> f  "Waiting for server_done...");
    server_done >>= fun () ->
    Lwt.return_unit (* exit cleanly *)
end

let test_tcp_iperf_two_stacks_basic amt timeout () =
  let module Test = Test_iperf (Vnetif_backends.Basic) in
  Test.default_network () >>= fun { backend; Test.client; Test.server } ->
  Test.V.record_pcap backend
    (Printf.sprintf "tcp_iperf_two_stacks_basic_%d.pcap" amt)
    (Test.tcp_iperf ~server ~client amt timeout)

let test_tcp_iperf_two_stacks_mtu amt timeout () =
  let module Test = Test_iperf (Vnetif_backends.Mtu_enforced) in
  Test.default_network () >>= fun { backend; Test.client; Test.server } ->
  Test.V.record_pcap backend
    (Printf.sprintf "tcp_iperf_two_stacks_mtu_%d.pcap" amt)
    (Test.tcp_iperf ~server ~client amt timeout)

let test_tcp_iperf_two_stacks_trailing_bytes amt timeout () =
  let module Test = Test_iperf (Vnetif_backends.Trailing_bytes) in
  Test.default_network () >>= fun { backend; Test.client; Test.server } ->
  Test.V.record_pcap backend
    (Printf.sprintf "tcp_iperf_two_stacks_trailing_bytes_%d.pcap" amt)
    (Test.tcp_iperf ~server ~client amt timeout)

let test_tcp_iperf_two_stacks_uniform_packet_loss amt timeout () =
  let module Test = Test_iperf (Vnetif_backends.Uniform_packet_loss) in
  Test.default_network () >>= fun { backend; Test.client; Test.server } ->
  Test.V.record_pcap backend
    (Printf.sprintf "tcp_iperf_two_stacks_uniform_packet_loss_%d.pcap" amt)
    (Test.tcp_iperf ~server ~client amt timeout)

let test_tcp_iperf_two_stacks_uniform_packet_loss_no_payload amt timeout () =
  let module Test = Test_iperf (Vnetif_backends.Uniform_no_payload_packet_loss) in
  Test.default_network () >>= fun { backend; Test.client; Test.server } ->
  Test.V.record_pcap backend
    (Printf.sprintf "tcp_iperf_two_stacks_uniform_packet_loss_no_payload_%d.pcap" amt)
    (Test.tcp_iperf ~server ~client amt timeout)

let test_tcp_iperf_two_stacks_drop_1sec_after_1mb amt timeout () =
  let module Test = Test_iperf (Vnetif_backends.Drop_1_second_after_1_megabyte) in
  Test.default_network () >>= fun { backend; Test.client; Test.server } ->
  Test.V.record_pcap backend
    "tcp_iperf_two_stacks_drop_1sec_after_1mb.pcap"
    (Test.tcp_iperf ~server ~client amt timeout)

let amt_quick = 10_000_000
let amt_slow  = amt_quick * 100

let suite = [

  "iperf with two stacks, basic tests", `Quick,
  test_tcp_iperf_two_stacks_basic amt_quick 120.0;

  "iperf with two stacks, over an MTU-enforcing backend", `Quick,
  test_tcp_iperf_two_stacks_mtu amt_quick 120.0;

  "iperf with two stacks, testing trailing_bytes", `Quick,
  test_tcp_iperf_two_stacks_trailing_bytes amt_quick 120.0;

  "iperf with two stacks and uniform packet loss", `Quick,
  test_tcp_iperf_two_stacks_uniform_packet_loss amt_quick 120.0;

  "iperf with two stacks and uniform packet loss of packets with no payload", `Quick,
  test_tcp_iperf_two_stacks_uniform_packet_loss_no_payload amt_quick 120.0;

  "iperf with two stacks and uniform packet loss of packets with no payload, longer", `Slow,
  test_tcp_iperf_two_stacks_uniform_packet_loss_no_payload amt_slow 240.0;

  "iperf with two stacks, basic tests, longer", `Slow,
  test_tcp_iperf_two_stacks_basic amt_slow 240.0;

  "iperf with two stacks and uniform packet loss, longer", `Slow,
  test_tcp_iperf_two_stacks_uniform_packet_loss amt_slow 240.0;

  "iperf with two stacks drop 1 sec after 1 mb", `Quick,
  test_tcp_iperf_two_stacks_drop_1sec_after_1mb amt_quick 120.0;

]
