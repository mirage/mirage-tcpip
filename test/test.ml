(*
 * Copyright (c) 2013 Thomas Gazagnaire <thomas@gazagnaire.org>
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

let suite = [
  "checksums"      , Test_checksums.suite   ;
  "ipv4"           , Test_ipv4.suite        ;
  "ipv6"           , Test_ipv6.suite        ;
  "icmpv4"         , Test_icmpv4.suite      ;
  "udp"            , Test_udp.suite         ;
  "tcp_window"     , Test_tcp_window.suite  ;
  "tcp_options"    , Test_tcp_options.suite ;
  "mtu+tcp"        , Test_mtus.suite        ;
  "rfc5961"        , Test_rfc5961.suite     ;
  "socket"         , Test_socket.suite      ;
  "connect"        , Test_connect.suite     ;
  "connect_ipv6"   , Test_connect_ipv6.suite     ;
  "deadlock"       , Test_deadlock.suite    ;
  "iperf"          , Test_iperf.suite       ;
  "iperf_ipv6"     , Test_iperf_ipv6.suite       ;
  "keepalive"      , Test_keepalive.suite   ;
  "simultaneous_close", Test_simulatenous_close.suite
]

let run test () =
  Lwt_main.run (test ())

let () =
  Printexc.record_backtrace true;
  Mirage_crypto_rng_unix.initialize (module Mirage_crypto_rng.Fortuna);
  (* enable logging to stdout for all modules *)
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs.set_level ~all:true (Some Logs.Debug);
  (* Uncomment to enable tracing *)
  (*let buffer = MProf_unix.mmap_buffer ~size:1000000 "trace.ctf" in
  let trace_config = MProf.Trace.Control.make buffer MProf_unix.timestamper in
  MProf.Trace.Control.start trace_config;*)
  let suite = List.map (fun (n, s) ->
      n, List.map (fun (d, s, f) -> d, s, run f) s
    ) suite
  in
  let filter ~name ~index =
    (* Lwt_bytes (as of 5.5.0) on Windows doesn't support UDP. *)
    let skip = [
        3 (* no_leak_fds_in_udpv4 *);
        5 (* no_leak_fds_in_udpv6 *);
        7 (* no_leak_fds_in_udpv4v6 *);
        9 (* no_leak_fds_in_udpv4v6_2 *);
        11 (* no_leak_fds_in_udpv4v6_3 *);
        13 (* no_leak_fds_in_udpv4v6_4 *);
        15 (* no_leak_fds_in_udpv4v6_5 *);
      ] in
    if Sys.win32 && name = "socket" && List.mem index skip then `Skip else `Run
  in
  Alcotest.run "tcpip" suite ~filter
