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
  "udp"            , Test_udp.suite            ;
  "socket"         , Test_socket.suite         ;
  "icmpv4"         , Test_icmpv4.suite         ;
  "tcp_options"    , Test_tcp_options.suite    ;
  "ip_options"     , Test_ip_options.suite     ;
  "ip_fragmentation",  Test_ip_fragmentation.suite  ;
  "rfc5961"        , Test_rfc5961.suite        ;
  "arp"            , Test_arp.suite            ;
  "connect"        , Test_connect.suite        ;
  "iperf"          , Test_iperf.suite          ; 
]

let run test () =
  Lwt_main.run (test ())

let () =
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
  Alcotest.run "tcpip" suite
