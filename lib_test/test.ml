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
  "arp"            , Test_arp.suite         ;
  "connect"        , Test_connect.suite     ;
  "iperf"          , Test_iperf.suite       ;
  "tcp_options"    , Test_tcp_options.suite ;
  "tcp_state"      , Test_tcp_state.suite   ;
]

let run test () =
  Lwt_main.run (test ())

let () =
  (* Enable TCP debug output *)
  let open Tcp in
  [Segment.info; Segment.debug; Pcb.info; Pcb.debug] |> List.iter (fun log ->
      Log.enable log;
      Log.set_stats log false
    );
  (* Uncomment to enable tracing *)
  (*let buffer = MProf_unix.mmap_buffer ~size:1000000 "trace.ctf" in
  let trace_config = MProf.Trace.Control.make buffer MProf_unix.timestamper in
  MProf.Trace.Control.start trace_config;*)
  let suite = List.map (fun (n, s) ->
      n, List.map (fun (d, s, f) -> d, s, run f) s
    ) suite
  in
  Alcotest.run "tcpip" suite
