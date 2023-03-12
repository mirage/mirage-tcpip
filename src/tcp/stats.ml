(*
 * Copyright (c) 2015 Thomas Gazagnaire <thomas@gazagnaire.org>
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

module Gc = struct

  let gc = ref false
  let enable () = gc := true
  let disable () = gc := false

  let full = ref false
  let full_major b = full := b

  let words () =
    let t = Gc.stat () in
    t.Gc.live_words / 1_000

  let run_full_major () = if !full then Gc.full_major ()

  let pp fmt () =
    match !gc with
    | false -> ()
    | true  ->
      run_full_major ();
      Format.fprintf fmt "|%dk" (words ())

end

type t = {
  mutable tcp_listens : int;
  mutable tcp_channels: int;
  mutable tcp_connects: int;
  mutable tcp_timers  : int;
  mutable total_established : int;
  mutable total_passive_connections : int;
  mutable total_active_connections : int;
  mutable total_timers : int;
}

let metrics =
  let open Metrics in
  let doc = "TCP metrics" in
  let data t =
    Data.v
      [ int "syn-rcvd state" t.tcp_listens
      ; int "established state" t.tcp_channels
      ; int "client connections" t.tcp_connects
      ; int "timers" t.tcp_timers
      ; int "total timers" t.total_timers
      ; int "total established" t.total_established
      ; int "total syn-rcvd" t.total_passive_connections
      ; int "total client" t.total_active_connections ]
  in
  Src.v ~doc ~tags:Metrics.Tags.[] ~data "tcp"

let pp fmt t = Format.fprintf fmt "[%d|%d|%d|%d%a]"
    t.tcp_timers
    t.tcp_listens
    t.tcp_channels
    t.tcp_connects
    Gc.pp ()

let singleton =
  {
    tcp_listens = 0;
    tcp_channels = 0;
    tcp_connects = 0;
    tcp_timers = 0;
    total_timers = 0;
    total_established = 0;
    total_passive_connections = 0;
    total_active_connections = 0;
  }

let metrics () =
  Metrics.add metrics (fun x -> x) (fun d -> d singleton)

let incr_listen () =
  singleton.tcp_listens <- succ singleton.tcp_listens;
  singleton.total_passive_connections <- succ singleton.total_passive_connections;
  metrics ()
let decr_listen () =
  singleton.tcp_listens <- pred singleton.tcp_listens;
  metrics ()

let incr_channel () =
  singleton.tcp_channels <- succ singleton.tcp_channels;
  singleton.total_established <- succ singleton.total_established;
  metrics ()
let decr_channel () =
  singleton.tcp_channels <- pred singleton.tcp_channels;
  metrics ()

let incr_connect () =
  singleton.tcp_connects <- succ singleton.tcp_connects;
  singleton.total_active_connections <- succ singleton.total_active_connections;
  metrics ()
let decr_connect () =
  singleton.tcp_connects <- pred singleton.tcp_connects;
  metrics ()

let incr_timer () =
  singleton.tcp_timers <- succ singleton.tcp_timers;
  singleton.total_timers <- succ singleton.total_timers;
  metrics ()
let decr_timer () =
  singleton.tcp_timers <- pred singleton.tcp_timers;
  metrics ()

