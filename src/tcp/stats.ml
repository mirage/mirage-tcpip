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

type counter = MProf.Counter.t

let value = MProf.Counter.value

let pp_counter fmt t = Format.fprintf fmt "%d" (value t)

type t = {
  tcp_listens : counter;
  tcp_channels: counter;
  tcp_connects: counter;
  tcp_timers  : counter;
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
      [ int "syn-rcvd state" (MProf.Counter.value t.tcp_listens)
      ; int "established state" (MProf.Counter.value t.tcp_channels)
      ; int "client connections" (MProf.Counter.value t.tcp_connects)
      ; int "timers" (MProf.Counter.value t.tcp_timers)
      ; int "total timers" t.total_timers
      ; int "total established" t.total_established
      ; int "total syn-rcvd" t.total_passive_connections
      ; int "total client" t.total_active_connections ]
  in
  Src.v ~doc ~tags:Metrics.Tags.[] ~data "tcp"

let pp fmt t = Format.fprintf fmt "[%a|%a|%a|%a%a]"
    pp_counter t.tcp_timers
    pp_counter t.tcp_listens
    pp_counter t.tcp_channels
    pp_counter t.tcp_connects
    Gc.pp ()

let incr r = MProf.Counter.increase r 1
let decr r = MProf.Counter.increase r (-1)

let singleton =
  let make name = MProf.Counter.create ~name () in
  {
    tcp_listens = make "Tcp.listens";
    tcp_channels = make "Tcp.channels";
    tcp_connects = make "Tcp.connects";
    tcp_timers = make "Tcp.timers";
    total_timers = 0;
    total_established = 0;
    total_passive_connections = 0;
    total_active_connections = 0;
  }

let metrics () =
  Metrics.add metrics (fun x -> x) (fun d -> d singleton)

let incr_listen () =
  incr singleton.tcp_listens;
  singleton.total_passive_connections <- succ singleton.total_passive_connections;
  metrics ()
let decr_listen () = decr singleton.tcp_listens; metrics ()

let incr_channel () =
  incr singleton.tcp_channels;
  singleton.total_established <- succ singleton.total_established;
  metrics ()
let decr_channel () = decr singleton.tcp_channels; metrics ()

let incr_connect () =
  incr singleton.tcp_connects;
  singleton.total_active_connections <- succ singleton.total_active_connections;
  metrics ()
let decr_connect () = decr singleton.tcp_connects; metrics ()

let incr_timer () =
  incr singleton.tcp_timers;
  singleton.total_timers <- succ singleton.total_timers;
  metrics ()
let decr_timer () = decr singleton.tcp_timers; metrics ()

