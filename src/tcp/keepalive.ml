(*
 * Copyright (c) 2017 Docker Inc
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

type action = [
  | `SendProbe
  | `Wait of Duration.t
  | `Close
]

type state = {
  probes_sent: int
}

let alive = {
  probes_sent = 0;
}

let next ~configuration ~ns state =
  let open Mirage_protocols.Keepalive in
  let after_ns = configuration.after in
  (* Wait until [time] has gone past *)
  if after_ns > ns
  then `Wait (Int64.sub after_ns ns), alive
  else begin
    let sending_probes_for_ns = Int64.sub ns after_ns in
    let interval_ns = configuration.interval in
    let should_have_sent = Int64.(to_int (div sending_probes_for_ns interval_ns)) in
    if should_have_sent > configuration.probes
    then `Close, state
    else
      if should_have_sent > state.probes_sent
      then `SendProbe, { probes_sent = should_have_sent } (* we don't want to send back-to-back probes *)
      else begin
        let since_last_probe_ns = Int64.rem sending_probes_for_ns interval_ns in
        `Wait (Int64.sub interval_ns since_last_probe_ns), state
      end
  end

  module Make(T:Mirage_time.S)(Clock:Mirage_clock.MCLOCK) = struct
    type t = {
      configuration: Mirage_protocols.Keepalive.t;
      callback: ([ `SendProbe | `Close ] -> unit Lwt.t);
      mutable state: state;
      mutable timer: unit Lwt.t;
      mutable start: int64;
    }
    (** A keep-alive timer *)

    let rec restart t =
      let open Lwt.Infix in
      let ns = Int64.sub (Clock.elapsed_ns ()) t.start in
      match next ~configuration:t.configuration ~ns t.state with
      | `Wait ns, state ->
        T.sleep_ns ns >>= fun () ->
        t.state <- state;
        restart t
      | `SendProbe, state ->
        t.callback `SendProbe >>= fun () ->
        t.state <- state;
        restart t
      | `Close, _ ->
        t.callback `Close >>= fun () ->
        Lwt.return_unit

    let create configuration callback =
      let state = alive in
      let timer = Lwt.return_unit in
      let start = Clock.elapsed_ns () in
      let t = { configuration; callback; state; timer; start } in
      t.timer <- restart t;
      t

    let refresh t =
      t.start <- Clock.elapsed_ns ();
      t.state <- alive;
      Lwt.cancel t.timer;
      t.timer <- restart t
  end
