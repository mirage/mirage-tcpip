(*
 * Copyright (c) 2012 Balraj Singh <bs375@cl.cam.ac.uk>
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

open Lwt.Infix

let src = Logs.Src.create "tcptimer" ~doc:"Mirage TCP Tcptimer module"
module Log = (val Logs.src_log src : Logs.LOG)

type time = int64

type tr =
  | Stoptimer
  | Continue of Sequence.t
  | ContinueSetPeriod of (time * Sequence.t)

type t = {
  expire: (Sequence.t -> tr Lwt.t);
  mutable period_ns: time;
  mutable running: bool;
}

module Make(Time:Mirage_time_lwt.S) = struct
  let t ~period_ns ~expire =
    let running = false in
    {period_ns; expire; running}

  let timerloop t s =
    Log.debug (fun f -> f "timerloop");
    Stats.incr_timer ();
    let rec aux t s =
      Log.debug (fun f -> f "timerloop: sleeping for %Lu ns" t.period_ns);
      Time.sleep_ns t.period_ns >>= fun () ->
      t.expire s >>= function
      | Stoptimer ->
        Stats.decr_timer ();
        t.running <- false;
        Log.debug (fun f -> f "timerloop: stoptimer");
        Lwt.return_unit
      | Continue d ->
        Log.debug (fun f -> f "timerloop: continuer");
        aux t d
      | ContinueSetPeriod (p, d) ->
        Log.debug (fun f -> f "timerloop: continuesetperiod (new period: %Lu ns)" p);
        t.period_ns <- p;
        aux t d
    in
    aux t s

  let period_ns t = t.period_ns

  let start t ?(p=(period_ns t)) s =
    if not t.running then begin
      t.period_ns <- p;
      t.running <- true;
      Lwt.async (fun () -> timerloop t s);
      Lwt.return_unit
    end else
      Lwt.return_unit
end
