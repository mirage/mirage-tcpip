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
open Printf

let debug = Log.create "State"

type action =
  | Passive_open
  | Recv_rst
  | Recv_synack of Sequence.t
  | Recv_ack of Sequence.t
  | Recv_fin
  (* | Recv_finack of Sequence.t *)
  | Send_syn of Sequence.t
  | Send_synack of Sequence.t
  | Send_rst
  | Send_fin of Sequence.t
  | Timeout

type tcpstate =
  | Closed
  | Listen
  | Syn_rcvd of Sequence.t
  | Syn_sent of Sequence.t
  | Established
  | Close_wait
  | Last_ack of Sequence.t
  | Fin_wait_1 of Sequence.t
  | Fin_wait_2
  | Closing of Sequence.t
  | Time_wait
  | Reset

type close_cb = unit -> unit

type t = {
  on_close: close_cb;
  mutable state: tcpstate;
}

let start ~on_close =
  { on_close; state=Closed }

let state t = t.state

let pp_action fmt = function
  | Passive_open  -> Log.ps fmt "Passive_open"
  | Recv_rst      -> Log.ps fmt "Recv_rst"
  | Recv_synack x -> Log.pf fmt "Recv_synack(%a)" Sequence.pp x
  | Recv_ack x    -> Log.pf fmt "Recv_ack(%a)" Sequence.pp x
  | Recv_fin      -> Log.ps fmt "Recv_fin"
  (*  | Recv_finack x -> pf fmt "Recv_finack(%a)" Sequence.pp x *)
  | Send_syn x    -> Log.pf fmt "Send_syn(%a)" Sequence.pp x
  | Send_synack x -> Log.pf fmt "Send_synack(%a)" Sequence.pp x
  | Send_rst      -> Log.ps fmt "Send_rst"
  | Send_fin x    -> Log.pf fmt "Send_fin(%a)" Sequence.pp x
  | Timeout       -> Log.ps fmt "Timeout"

let pp_tcpstate fmt = function
  | Closed       -> Log.ps fmt "Closed"
  | Listen       -> Log.ps fmt "Listen"
  | Syn_rcvd x   -> Log.pf fmt "Syn_rcvd(%a)" Sequence.pp x
  | Syn_sent x   -> Log.pf fmt "Syn_sent(%a)" Sequence.pp x
  | Established  -> Log.ps fmt "Established"
  | Close_wait   -> Log.ps fmt "Close_wait"
  | Last_ack x   -> Log.pf fmt "Last_ack(%a)" Sequence.pp x
  | Fin_wait_1 x -> Log.pf fmt "Fin_wait_1(%a)" Sequence.pp x
  | Fin_wait_2   -> Log.pf fmt "Fin_wait_2"
  | Closing x    -> Log.pf fmt "Closing(%a)" Sequence.pp x
  | Time_wait    -> Log.ps fmt "Time_wait"
  | Reset        -> Log.ps fmt "Reset"

let pp fmt t = Log.pf fmt "{ %a }" pp_tcpstate t.state

module Make(Time:V1_LWT.TIME) = struct

  let fin_wait_2_time = (* 60. *) 10.
  let time_wait_time = (* 30. *) 2.

  let rec finwait2timer t timeout =
    Log.f debug (fun fmt -> Log.pf fmt "finwait2timer %.02f" timeout);
    Time.sleep timeout >>= fun () ->
    match t.state with
    | Fin_wait_2 ->
      Log.s debug "finwait2timer: Fin_wait_2";
      t.state <- Closed;
      t.on_close ();
      Lwt.return_unit
    | s ->
      Log.f debug (fun fmt -> Log.pf fmt "finwait2timer: %a" pp_tcpstate s);
      Lwt.return_unit

  let timewait t twomsl =
    Log.f debug (fun fmt -> Log.pf fmt "timewait %.02f" twomsl);
    Time.sleep twomsl >>= fun () ->
    t.state <- Closed;
    Log.s debug "timewait on_close";
    t.on_close ();
    Lwt.return_unit

  let tick t (i:action) =
    let diffone x y = Sequence.incr y = x in
    let tstr s (i:action) =
      match s, i with
      | Closed, Passive_open -> Listen
      | Closed, Send_syn a -> Syn_sent a
      | Listen, Send_synack a -> Syn_rcvd a
      | Syn_rcvd _, Timeout -> t.on_close (); Closed
      | Syn_rcvd _, Recv_rst -> Closed
      | Syn_sent _, Timeout -> t.on_close (); Closed
      | Syn_rcvd a, Recv_ack b -> if diffone b a then Established else Syn_rcvd a
      | Syn_sent a, Recv_synack b -> if diffone b a then Established else Syn_sent a
      | Syn_sent a, Recv_rstack b ->
        if diffone b a then begin t.on_close (); Closed end
        else Syn_sent a
      | Established, Recv_ack _ -> Established
      | Established, Send_fin a -> Fin_wait_1 a
      | Established, Recv_fin -> Close_wait
      | Established, Timeout ->  t.on_close (); Closed
      | Established, Recv_rst -> t.on_close (); Reset
      | Fin_wait_1 a, Recv_ack b ->
        if diffone b a then begin
          Lwt.async (fun () -> finwait2timer t fin_wait_2_time);
          Fin_wait_2
            (* so the first time we enter fin_wait_2, we set the count to 0 and
               spawn a waiting thread; the waiting thread only closes the
               connection if the state still matches the number.  So if we keep
               receiving ACKs, won't we never close? That seems incorrect. *)
        end else
          Fin_wait_1 a
      | Fin_wait_1 a, Recv_fin -> Closing a
      | Fin_wait_1 _, Timeout -> t.on_close (); Closed
      | Fin_wait_1 _, Recv_rst -> t.on_close (); Reset
      | Fin_wait_2 i, Recv_ack _ -> Fin_wait_2 (i + 1)
      | Fin_wait_2 _, Recv_rst -> t.on_close (); Reset
      | Fin_wait_2 _, Recv_fin ->
        Lwt.async (fun () -> timewait t time_wait_time);
        Time_wait
      | Closing a, Recv_ack b -> if diffone b a then Time_wait else Closing a
      | Closing _, Timeout -> t.on_close (); Closed
      | Closing _, Recv_rst -> t.on_close (); Reset
      | Time_wait, Timeout -> t.on_close (); Closed
      | Close_wait,  Send_fin a -> Last_ack a
      | Close_wait,  Timeout -> t.on_close (); Closed
      | Close_wait,  Recv_rst -> t.on_close (); Reset
      | Last_ack a, Recv_ack b -> if diffone b a then (t.on_close (); Closed) else Last_ack a
      | Last_ack _, Timeout -> t.on_close (); Closed
      | _, Recv_rst _ -> t.on_close (); Closed
      | x, _ -> x
    in
    let old_state = t.state in
    let new_state = tstr t.state i in
    Log.f debug (fun fmt ->
        Log.pf fmt "%a  - %a -> %a"
          pp_tcpstate old_state pp_action i pp_tcpstate new_state);
    t.state <- new_state;

end
