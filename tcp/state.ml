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

open Lwt
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
  | Fin_wait_2 of int
  | Closing of Sequence.t
  | Time_wait
  | Reset

type close_cb = unit -> unit

type t = {
  on_close: close_cb;
  mutable state: tcpstate;
}

let t ~on_close =
  { on_close; state=Closed }

let state t = t.state

let ps = Format.pp_print_string
let pf = Format.fprintf

let pp_action fmt = function
  | Passive_open  -> ps fmt "Passive_open"
  | Recv_rst      -> ps fmt "Recv_rst"
  | Recv_synack x -> pf fmt "Recv_synack(%a)" Sequence.pp x
  | Recv_ack x    -> pf fmt "Recv_ack(%a)" Sequence.pp x
  | Recv_fin      -> ps fmt "Recv_fin"
  (*  | Recv_finack x -> pf fmt "Recv_finack(%a)" Sequence.pp x *)
  | Send_syn x    -> pf fmt "Send_syn(%a)" Sequence.pp x
  | Send_synack x -> pf fmt "Send_synack(%a)" Sequence.pp x
  | Send_rst      -> ps fmt "Send_rst"
  | Send_fin x    -> pf fmt "Send_fin(%a)" Sequence.pp x
  | Timeout       -> ps fmt "Timeout"

let pp_tcpstate fmt = function
  | Closed       -> ps fmt "Closed"
  | Listen       -> ps fmt "Listen"
  | Syn_rcvd x   -> pf fmt "Syn_rcvd(%a)" Sequence.pp x
  | Syn_sent x   -> pf fmt "Syn_sent(%a)" Sequence.pp x
  | Established  -> ps fmt "Established"
  | Close_wait   -> ps fmt "Close_wait"
  | Last_ack x   -> pf fmt "Last_ack(%a)" Sequence.pp x
  | Fin_wait_1 x -> pf fmt "Fin_wait_1(%a)" Sequence.pp x
  | Fin_wait_2 i -> pf fmt "Fin_wait_2(%d)" i
  | Closing x    -> pf fmt "Closing(%a)" Sequence.pp x
  | Time_wait    -> ps fmt "Time_wait"
  | Reset        -> ps fmt "Reset"

let pp fmt t = Format.fprintf fmt "{ %a }" pp_tcpstate t.state

module Make(Time:V1_LWT.TIME) = struct

  let fin_wait_2_time = (* 60. *) 10.
  let time_wait_time = (* 30. *) 2.

  let rec finwait2timer t count timeout =
    Log.f debug "finwait2timer %.02f" timeout;
    Time.sleep timeout
    >>= fun () ->
    match t.state with
    | Fin_wait_2 i ->
      Log.f debug "finwait2timer: Fin_wait_2";
      if i = count then begin
        t.state <- Closed;
        t.on_close ();
        return_unit
      end else begin
        finwait2timer t i timeout
      end
    | s ->
      Log.f debug "finwait2timer: %a" pp_tcpstate s;
      return_unit

  let timewait t twomsl =
    Log.f debug "timewait %.02f" twomsl;
    Time.sleep twomsl
    >>= fun () ->
    t.state <- Closed;
    Log.f debug "timewait on_close";
    t.on_close ();
    return_unit

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
      | Syn_sent a, Recv_synack b-> if diffone b a then Established else Syn_sent a
      | Syn_rcvd a, Recv_ack b -> if diffone b a then Established else Syn_rcvd a
      | Established, Recv_ack _ -> Established
      | Established, Send_fin a -> Fin_wait_1 a
      | Established, Recv_fin -> Close_wait
      | Established, Timeout ->  t.on_close (); Closed
      | Established, Recv_rst -> t.on_close (); Reset
      | Fin_wait_1 a, Recv_ack b ->
        if diffone b a then
          let count = 0 in
          let _ = finwait2timer t count fin_wait_2_time in
          Fin_wait_2 count
        else
          Fin_wait_1 a
      | Fin_wait_1 a, Recv_fin -> Closing a
      | Fin_wait_1 _, Timeout -> t.on_close (); Closed
      | Fin_wait_1 _, Recv_rst -> t.on_close (); Reset
      | Fin_wait_2 i, Recv_ack _ -> Fin_wait_2 (i + 1)
      | Fin_wait_2 _, Recv_fin -> let _ = timewait t time_wait_time in Time_wait
      | Fin_wait_2 _, Recv_rst -> t.on_close (); Reset
      | Closing a, Recv_ack b -> if diffone b a then Time_wait else Closing a
      | Closing _, Timeout -> t.on_close (); Closed
      | Closing _, Recv_rst -> t.on_close (); Reset
      | Time_wait, Timeout -> t.on_close (); Closed
      | Close_wait,  Send_fin a -> Last_ack a
      | Close_wait,  Timeout -> t.on_close (); Closed
      | Close_wait,  Recv_rst -> t.on_close (); Reset
      | Last_ack a, Recv_ack b -> if diffone b a then (t.on_close (); Closed) else Last_ack a
      | Last_ack _, Timeout -> t.on_close (); Closed
      | Last_ack _, Recv_rst -> t.on_close (); Reset
      | x, _ -> x
    in
    let old_state = t.state in
    let new_state = tstr t.state i in
    Log.f debug "%a  - %a -> %a"
      pp_tcpstate old_state pp_action i pp_tcpstate new_state;
    t.state <- new_state;

end
