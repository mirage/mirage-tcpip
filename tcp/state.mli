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

val debug: Log.t

type action =
  | Passive_open
  | Recv_rst
  | Recv_rstack of Sequence.t (* ACK number *)
  | Recv_synack of Sequence.t
  | Recv_ack of Sequence.t
  | Recv_fin
  (* | Recv_finack of Sequence.t *)
  | Send_syn of Sequence.t
  | Send_synack of Sequence.t
  | Send_rst
  | Send_fin of Sequence.t
  | Timeout

val pp_action: Format.formatter -> action -> unit

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

val pp_tcpstate : Format.formatter -> tcpstate -> unit

type close_cb = unit -> unit

type t

val state : t -> tcpstate
val start : on_close:close_cb -> t

val pp: Format.formatter -> t -> unit

module Make(Time : V1_LWT.TIME) : sig
  val fin_wait_2_time : float
  (* when in state fin_wait_2, use this as a timeout parameter  *)
  val time_wait_time : float
    (* when in state Time_wait, wait this long before transitioning to Closed *)
  val finwait2timer : t -> float -> unit Lwt.t
(* [finwait2timer t timeout] waits for the given amount of time, then if the
   state is still Fin_wait_2, sets the state to closed and calls on_close.  If
   the state is other than Fin_wait_2, it is assumed that whatever set the state
   to something else has handled the closure and the state is not changed. *)
  val timewait : t -> float -> unit Lwt.t
(* [timewait t time] waits for time, then sets the state to closed and calls
   on_close *)
  val tick : t -> action -> unit
end
