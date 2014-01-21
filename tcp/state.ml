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

type action =
  | Passive_open
  | Recv_rst
  | Recv_synack of Sequence.t
  | Recv_ack of Sequence.t
  | Recv_fin
  | Recv_finack of Sequence.t
  | Send_syn of Sequence.t
  | Send_synack of Sequence.t
  | Send_rst
  | Send_fin of Sequence.t
  | Timeout

type tcpstates = 
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

type close_cb = unit -> unit

type t = {
  on_close: close_cb;  
  mutable state: tcpstates;
}

exception Bad_transition of (tcpstates * action)

let t ~on_close =
  { on_close; state=Closed }

let state t = t.state

let action_to_string = function
  | Passive_open -> "Passive_open"
  | Recv_rst -> "Recv_rst"
  | Recv_synack x -> "Recv_synack " ^ (Sequence.to_string x)
  | Recv_ack x -> "Recv_ack " ^ (Sequence.to_string x)
  | Recv_fin -> "Recv_fin"
  | Recv_finack x -> "Recv_finack " ^ (Sequence.to_string x)
  | Send_syn x -> "Send_syn " ^ (Sequence.to_string x)
  | Send_synack x -> "Send_synack " ^ (Sequence.to_string x)
  | Send_rst -> "Send_rst"
  | Send_fin x -> "Send_fin " ^ (Sequence.to_string x)
  | Timeout -> "Timeout"

let tcpstates_to_string = function
  | Closed -> "Closed"
  | Listen -> "Listen"
  | Syn_rcvd x -> "Syn_rcvd " ^ (Sequence.to_string x)
  | Syn_sent x -> "Syn_sent " ^ (Sequence.to_string x)
  | Established -> "Established"
  | Close_wait -> "Close_wait"
  | Last_ack x -> "Last_ack " ^ (Sequence.to_string x)
  | Fin_wait_1 x -> "Fin_wait_1 " ^ (Sequence.to_string x)
  | Fin_wait_2 i -> "Fin_wait_2 " ^ (string_of_int i)
  | Closing x -> "Closing " ^ (Sequence.to_string x)
  | Time_wait -> "Time_wait"

let to_string t =
  sprintf "{ %s }" (tcpstates_to_string t.state)
