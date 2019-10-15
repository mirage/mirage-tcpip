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

(** TCP keepalives.

    A TCP implementation may send "keep-alives" (empty TCP ACKs with the
    sequence number set to one less than the current sequence number for
    the connection) in order to provoke the peer to respond with an ACK
    of the current sequence number. If the peer doesn't recognise the
    connection (e.g. because the connection state has been dropped) then
    it will return a RST; if the peer (or the network in-between) fails
    to respond to a configured number of repeated probes then the
    connection is assumed to be lost.
*)

type action = [
  | `SendProbe          (** we should send a keep-alive now *)
  | `Wait of Duration.t (** sleep for a given number of nanoseconds *)
  | `Close              (** connection should be closed *)
]
(** An I/O action to perform *)

type state
(** State of a current connection *)

val alive: state
(** An alive connection *)

val next: configuration:Mirage_protocols.Keepalive.t -> ns:int64 -> state -> action * state
(** [next ~configuration ~ns state] returns the action we should take given
    that we last received a packet [ns] nanoseconds ago and the new state
    of the connection *)

module Make(T:Mirage_time.S)(Clock:Mirage_clock.MCLOCK): sig
  type t
  (** A keep-alive timer *)

  val create: Mirage_protocols.Keepalive.t -> ([ `SendProbe | `Close] -> unit Lwt.t) -> t
  (** [create configuration f clock] returns a keep-alive timer which will call
      [f] in future depending on both the [configuration] and any calls to
      [refresh] *)

  val refresh: t -> unit
  (** [refresh t] marks the connection [t] as alive. This should be called
      when packets are received. *)
end
