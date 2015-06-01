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

(** TCP Statistics *)

type counter
(** The type for counters. *)

val value: counter -> int
(** The counter value. [value t] is [{!incr} t] - [{!decrs} t].*)

val incrs: counter -> int
(** How many time the counter has been increased. *)

val decrs: counter -> int
(** How many time the counter has been decreased. *)

type t = {
  tcp_flows   : counter;
  tcp_listens : counter;
  tcp_channels: counter;
  tcp_connects: counter;
}

val pp: Format.formatter -> t -> unit

val incr_flow: unit -> unit
val decr_flow: unit -> unit

val incr_listen: unit -> unit
val decr_listen: unit -> unit

val incr_channel: unit -> unit
val decr_channel: unit -> unit

val incr_connect: unit -> unit
val decr_connect: unit -> unit

val create: unit -> t
