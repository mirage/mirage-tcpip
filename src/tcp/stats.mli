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

type t = {
  mutable tcp_listens : int;
  mutable tcp_channels: int;
  mutable tcp_connects: int;
  mutable tcp_timers  : int;
  mutable total_established : int;
  mutable total_passive_connections : int;
  mutable total_active_connections : int;
  mutable total_timers  : int;
}

val pp: Format.formatter -> t -> unit

val incr_listen: unit -> unit
val decr_listen: unit -> unit

val incr_channel: unit -> unit
val decr_channel: unit -> unit

val incr_connect: unit -> unit
val decr_connect: unit -> unit

val incr_timer: unit -> unit
val decr_timer: unit -> unit

val singleton: t

module Gc: sig
  (** Show GC stats *)

  val enable: unit -> unit
  (** Show live works (in k) on every debug line. *)

  val disable: unit -> unit

  val full_major: bool -> unit
  (** [full_major true] runs a [Gc.full_major] before printing any
      debug statement. Quite expensive but can sometimes be useful. By
      default, it is set to [false].

      {b Note:} This is very slow, use it if you really need it!

  *)

end
