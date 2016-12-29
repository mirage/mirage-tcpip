(*
 * Copyright (c) 2010 http://github.com/barko 00336ea19fcb53de187740c490f764f4
 * Copyright (c) 2011 Anil Madhavapeddy <anil@recoil.org>
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

module Rx : sig
  type t

  val create : max_size:int32 -> wnd:Window.t -> t
  val add_r : t -> Cstruct.t option -> unit Lwt.t
  val take_l : t -> Cstruct.t option Lwt.t
  val cur_size : t -> int32
  val max_size : t -> int32
  val monitor: t -> int32 Lwt_mvar.t -> unit
end

module Tx(Time:Mirage_time_lwt.S)(Clock:Mirage_clock.MCLOCK) : sig

  type t

  module TXS : sig
    type t = Segment.Tx(Time)(Clock).t
    val output : ?flags:Segment.tx_flags -> ?options:Options.t list -> t ->
      Cstruct.t -> unit Lwt.t
  end

  val create: max_size:int32 -> wnd:Window.t -> txq:TXS.t -> t
  val available: t -> int32
  val wait_for: t -> int32 -> unit Lwt.t
  val wait_for_flushed: t -> unit Lwt.t
  val write: t -> Cstruct.t list -> unit Lwt.t
  val write_nodelay: t -> Cstruct.t list -> unit Lwt.t
  val free: t -> int -> unit Lwt.t
  val reset: t -> unit Lwt.t
end
