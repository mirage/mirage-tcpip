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

type t

type time = int64

type tr =
  | Stoptimer
  | Continue of Sequence.t
  | ContinueSetPeriod of (time * Sequence.t)

module Make(T:Mirage_time_lwt.S) : sig
  val t : period_ns: time -> expire: (Sequence.t -> tr Lwt.t) -> t

  val start : t -> ?p:time -> Sequence.t -> unit Lwt.t
end
