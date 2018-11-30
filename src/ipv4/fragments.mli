(*
 * Copyright (c) 2018 Hannes Mehnert <hannes@mehnert.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS l SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

module V : sig
  type t = int64 * Cstruct.t * bool * int * (int * Cstruct.t) list

  val weight : t -> int
end

module K : sig
  type t = Ipaddr.V4.t * Ipaddr.V4.t * int * int
  val compare : t -> t -> int
end

module Cache : sig
  include Lru.F.S with type k = K.t and type v = V.t
end

val max_duration : int64

val process : Cache.t -> int64 -> Ipv4_packet.t -> Cstruct.t ->
  Cache.t * (Ipv4_packet.t * Cstruct.t) option
