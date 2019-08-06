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
  (** The type of values in the fragment cache: a timestamp of the first
     received one, IP options (of the first fragment), whether or not the last
     fragment was received (the one with more fragments cleared), amount of
     received fragments, and a list of pairs of offset and fragment. *)

  val weight : t -> int
  (** [weight t] is the data length of the received fragments. *)
end

module K : sig
  type t = Ipaddr.V4.t * Ipaddr.V4.t * int * int
  (** The type of keys in the fragment cache: source IP address, destination
      IP address, protocol type, and IP identifier. *)

  val compare : t -> t -> int
end

module Cache : sig
  include Lru.F.S with type k = K.t and type v = V.t
end

val max_duration : int64
(** [max_duration] is the maximum delta between first and last received
    fragment, in nanoseconds. At the moment it is 10 seconds. *)

val process : Cache.t -> int64 -> Ipv4_packet.t -> Cstruct.t -> Cache.t *
   (Ipv4_packet.t * Cstruct.t) option (** [process t timestamp hdr payload] is
   [t'], a new cache, and maybe a fully reassembled IPv4 segment. If reassembly
   fails, e.g. too many fragments, delta between receive timestamp of first and
   last segment exceeds {!max_duration}, overlapping segments, these segments
   will be dropped from the cache. The IPv4 header options are always taken from
   the first fragment (where offset is 0). If the provided IPv4 header has an
   fragmentation offset of 0, and the more fragments bit is not set, the given
   header and payload is directly returned. Handles out-of-order fragments
   gracefully. *)

val fragment : mtu:int -> Ipv4_packet.t -> Cstruct.t -> Cstruct.t list
(** [fragment ~mtu hdr payload] is called with the IPv4 header of the first
    fragment and the remaining payload (which did not fit into the first
    fragment). The [data_length = ((mtu - header_length hdr) / 8) * 8] is used
    for each fragment (and it is assumed that the first fragment contains
    exactly that much data). The number of segments returned is
    [len payload / data_len]. If [data_len <= 0], the empty list is returned. *)
