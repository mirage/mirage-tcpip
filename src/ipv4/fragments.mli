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

(** IPv4 Fragmentation and reassembly

    An IPv4 packet may exceed the maximum transferable unit (MTU) of a link, and
   thus may be fragmented into multiple packets. Since the MTU depends on the
   underlying link, fragmentation and reassembly may happen in gateways as well
   as endpoints. Starting at byte 6, 16 bit in the IPv4 header are used for
   fragmentation. The first bit is reserved, the second signals if set to never
   fragment this packet - instead if it needs to be fragmented, an ICMP error
   must be returned (used for path MTU discovery). The third bit indicates
   whether this is the last fragment or more are following. The remaining 13
   bits are the offset of this fragment in the reassembled packet, divided by
   8. All fragments of one reassembled packet use the same 16 bit IPv4
   identifier (byte offset 4). The IPv4 header is repeated in each fragment,
   apart from those options which highest bit is cleared. Fragments may be
   received in any order.

    This module implements a reassembly cache, using a least recently used (LRU)
   cache underneath. For security reasons, only non-overlapping fragments are
   accepted. To avoid denial of service attacks, the maximum number of segments
   is limited to 16 - with a common MTU of 1500, this means that packets
   exceeding 24000 bytes will be dropped. The arrival time of the first and last
   fragment may not exceed 10 seconds. There is no per-source IP limit of
   fragment data to keep, only the total amount of fragmented data can be
   limited by the choice of the size of the LRU.

    Any received packet may be the last needed for a successful reassembly (due
   to receiving them out-of-order). When the last fragment (which has the more
   fragments bit cleared) for a quadruple source IP, destination IP, IP
   identifier, and protocol ID, is received, reassembly is attempted - also on
   subsequent packets with the same quadruple. *)

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
   [t'], a new cache, and maybe a fully reassembled IPv4 packet. If reassembly
   fails, e.g. too many fragments, delta between receive timestamp of first and
   last packet exceeds {!max_duration}, overlapping packets, these packets
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
    exactly that much data). The number of packets returned is
    [len payload / data_len]. If [data_len <= 0], the empty list is returned. *)
