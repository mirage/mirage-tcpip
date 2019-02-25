(*
 * Copyright (c) 2015 Nicolas Ojeda Bar <n.oje.bar@gmail.com>
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

type buffer = Cstruct.t
type ipaddr = Ipaddr.V6.t
type prefix = Ipaddr.V6.Prefix.t
type time   = int64

val ipaddr_of_cstruct : buffer -> ipaddr
val ipaddr_to_cstruct_raw : ipaddr -> buffer -> int -> unit
val checksum : buffer -> buffer list -> int

type event =
  [ `Tcp of ipaddr * ipaddr * buffer
  | `Udp of ipaddr * ipaddr * buffer
  | `Default of int * ipaddr * ipaddr * buffer ]

type context

val local : now:time -> random:(int -> Cstruct.t) -> Macaddr.t ->
  context * (Macaddr.t * int * (buffer -> int)) list
(** [local ~now ~random mac] is a pair [ctx, outs] where [ctx] is a local IPv6 context
    associated to the hardware address [mac].  [outs] is a list of ethif packets
    to be sent. *)

val add_ip : now:time -> context -> ipaddr ->
  context * (Macaddr.t * int * (buffer -> int)) list
(** [add_ip ~now ctx ip] is [ctx', outs] where [ctx'] is [ctx] updated with a
    new local ip and [outs] is a list of ethif packets to be sent. *)

val get_ip : context -> ipaddr list
(** [get_ip ctx] returns the list of local ips. *)

val select_source : context -> ipaddr -> ipaddr
(** [select_source ctx ip] returns the ip that should be put in the source field
    of a packet destined to [ip]. *)

val handle : now:time -> random:(int -> Cstruct.t) -> context -> buffer ->
  context * (Macaddr.t * int * (buffer -> int)) list * event list
(** [handle ~now ~random ctx buf] handles an incoming ipv6 packet.  It returns
    [ctx', bufs, evs] where [ctx'] is the updated context, [bufs] is a list of
    packets to be sent and [evs] is a list of packets to be passed to the higher
    layers (udp, tcp, etc) for further processing. *)

val send : now:time -> context -> ipaddr -> Mirage_protocols.Ip.proto ->
  int -> (buffer -> buffer -> int) -> context * (Macaddr.t * int * (buffer -> int)) list
(** [send ~now ctx ip proto size fillf] starts route resolution and assembles an
    ipv6 packet of [size] for sending with header and body passed to [fillf].
    It returns a pair [ctx', dst_size_fills] where [ctx'] is the updated
    context and [dst, size, fillf] is a list of packets to be sent, specified
    by destination, their size, and fill function. *)

val tick : now:time -> context -> context * (Macaddr.t * int * (buffer -> int)) list
(** [tick ~now ctx] should be called periodically (every 1s is good).  It
    returns [ctx', bufs] where [ctx'] is the updated context and [bufs] is a list of
    packets to be sent. *)

val add_prefix : now:time -> context -> prefix -> context
(** [add_prefix ~now ctx pfx] adds a local prefix to [ctx]. *)

val get_prefix : context -> prefix list
(** [get_prefix ctx] returns the list of local prefixes known to [ctx]. *)

val add_routers : now:time -> context -> ipaddr list -> context
(** [add_routers ~now ctx ips] adds a list of gateways to [ctx] to be used for
    routing. *)

val get_routers : context -> ipaddr list
(** [get_routers ctx] returns the list of gateways known to [ctx]. *)
