(*
 * Copyright (c) 2014 Nicolas Ojeda Bar <n.oje.bar@gmail.com>
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

(** Neighbor Discovery Protocol and Stateless Adress Auto Configuration for IPv6.

    [Ndpv6] implements the {{:http://tools.ietf.org/html/rfc4861}Neighbor
    Discover Protocol} (NDP).  This protocol is used to find other IPv6 nodes in
    the same local network, monitor any change in their reachability and also to
    advertise our own existence to them.  In this way it plays a crucial role in
    {em address resolution:} finding out suitable neighboring MAC hardware
    addresses in order to route IPv6 packets.

    It also implements the required functionality to support
    {{:http://tools.ietf.org/html/rfc4862}Stateless Address Auto Configuration
    for IPv6} (SLAAC).  This allows to negotiate, with the help of routers in
    the local network, and obtain globally unique IPv6 addresses.  These
    addresses are deduced from our own MAC address, a simple technique that is
    not available in IPv4 given the relative sizes of both types of addresses
    (48 bits for MAC vs 32 bits for IPv4).

    Conceptually an IPv6 keeps 5 data structures associated with routing.

    {ul
    {- The Address List: this data structure keeps track of which addresses have
       been assigned or are in the process of being assigned (via SLAAC) to the
       network interface.  Addresses assigned via SLAAC have {em preferred} and
       {em valid} lifetimes associated to them and this data structure must be
       checked periodically to make sure that expired addresses are removed from
       the list.}
    {- The Prefix List: this is a list of "on-link" prefixes provided by routers
       in the local network for the purposes of SLAAC.  These play the role of
       the subnet mask of IPv4 and they are used to decide whether a packet must
       be routed through a router or sent directly to the destination
       address.}
    {- The Neighbor Cache: this is the most important structure.  It keeps track
       of every node that we have comunicated with (irrespective of whether the
       communication was started by us or them) and their hardware address.  A
       number of periodic upkeep tasks need to be performed in order to keep the
       information in the cache up-to-date.}
    {- The Router List: this is the list of known routers.  If an IPv6 packet is
       not on-link (i.e., it is not prefixed by one of the elements of the
       Prefix List), then it must be sent through a router.  This router will be
       chosen in an appropiate way from this list.  Routers also have valid
       lifetimes and care must be taken to expire them when they are no longer
       valid.  Routers can advertise their existence by the use of Router
       Advertisement messages.}}

    {Implementation Notes}

    All the data structures in this modules are immutable.  There is one
    top-level module for each of the data structures listed previously.

    {ul
    {- [`Sleep dt] means sleeping [dt] seconds and then call the corresponding
       [tick] function again.}
    {- [`SendNS (sf, dst, tgt)] means sending a Neighbor Solicitation to [dst]
       with target [tgt].  If [sf] is [`Unspecified], then the source address
       should be [::].  If it is [`Specified], then it should be an assigned
       address (selected using [select_source]).}
    {- [`SendQueued (ip, mac)] means sending any queued packets waiting to be
       delivered to [ip].  The MAC address of the destination field in these
       packets should be set to [mac].}} *)

module Ipaddr = Ipaddr.V6

(** Address List management.

    An address can be in one of three states: {em tentative}, {em preferred},
    and {em deprecated}. *)

module AddressList : sig

  (** {1 Address List} *)

  type t
  (** The type for an address list. *)

  val empty: t
  (** An empty address list. *)

  val to_list: t -> Ipaddr.t list
  (** Return the list of bound addresses.  This does not include tentative
      addresses. *)

  val select_source: t -> dst:Ipaddr.t -> Ipaddr.t
  (** Source Selection according to RFC .... Since  *)

  val tick: t -> now:float -> retrans_timer:float ->
    t * [> `Sleep of float | `SendNS of [> `Unspecified ] * Ipaddr.t * Ipaddr.t ] list
  (** [tick al now rt] performs the periodic upkeep of the address list.  This
      means: 1) deprecating (resp. expiring) addresses whose preferred (resp. valid)
      lifetimes have elapsed; 2) sending repeated NS to verify that a TENTATIVE
      address is not in use by another host. *)

  val expired: t -> now:float -> bool
  (** [expired al now] is [true] if there is some address in the list whose
      valid lifetime has elapsed and [false] otherwise. *)

  val is_my_addr: t -> Ipaddr.t -> bool
  (** [is_my_addr al ip] is [true] if [ip] is an address assigned to this list.
      In particular this means that it is not TENTATIVE. *)

  val add: t -> now:float -> retrans_timer:float -> lft:(float * float option) option -> Ipaddr.t ->
    t * [> `Sleep of float | `SendNS of [> `Unspecified ] * Ipaddr.t * Ipaddr.t ] list
  (** [add al now rt lft ip] marks the address [ip] as TENTATIVE and beings
      Duplicate Address Detection (DAD) by sending Neighbor Solicitation
      messages to [ip] to try to determine if this address is already assigned
      to another node in the local network. [lft] is the lifetime of [ip].  Here
      [lft] is [None] if the lifetime is infinite, [Some (plft, None)] if the
      preferred lifetime is [plft] and the valid lifetime is infinite and [Some
      (plft, Some vlft)] if the valid lifetime is finite as well.

      If the address is already bound or in the process of being bound, nothing
      happens. *)

  val configure: t -> now:float -> retrans_timer:float -> lft:(float * float option) option -> Macaddr.t -> Ipaddr.Prefix.t ->
    t * [> `Sleep of float | `SendNS of [> `Unspecified ] * Ipaddr.t * Ipaddr.t ] list
  (** [configure t now rt lft mac pfx] begins the process of assigning a
      globally unique address with prefix [pfx]. *)

  val handle_na: t -> Ipaddr.t -> t
  (** [handle_na al ip] handles a NA which has arrived from [ip].  If [ip] is a
      TENTATIVE address in [al] then it means that DAD has failed and [ip] should
      not be bound. *)
end

module PrefixList : sig
  type t
  val link_local: t
  val to_list: t -> Ipaddr.Prefix.t list
  val expired: t -> now:float -> bool
  val tick: t -> now:float -> t
  val is_local: t -> Ipaddr.t -> bool
  val add: t -> now:float -> Ipaddr.Prefix.t -> vlft:float option -> t
  val handle_ra: t -> now:float -> vlft:float option -> Ipaddr.Prefix.t ->
    t * [> `Sleep of float ] list
end

module NeighborCache : sig
  type t
  val empty: t
  val tick: t -> now:float -> retrans_timer:float ->
    t * [> `Sleep of float | `SendNS of [> `Specified ] * Ipaddr.t * Ipaddr.t | `CancelQueued of Ipaddr.t ] list
  val handle_ns: t -> src:Ipaddr.t -> Macaddr.t ->
    t * [> `SendQueued of Ipaddr.t * Macaddr.t ] list
  val handle_ra: t -> src:Ipaddr.t -> Macaddr.t ->
    t * [> `SendQueued of Ipaddr.t * Macaddr.t ] list
  val handle_na: t -> now:float -> reachable_time:float -> rtr:bool -> sol:bool -> ovr:bool -> tgt:Ipaddr.t -> lladdr:Macaddr.t option ->
    t * [> `Sleep of float | `SendQueued of Ipaddr.t * Macaddr.t ] list
  val query: t -> now:float -> reachable_time:float -> Ipaddr.t ->
    t * Macaddr.t option * [> `Sleep of float | `SendNS of [> `Specified ] * Ipaddr.t * Ipaddr.t ] list
  val reachable: t -> Ipaddr.t -> bool
end

module RouterList : sig
  type t
  val empty: t
  val to_list: t -> Ipaddr.t list
  val add: t -> now:float -> ?lifetime:float -> Ipaddr.t -> t
  val tick: t -> now:float -> t
  val handle_ra: t -> now:float -> src:Ipaddr.t -> lft:float ->
    t * [> `Sleep of float ] list
  val add: t -> now:float -> Ipaddr.t -> t
  val select: t -> (Ipaddr.t -> bool) -> Ipaddr.t -> Ipaddr.t * t
end
