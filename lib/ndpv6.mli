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

(** Address List management.

    An address can be in one of three states: {em tentative}, {em preferred},
    and {em deprecated}. *)

module AddressList : sig

  (** {1 Address List} *)

  type t
  (** The type for an address list. *)

  val empty: t
  (** An empty address list. *)

  val to_list: t -> Ipaddr.V6.t list
  (** Return the list of bound addresses.  This does not include tentative
      addresses. *)

  val select_source: t -> dst:Ipaddr.V6.t -> Ipaddr.V6.t
  (** Source Selection *)

  val tick: t -> now:float -> retrans_timer:float ->
    t * [> `Sleep of float | `SendNS of [> `Unspecified ] * Ipaddr.V6.t * Ipaddr.V6.t ] list
  (** [tick al now rt] performs the periodic upkeep of the address list.  This
      means: 1) deprecating (resp. expiring) addresses whose preferred (resp. valid)
      lifetimes have elapsed; 2) sending repeated NS to verify that a TENTATIVE
      address is not in use by another host. *)

  val expired: t -> now:float -> bool
  (** [expired al now] is [true] if there is some address in the list whose
      valid lifetime has elapsed and [false] otherwise. *)

  val is_my_addr: t -> Ipaddr.V6.t -> bool
  (** [is_my_addr al ip] is [true] if [ip] is an address assigned to this list.
      In particular this means that it is not TENTATIVE. *)

  val add: t -> now:float -> retrans_timer:float -> lft:(float * float option) option -> Ipaddr.V6.t ->
    t * [> `Sleep of float | `SendNS of [> `Unspecified ] * Ipaddr.V6.t * Ipaddr.V6.t ] list
  (** [add al now rt lft ip] marks the address [ip] as TENTATIVE and beings
      Duplicate Address Detection (DAD) by sending Neighbor Solicitation
      messages to [ip] to try to determine if this address is already assigned
      to another node in the local network. [lft] is the lifetime of [ip].  Here
      [lft] is [None] if the lifetime is infinite, [Some (plft, None)] if the
      preferred lifetime is [plft] and the valid lifetime is infinite and [Some
      (plft, Some vlft)] if the valid lifetime is finite as well.

      If the address is already bound or in the process of being bound, nothing
      happens. *)

  val configure: t -> now:float -> retrans_timer:float -> lft:(float * float option) option -> Macaddr.t -> Ipaddr.V6.Prefix.t ->
    t * [> `Sleep of float | `SendNS of [> `Unspecified ] * Ipaddr.V6.t * Ipaddr.V6.t ] list
  (** [configure t now rt lft mac pfx] begins the process of assigning a
      globally unique address with prefix [pfx]. *)

  val handle_na: t -> Ipaddr.V6.t -> t
  (** [handle_na al ip] handles a Neighbor Advertisement which has arrived from
      [ip].  If [ip] is a TENTATIVE address in [al] then it means that DAD has
      failed and [ip] should not be bound. *)
end

module PrefixList : sig
  type t
  val link_local: t
  val to_list: t -> Ipaddr.V6.Prefix.t list
  val expired: t -> now:float -> bool
  val tick: t -> now:float -> t
  val is_local: t -> Ipaddr.V6.t -> bool
  val add: t -> now:float -> Ipaddr.V6.Prefix.t -> vlft:float option -> t
  val handle_ra: t -> now:float -> vlft:float option -> Ipaddr.V6.Prefix.t ->
    t * [> `Sleep of float ] list
end

module NeighborCache : sig
  type t
  val empty: t
  val tick: t -> now:float -> retrans_timer:float ->
    t * [> `Sleep of float | `SendNS of [> `Specified ] * Ipaddr.V6.t * Ipaddr.V6.t | `CancelQueued of Ipaddr.V6.t ] list
  val handle_ns: t -> src:Ipaddr.V6.t -> Macaddr.t ->
    t * [> `SendQueued of Ipaddr.V6.t * Macaddr.t ] list
  val handle_ra: t -> src:Ipaddr.V6.t -> Macaddr.t ->
    t * [> `SendQueued of Ipaddr.V6.t * Macaddr.t ] list
  val handle_na: t -> now:float -> reachable_time:float -> rtr:bool -> sol:bool -> ovr:bool -> tgt:Ipaddr.V6.t -> lladdr:Macaddr.t option ->
    t * [> `Sleep of float | `SendQueued of Ipaddr.V6.t * Macaddr.t ] list
  val query: t -> now:float -> reachable_time:float -> Ipaddr.V6.t ->
    t * Macaddr.t option * [> `Sleep of float | `SendNS of [> `Specified ] * Ipaddr.V6.t * Ipaddr.V6.t ] list
  val reachable: t -> Ipaddr.V6.t -> bool
end

module RouterList : sig
  type t
  val empty: t
  val to_list: t -> Ipaddr.V6.t list
  val add: t -> now:float -> ?lifetime:float -> Ipaddr.V6.t -> t
  val tick: t -> now:float -> t
  val handle_ra: t -> now:float -> src:Ipaddr.V6.t -> lft:float ->
    t * [> `Sleep of float ] list
  val add: t -> now:float -> Ipaddr.V6.t -> t
  val select: t -> (Ipaddr.V6.t -> bool) -> Ipaddr.V6.t -> Ipaddr.V6.t * t
end
