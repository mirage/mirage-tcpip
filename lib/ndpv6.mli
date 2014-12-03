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

module Ipaddr = Ipaddr.V6

module Action : sig
  type specified_flag =
    | Unspecified
    | Specified
  type solicited_flag =
    | Solicited
    | Unsolicited
  type t =
    | Sleep of float
    | SendNS of specified_flag * Ipaddr.t * Ipaddr.t
    | SendNA of Ipaddr.t * Ipaddr.t * Ipaddr.t * solicited_flag
    | SendRS
    | SendQueued of Ipaddr.t * Macaddr.t
    | CancelQueued of Ipaddr.t
end

module AddressList : sig
  type t
  val empty: t
  val to_list: t -> Ipaddr.t list
  val select_source: t -> dst:Ipaddr.t -> Ipaddr.t
  val tick: t -> now:float -> retrans_timer:float -> t * Action.t list
  val expired: t -> now:float -> bool
  val is_my_addr: t -> Ipaddr.t -> bool
  val add: t -> now:float -> retrans_timer:float -> lft:(float * float option) option -> Ipaddr.t -> t * Action.t list
  val handle_na: t -> Ipaddr.t -> t
  val configure: t -> now:float -> retrans_timer:float -> lft:(float * float option) option -> Macaddr.t -> Ipaddr.Prefix.t -> t * Action.t list
end

module PrefixList : sig
  type t
  val link_local: t
  val to_list: t -> Ipaddr.Prefix.t list
  val expired: t -> now:float -> bool
  val tick: t -> now:float -> t
  val is_local: t -> Ipaddr.t -> bool
  val add: t -> now:float -> Ipaddr.Prefix.t -> vlft:float option -> t
  val handle_ra: t -> now:float -> vlft:float option -> Ipaddr.Prefix.t -> t * Action.t list
end

module NeighborCache : sig
  type t
  val empty: t
  val tick: t -> now:float -> retrans_timer:float -> t * Action.t list
  val handle_ns: t -> src:Ipaddr.t -> Macaddr.t -> t * Action.t list
  val handle_ra: t -> src:Ipaddr.t -> Macaddr.t -> t * Action.t list
  val handle_na: t -> now:float -> reachable_time:float -> rtr:bool -> sol:bool -> ovr:bool -> tgt:Ipaddr.t -> lladdr:Macaddr.t option -> t * Action.t list
  val query: t -> now:float -> reachable_time:float -> Ipaddr.t -> t * Macaddr.t option * Action.t list
  val reachable: t -> Ipaddr.t -> bool
end

module RouterList : sig
  type t
  val empty: t
  val to_list: t -> Ipaddr.t list
  val add: t -> now:float -> ?lifetime:float -> Ipaddr.t -> t
  val tick: t -> now:float -> t
  val handle_ra: t -> now:float -> src:Ipaddr.t -> lft:float -> t * Action.t list
  val add: t -> now:float -> Ipaddr.t -> t
  val select: t -> (Ipaddr.t -> bool) -> Ipaddr.t -> Ipaddr.t * t
end
