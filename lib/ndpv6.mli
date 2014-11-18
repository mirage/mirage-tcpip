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

type na = {
  na_router    : bool;
  na_solicited : bool;
  na_override  : bool;
  na_target    : Ipaddr.V6.t;
  na_tlla      : Macaddr.t option
}

type ra_prefix = {
  prf_on_link            : bool;
  prf_autonomous         : bool;
  prf_valid_lifetime     : float;
  prf_preferred_lifetime : float;
  prf_prefix             : Ipaddr.V6.Prefix.t
}

type ra = {
  ra_cur_hop_limit   : int;
  ra_router_lifetime : float;
  ra_reachable_time  : float;
  ra_retrans_timer   : float;
  ra_slla            : Macaddr.t option;
  ra_prefix          : ra_prefix option
}

type ns = {
  ns_target : Ipaddr.V6.t;
  ns_slla   : Macaddr.t option
}

type state

val is_local : state:state -> Ipaddr.V6.t -> bool

val select_source_address : state -> Ipaddr.V6.t

type packet =
  | NS of ns
  | RA of ra
  | NA of na

type action =
  | Sleep        of float
  | SendNS       of Ipaddr.V6.t * Ipaddr.V6.t * Ipaddr.V6.t
  | SendNA       of Ipaddr.V6.t * Ipaddr.V6.t * Ipaddr.V6.t * bool
  | SendRS
  | SendQueued   of int * Macaddr.t
  | CancelQueued of int

val tick : now:float -> state:state -> state * action list

val add_ip : now:float -> state:state -> ?lifetime:(float * float option) -> Ipaddr.V6.t -> state * action list

val input : now:float -> state:state -> src:Ipaddr.V6.t -> dst:Ipaddr.V6.t -> packet -> state * action list

val is_my_addr : state:state -> Ipaddr.V6.t -> bool

val create : now:float -> Macaddr.t -> state * action list

type output =
  | SendNow of Macaddr.t
  | SendLater of int

val output : now:float -> state:state -> dst:Ipaddr.V6.t -> state * output * action list

val mac : state -> Macaddr.t

val get_ipv6 : state -> Ipaddr.V6.t list

val cur_hop_limit : state -> int

val add_router : now:float -> state:state -> Ipaddr.V6.t -> state

val get_routers : state -> Ipaddr.V6.t list
