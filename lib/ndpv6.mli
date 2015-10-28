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

(*
- Transmission of IPv6 packets over Ethernet networks
 http://tools.ietf.org/html/rfc2464

- IPv6 Stateless Address Autoconfiguration
 https://tools.ietf.org/html/rfc2462

- Neighbor Discovery for IP Version 6 (IPv6)
 https://tools.ietf.org/html/rfc2461

- Internet Control Message Protocol (ICMPv6) for the Internet Protocol Version 6 (IPv6) Specification
 http://tools.ietf.org/html/rfc2463

- IPv6 Node Requirements
 http://tools.ietf.org/html/rfc6434

- Multicast Listener Discovery Version 2 (MLDv2) for IPv6
 http://tools.ietf.org/html/rfc3810
*)

type buffer = Cstruct.t
type ipaddr = Ipaddr.V6.t
type prefix = Ipaddr.V6.Prefix.t

val ipaddr_of_cstruct : buffer -> ipaddr
val checksum : buffer -> buffer list -> int

type event =
  [ `Tcp of ipaddr * ipaddr * buffer
  | `Udp of ipaddr * ipaddr * buffer
  | `Default of int * ipaddr * ipaddr * buffer ]

type context

val local : now:float -> Macaddr.t -> context * buffer list list
val add_ip : now:float -> context -> ipaddr -> context * buffer list list
val get_ip : context -> ipaddr list
val allocate_frame : context -> ipaddr -> [`ICMP | `TCP | `UDP] -> buffer * int
val select_source : context -> ipaddr -> ipaddr
val handle : now:float -> context -> buffer -> context * buffer list list * event list
val send : now:float -> context -> ipaddr -> buffer -> buffer list -> context * buffer list list
val tick : now:float -> context -> context * buffer list list
val add_prefix : now:float -> context -> prefix -> context
val get_prefix : context -> prefix list
val add_routers : now:float -> context -> ipaddr list -> context
val get_routers : context -> ipaddr list
