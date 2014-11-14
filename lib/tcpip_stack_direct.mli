(*
 * Copyright (c) 2014 Anil Madhavapeddy <anil@recoil.org>
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

type 'ipaddr direct_ip_input = src:'ipaddr -> dst:'ipaddr -> Cstruct.t -> unit Lwt.t
module type UDPV4_DIRECT = V2_LWT.UDP
  with type ipaddr = Ipaddr.V4.t
   and type ipinput = Ipaddr.V4.t direct_ip_input

module type TCPV4_DIRECT = V2_LWT.TCP
  with type ipaddr = Ipaddr.V4.t
   and type ipinput = Ipaddr.V4.t direct_ip_input

module type UDPV6_DIRECT = V2_LWT.UDP
  with type ipaddr = Ipaddr.V6.t
   and type ipinput = Ipaddr.V6.t direct_ip_input

module type TCPV6_DIRECT = V2_LWT.TCP
  with type ipaddr = Ipaddr.V6.t
   and type ipinput = Ipaddr.V6.t direct_ip_input

module Make
    (Console : V1_LWT.CONSOLE)
    (Time    : V1_LWT.TIME)
    (Random  : V1.RANDOM)
    (Netif   : V1_LWT.NETWORK)
    (Ethif   : V2_LWT.ETHIF with type netif = Netif.t)
    (Ipv4    : V2_LWT.IPV4 with type ethif = Ethif.t)
    (Ipv6    : V2_LWT.IPV6 with type ethif = Ethif.t)
    (Udpv4   : UDPV4_DIRECT with type ip = Ipv4.t)
    (Tcpv4   : TCPV4_DIRECT with type ip = Ipv4.t)
    (Udpv6   : UDPV6_DIRECT with type ip = Ipv6.t)
    (Tcpv6   : TCPV6_DIRECT with type ip = Ipv6.t) :
  V2_LWT.STACK
  with type console = Console.t
   and type netif   = Netif.t
   and type mode    = V2_LWT.direct_stack_config
   and type ipv4addr = Ipv4.ipaddr
   and type ipv6addr = Ipv6.ipaddr
   and type ipv4    = Ipv4.t
   and type ipv6    = Ipv6.t
   and type udpv4   = Udpv4.t
   and type tcpv4   = Tcpv4.t
   and type udpv6   = Udpv6.t
   and type tcpv6   = Tcpv6.t
   and module TCPV4 = Tcpv4
   and module UDPV4 = Udpv4
   and module IPV4 = Ipv4
   and module TCPV6 = Tcpv6
   and module UDPV6 = Udpv6
   and module IPV6 = Ipv6
