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

type direct_ipv4_input = src:Ipaddr.V4.t -> dst:Ipaddr.V4.t -> Cstruct.t -> unit Lwt.t

module type UDPV4_DIRECT = Mirage_protocols.UDP
  with type ipaddr = Ipaddr.V4.t
   and type ipinput = direct_ipv4_input

module type TCPV4_DIRECT = Mirage_protocols.TCP
  with type ipaddr = Ipaddr.V4.t
   and type ipinput = direct_ipv4_input

module Make
    (Time     : Mirage_time.S)
    (Random   : Mirage_random.S)
    (Netif    : Mirage_net.S)
    (Ethernet : Mirage_protocols.ETHERNET)
    (Arpv4    : Mirage_protocols.ARP)
    (Ipv4     : Mirage_protocols.IP with type ipaddr = Ipaddr.V4.t)
    (Icmpv4   : Mirage_protocols.ICMP with type ipaddr = Ipaddr.V4.t)
    (Udpv4    : UDPV4_DIRECT)
    (Tcpv4    : TCPV4_DIRECT) : sig
  include Mirage_stack.V4
    with module IPV4 = Ipv4
     and module TCPV4 = Tcpv4
     and module UDPV4 = Udpv4

  val connect : Netif.t -> Ethernet.t -> Arpv4.t -> Ipv4.t -> Icmpv4.t ->
    Udpv4.t -> Tcpv4.t -> t Lwt.t
  (** [connect] assembles the arguments into a network stack, then calls
      `listen` on the assembled stack before returning it to the caller.  The
      initial `listen` functions to ensure that the lower-level layers (e.g.
      ARP) are functioning, so that if the user wishes to establish outbound
      connections, they will be able to do so. *)
end

type direct_ipv6_input = src:Ipaddr.V6.t -> dst:Ipaddr.V6.t -> Cstruct.t -> unit Lwt.t

module type UDPV6_DIRECT = Mirage_protocols.UDP
  with type ipaddr = Ipaddr.V6.t
   and type ipinput = direct_ipv6_input

module type TCPV6_DIRECT = Mirage_protocols.TCP
  with type ipaddr = Ipaddr.V6.t
   and type ipinput = direct_ipv6_input

module MakeV6
    (Time     : Mirage_time.S)
    (Random   : Mirage_random.S)
    (Netif    : Mirage_net.S)
    (Ethernet : Mirage_protocols.ETHERNET)
    (Ipv6     : Mirage_protocols.IP with type ipaddr = Ipaddr.V6.t)
    (Udpv6    : UDPV6_DIRECT)
    (Tcpv6    : TCPV6_DIRECT) : sig
  include Mirage_stack.V6
    with module IP = Ipv6
     and module TCP = Tcpv6
     and module UDP = Udpv6

  val connect : Netif.t -> Ethernet.t -> Ipv6.t -> Udpv6.t -> Tcpv6.t -> t Lwt.t
  (** [connect] assembles the arguments into a network stack, then calls
      `listen` on the assembled stack before returning it to the caller.  The
      initial `listen` functions to ensure that the lower-level layers are
      functioning, so that if the user wishes to establish outbound connections,
      they will be able to do so. *)
end

type direct_ipv4v6_input = src:Ipaddr.t -> dst:Ipaddr.t -> Cstruct.t -> unit Lwt.t

module type UDPV4V6_DIRECT = Mirage_protocols.UDP
  with type ipaddr = Ipaddr.t
   and type ipinput = direct_ipv4v6_input

module type TCPV4V6_DIRECT = Mirage_protocols.TCP
  with type ipaddr = Ipaddr.t
   and type ipinput = direct_ipv4v6_input

module IPV4V6 (Ipv4 : Mirage_protocols.IPV4) (Ipv6 : Mirage_protocols.IPV6) : sig
  include Mirage_protocols.IP with type ipaddr = Ipaddr.t

  val connect : ipv4_only:bool -> ipv6_only:bool -> Ipv4.t -> Ipv6.t -> t Lwt.t
end

module MakeV4V6
    (Time     : Mirage_time.S)
    (Random   : Mirage_random.S)
    (Netif    : Mirage_net.S)
    (Ethernet : Mirage_protocols.ETHERNET)
    (Arpv4    : Mirage_protocols.ARP)
    (Ip       : Mirage_protocols.IP with type ipaddr = Ipaddr.t)
    (Icmpv4   : Mirage_protocols.ICMP with type ipaddr = Ipaddr.V4.t)
    (Udp      : UDPV4V6_DIRECT)
    (Tcp      : TCPV4V6_DIRECT) : sig
  include Mirage_stack.V4V6
    with module IP = Ip
     and module TCP = Tcp
     and module UDP = Udp

  val connect : Netif.t -> Ethernet.t -> Arpv4.t -> Ip.t -> Icmpv4.t -> Udp.t -> Tcp.t -> t Lwt.t
  (** [connect] assembles the arguments into a network stack, then calls
      `listen` on the assembled stack before returning it to the caller.  The
      initial `listen` functions to ensure that the lower-level layers are
      functioning, so that if the user wishes to establish outbound connections,
      they will be able to do so. *)
end
