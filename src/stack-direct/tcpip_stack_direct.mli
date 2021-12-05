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

module Make
    (Time     : Mirage_time.S)
    (Random   : Mirage_random.S)
    (Netif    : Mirage_net.S)
    (Ethernet : Ethernet.S)
    (Arpv4    : Arp.S)
    (Ipv4     : Tcpip.Ip.S with type ipaddr = Ipaddr.V4.t)
    (Icmpv4   : Icmpv4.S)
    (Udpv4    : Tcpip.Udp.S with type ipaddr = Ipaddr.V4.t)
    (Tcpv4    : Tcpip.Tcp.S with type ipaddr = Ipaddr.V4.t) : sig
  include Tcpip.Stack.V4
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

module MakeV6
    (Time     : Mirage_time.S)
    (Random   : Mirage_random.S)
    (Netif    : Mirage_net.S)
    (Ethernet : Ethernet.S)
    (Ipv6     : Tcpip.Ip.S with type ipaddr = Ipaddr.V6.t)
    (Udpv6    : Tcpip.Udp.S with type ipaddr = Ipaddr.V6.t)
    (Tcpv6    : Tcpip.Tcp.S with type ipaddr = Ipaddr.V6.t) : sig
  include Tcpip.Stack.V6
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

module IPV4V6 (Ipv4 : Tcpip.Ip.S with type ipaddr = Ipaddr.V4.t) (Ipv6 : Tcpip.Ip.S with type ipaddr = Ipaddr.V6.t) : sig
  include Tcpip.Ip.S with type ipaddr = Ipaddr.t

  val connect : ipv4_only:bool -> ipv6_only:bool -> Ipv4.t -> Ipv6.t -> t Lwt.t
end

module MakeV4V6
    (Time     : Mirage_time.S)
    (Random   : Mirage_random.S)
    (Netif    : Mirage_net.S)
    (Ethernet : Ethernet.S)
    (Arpv4    : Arp.S)
    (Ip       : Tcpip.Ip.S with type ipaddr = Ipaddr.t)
    (Icmpv4   : Icmpv4.S)
    (Udp      : Tcpip.Udp.S with type ipaddr = Ipaddr.t)
    (Tcp      : Tcpip.Tcp.S with type ipaddr = Ipaddr.t) : sig
  include Tcpip.Stack.V4V6
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
