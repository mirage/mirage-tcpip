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
