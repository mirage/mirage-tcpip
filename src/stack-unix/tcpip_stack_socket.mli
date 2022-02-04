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

module V4 : sig
  include
    Tcpip.Stack.V4
      with module UDPV4 = Udpv4_socket
       and module TCPV4 = Tcpv4_socket
       and module IPV4 = Ipv4_socket

  val connect : Udpv4_socket.t -> Tcpv4_socket.t -> t Lwt.t
end

module V6 : sig
  include
    Tcpip.Stack.V6
      with module UDP = Udpv6_socket
       and module TCP = Tcpv6_socket
       and module IP = Ipv6_socket

  val connect : Udpv6_socket.t -> Tcpv6_socket.t -> t Lwt.t
end

module V4V6 : sig
  include
    Tcpip.Stack.V4V6
      with module UDP = Udpv4v6_socket
       and module TCP = Tcpv4v6_socket
       and module IP = Ipv4v6_socket

  val connect : Udpv4v6_socket.t -> Tcpv4v6_socket.t -> t Lwt.t
end
