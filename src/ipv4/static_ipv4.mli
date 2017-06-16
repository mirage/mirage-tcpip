(*
 * Copyright (c) 2010 Anil Madhavapeddy <anil@recoil.org>
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

module Make (N:Mirage_protocols_lwt.ETHIF) (A: Mirage_protocols_lwt.ARP) : sig
  include Mirage_protocols_lwt.IPV4 with type ethif = N.t
  val connect :
    ?ip:Ipaddr.V4.t ->
    ?network:Ipaddr.V4.Prefix.t ->
    ?gateway:Ipaddr.V4.t option ->
    ethif -> A.t -> t Lwt.t
    (** Connect to an ipv4 device.
        Default ip is {!Ipaddr.V4.any}
        Default network is {!Ipaddr.V4.any}/0
        Default gateway is None. *)

end
