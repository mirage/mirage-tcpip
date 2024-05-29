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

module Make (R: Mirage_random.S) (C: Mirage_clock.MCLOCK) (E: Ethernet.S) (A: Arp.S) : sig
  include Tcpip.Ip.S with type ipaddr = Ipaddr.V4.t and type prefix = Ipaddr.V4.Prefix.t

  val connect : ?no_init:bool -> cidr:Ipaddr.V4.Prefix.t -> ?gateway:Ipaddr.V4.t ->
    ?fragment_cache_size:int -> E.t -> A.t -> t Lwt.t
  (** [connect ~no_init ~cidr ~gateway ~fragment_cache_size eth arp] connects the ipv4
      device using [cidr] and [gateway] for network communication. The size of
      the IPv4 fragment cache (for reassembly) can be provided in byte-size of
      fragments (defaults to 256kB). *)
end
