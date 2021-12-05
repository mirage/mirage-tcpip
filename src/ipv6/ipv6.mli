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

module Make (N : Mirage_net.S)
            (E : Ethernet.S)
            (R : Mirage_random.S)
            (T : Mirage_time.S)
            (Clock : Mirage_clock.MCLOCK) : sig
  include Tcpip.Ip.S with type ipaddr = Ipaddr.V6.t
  val connect :
    ?no_init:bool ->
    ?handle_ra:bool ->
    ?cidr:Ipaddr.V6.Prefix.t ->
    ?gateway:Ipaddr.V6.t ->
    N.t -> E.t -> t Lwt.t
end
