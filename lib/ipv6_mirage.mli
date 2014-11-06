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

module type IP = sig
  type ethif
  type 'a io
  type buffer
  type ipaddr
  type callback = src:ipaddr -> dst:ipaddr -> buffer -> unit io

  type t

  val id : t -> ethif
  val input : t -> tcp:callback -> udp:callback -> default:(proto:int -> callback) -> buffer -> unit io
  val connect : ethif -> [> `Ok of t] io
  val get_gateways : t -> ipaddr list
  val get_ips : t -> ipaddr list
end

module type IPV6 = sig
  include IP with type ipaddr = Ipaddr.V6.t
end

module Make (E : V2_LWT.ETHIF) (T : V2_LWT.TIME) (C : V2.CLOCK) : IPV6
  with type 'a io = 'a Lwt.t
   and type buffer = Cstruct.t
