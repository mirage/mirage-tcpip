(*
 * Copyright (c) 2014 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (c) 2014 Nicolas Ojeda Bar <n.oje.bar@gmail.com>
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

open Lwt

type t = unit
type +'a io = 'a Lwt.t
type error = Mirage_protocols.Ip.error
type ipaddr = Ipaddr.V6.t
type buffer = Cstruct.t
type callback = src:ipaddr -> dst:ipaddr -> buffer -> unit io

let pp_error = Mirage_protocols.Ip.pp_error
let pp_ipaddr = Ipaddr.V6.pp

let mtu _ = 1500 - Ipv6_wire.sizeof_ipv6

let id _ = ()
let disconnect () = return_unit
let connect () = return_unit

let input _ ~tcp:_ ~udp:_ ~default:_ _ = return_unit
let write _ ?fragment:_ ?ttl:_ ?src:_ _ _ ?size:_ _ _ = fail (Failure "Not implemented")

let get_ip _ = [Ipaddr.V6.unspecified]
let src _ ~dst:_ = raise (Failure "Not implemented")
let pseudoheader _ ?src:_ _ _ _ = raise (Failure "Not implemented")
