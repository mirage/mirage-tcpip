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

open Lwt

type id = string
type t = Ipaddr.V4.t option
type +'a io = 'a Lwt.t
type error = Mirage_protocols.Ip.error
type ipaddr = Ipaddr.V4.t
type prefix = Ipaddr.V4.t (* FIXME *)
type ethif = unit
type buffer = Cstruct.t
type callback = src:ipaddr -> dst:ipaddr -> buffer -> unit io
type uipaddr = Ipaddr.t

let pp_error = Mirage_protocols.Ip.pp_error

let to_uipaddr ip = Ipaddr.V4 ip
let of_uipaddr = Ipaddr.to_v4
let mtu _ = 1500 - Ipv4_wire.sizeof_ipv4

let id _ = ()
let disconnect _ = return_unit
let connect _ = return_unit

let input_arpv4 _ _ = fail (Failure "Not implemented")
let input _ ~tcp:_ ~udp:_ ~default:_ _ = return_unit
let allocate_frame _ ~dst:_ ~proto:_ = raise (Failure "Not implemented")
let write _ _ _ = fail (Failure "Not implemented")
let writev _ _ _ = fail (Failure "Not implemented")

let get_ip _ = [Ipaddr.V4.of_string_exn "0.0.0.0"]
let set_ip _ _ = fail (Failure "Not implemented")
let get_ip_netmasks _ = [Ipaddr.V4.of_string_exn "255.255.255.0"]
let get_ip_gateways _ = raise (Failure "Not implemented")
let set_ip_netmask _ _ = fail (Failure "Not implemented")
let set_ip_gateways _ _ = fail (Failure "Not implemented")
let src _ ~dst:_ = raise (Failure "Not implemented")
let checksum _ _ = raise (Failure "Not implemented")
let pseudoheader _ ~dst:_ ~proto:_ _ = raise (Failure "Not implemented")
