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

type t = unit
type error = Tcpip.Ip.error
type ipaddr = Ipaddr.V6.t
type callback = src:ipaddr -> dst:ipaddr -> Cstruct.t -> unit Lwt.t
type prefix = Ipaddr.V6.Prefix.t

let pp_error = Tcpip.Ip.pp_error
let pp_ipaddr = Ipaddr.V6.pp
let pp_prefix = Ipaddr.V6.Prefix.pp

let mtu _ ~dst:_ = 1500 - Ipv6_wire.sizeof_ipv6

let disconnect () = Lwt.return_unit
let connect () = Lwt.return_unit

let input _ ~tcp:_ ~udp:_ ~default:_ _ = Lwt.return_unit
let write _ ?fragment:_ ?ttl:_ ?src:_ _ _ ?size:_ _ _ =
  Lwt.fail (Failure "Not implemented")

let get_ip _ = [Ipaddr.V6.unspecified]
let configured_ips _ = [Ipaddr.V6.Prefix.of_string_exn "::/0"]
let src _ ~dst:_ = raise (Failure "Not implemented")
let pseudoheader _ ?src:_ _ _ _ = raise (Failure "Not implemented")
