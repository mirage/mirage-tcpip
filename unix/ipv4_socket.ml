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
type ipv4 = unit
type t = unit
type +'a io = 'a Lwt.t
type error = [ `Unimplemented | `Unknown of string ]
type ipv4addr = Ipaddr.V4.t
type ethif = unit
type buffer = Cstruct.t
type callback = src:ipv4addr -> dst:ipv4addr -> buffer -> unit io

let id _ = ()
let disconnect () = return ()
let connect () = return (`Ok ())

let input ~tcp ~udp ~default _ _ = return ()
let allocate_frame ~proto ~dest_ip t = fail (Failure "Not implemented")
let write _ _ _ = fail (Failure "Not implemented")
let writev _ _ _ = fail (Failure "Not implemented")

let get_ipv4 _ = Ipaddr.V4.of_string_exn "0.0.0.0"
let set_ipv4 _ _ = fail (Failure "Not implemented")
let get_ipv4_netmask _ = Ipaddr.V4.of_string_exn "255.255.255.0"
let get_ipv4_gateways _ = raise (Failure "Not implemented")
let set_ipv4_netmask _ _ = fail (Failure "Not implemented")
let set_ipv4_gateways _ _ = fail (Failure "Not implemented")
