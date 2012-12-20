(*
 * Copyright (c) 2010-2011 Anil Madhavapeddy <anil@recoil.org>
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
 *
 *)

open Nettypes
open Printf

type t
 
val set_ips: t -> ipv4_addr list -> unit Lwt.t
val get_ips: t -> ipv4_addr list
val add_ip: t -> ipv4_addr -> unit Lwt.t
val remove_ip: t -> ipv4_addr -> unit Lwt.t

val input: t -> Cstruct.t -> unit Lwt.t
val query: t -> ipv4_addr -> ethernet_mac Lwt.t

val create: get_etherbuf:(unit -> Cstruct.t Lwt.t) -> 
  output:(Cstruct.t -> unit Lwt.t) -> get_mac:(unit -> ethernet_mac) -> t
