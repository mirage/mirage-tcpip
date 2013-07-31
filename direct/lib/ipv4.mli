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

(** INTERNAL: IPv4 protocol. *)

open Nettypes

type t
(** Type of a IPv4 *)

val get_header: proto:[< `ICMP | `TCP | `UDP ] -> dest_ip:ipv4_addr -> t -> (Cstruct.t * int) Lwt.t

val write: t -> Cstruct.t -> Cstruct.t -> unit Lwt.t
val writev: t -> Cstruct.t -> Cstruct.t list -> unit Lwt.t

val set_ip: t -> ipv4_addr -> unit Lwt.t
val get_ip: t -> ipv4_addr
val mac: t -> Macaddr.t
val set_netmask: t -> ipv4_addr -> unit Lwt.t
val set_gateways: t -> ipv4_addr list -> unit Lwt.t
val create : Ethif.t -> t * unit Lwt.t

val attach : t ->
  [<  `ICMP of ipv4_addr -> Cstruct.t -> Cstruct.t -> unit Lwt.t
    | `UDP of src:Nettypes.ipv4_addr -> dst:Nettypes.ipv4_addr -> Cstruct.t -> unit Lwt.t 
    | `TCP of src:Nettypes.ipv4_addr -> dst:Nettypes.ipv4_addr -> Cstruct.t -> unit Lwt.t ] -> unit
val detach : t -> [< `ICMP | `UDP | `TCP ] -> unit
val get_netmask: t -> ipv4_addr
