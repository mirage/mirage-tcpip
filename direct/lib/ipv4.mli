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

val get_header: proto:[< `ICMP | `TCP | `UDP ] -> dest_ip:Ipaddr.V4.t -> t -> (Cstruct.t * int) Lwt.t

val write: t -> Cstruct.t -> Cstruct.t -> unit Lwt.t
val writev: t -> Cstruct.t -> Cstruct.t list -> unit Lwt.t

val set_ip: t -> Ipaddr.V4.t -> unit Lwt.t
val get_ip: t -> Ipaddr.V4.t
val mac: t -> Macaddr.t
val set_netmask: t -> Ipaddr.V4.t -> unit Lwt.t
val set_gateways: t -> Ipaddr.V4.t list -> unit Lwt.t
val get_gateways: t -> Ipaddr.V4.t list
val create : Ethif.t -> t * unit Lwt.t

val attach : t ->
  [<  `ICMP of Ipaddr.V4.t -> Cstruct.t -> Cstruct.t -> unit Lwt.t
    | `UDP of src:Ipaddr.V4.t -> dst:Ipaddr.V4.t -> Cstruct.t -> unit Lwt.t 
    | `TCP of src:Ipaddr.V4.t -> dst:Ipaddr.V4.t -> Cstruct.t -> unit Lwt.t ] -> unit
val detach : t -> [< `ICMP | `UDP | `TCP ] -> unit
val get_netmask: t -> Ipaddr.V4.t
