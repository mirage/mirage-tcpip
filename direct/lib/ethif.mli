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

type t

val default_process : t -> Cstruct.t -> unit Lwt.t
(** performs default input processing *)

val input : t -> Cstruct.t -> unit Lwt.t
(** called on every input frame *)

val listen : t -> unit Lwt.t
val create : OS.Netif.t -> t * unit Lwt.t

val add_ip : t -> Nettypes.ipv4_addr -> unit Lwt.t
val remove_ip : t -> Nettypes.ipv4_addr -> unit Lwt.t
val query_arp : t -> Nettypes.ipv4_addr -> Nettypes.ethernet_mac Lwt.t

val get_frame : t -> Frame.t Lwt.t

val write : t -> Frame.t -> unit Lwt.t

val writev : t -> Frame.t -> Cstruct.t list -> unit Lwt.t

val attach : t -> [< `IPv4 of Cstruct.t -> unit Lwt.t ] -> unit
val detach : t -> [< `IPv4 ] -> unit
val mac : t -> Nettypes.ethernet_mac
val get_ethif : t -> OS.Netif.t

val sizeof_ethernet : int
val set_ethernet_dst : string -> int -> Cstruct.t -> unit
val set_ethernet_src : string -> int -> Cstruct.t -> unit
val set_ethernet_ethertype : Cstruct.t -> int -> unit

type packet =
| Input of Cstruct.t       (** always read as a whole chunk *)
| Output of Cstruct.t list (** written as a list of fragments *)

val set_promiscuous : t -> (packet -> unit Lwt.t) -> unit
val disable_promiscuous : t -> unit
