(*
 * Copyright (c) 2011 Anil Madhavapeddy <anil@recoil.org>
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

open Nettypes

type t
type interface
type id = OS.Netif.id
val create :  ?devs:int -> ?attached:(string list) ->
  (t -> interface -> id -> unit Lwt.t) -> unit Lwt.t

val attach: t -> string -> bool Lwt.t
val detach: t -> string -> bool Lwt.t

type config = [ `DHCP | `IPv4 of ipv4_addr * ipv4_addr * ipv4_addr list ]
val configure: interface -> config -> unit Lwt.t

val get_udpv4 : t -> Lwt_unix.file_descr
val register_udpv4_listener : t -> ipv4_addr option * int -> Lwt_unix.file_descr -> unit
val get_udpv4_listener : t -> ipv4_addr option * int -> Lwt_unix.file_descr Lwt.t
val get_intf : interface -> string

val set_promiscuous: t -> id -> (id -> Ethif.packet -> unit Lwt.t) ->
  unit                                                              
val inject_packet : t -> id -> Frame.t -> unit Lwt.t            
val get_intf_name : t -> id -> string 
val get_intf_mac : t -> id -> ethernet_mac  

