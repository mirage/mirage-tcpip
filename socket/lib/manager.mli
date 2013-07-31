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

(** Manage network interfaces. *)

open Nettypes

(** Type of a manager *)
type t

(** Accessors for the t type *)

val get_udpv4 : t -> Lwt_unix.file_descr
val register_udpv4_listener : t -> ipv4_addr option * int -> Lwt_unix.file_descr -> unit
val get_udpv4_listener : t -> ipv4_addr option * int -> Lwt_unix.file_descr Lwt.t


(** The following functions are provided for compatibility with other
    backends, but are irrelevant for the socket backend, and thus
    should not be used. *)

type interface = unit
type id = string (** Always equal to "" *)
type config = [ `DHCP | `IPv4 of ipv4_addr * ipv4_addr * ipv4_addr list ]

(** Do nothing *)
val configure: interface -> config -> unit Lwt.t

(** Return "" *)
val get_intf : interface -> string


(** Type of the callback function given as an argument for
    [create]. *)
type callback = t -> interface -> id -> unit Lwt.t

(** [create callback] creates a manager that will call [callback]. The
    callback function is responsible for polling the hashtbl to check
    for new "connections", implemented here as UDP sockets that are
    bound to a particular sockaddr. *)
val create : callback -> unit Lwt.t


(** The following functions are provided for compatibility with other
    backends, but are not supported by the socket backend, and MUST
    NOT be used (They all fail with an appropriate error message). *)

val attach: t -> string -> bool Lwt.t
val detach: t -> string -> bool Lwt.t

val set_promiscuous: t -> id -> (id -> Cstruct.t -> unit Lwt.t) -> unit
val inject_packet : t -> id -> Cstruct.t -> unit Lwt.t
val get_intf_name : t -> id -> string
val get_intf_mac : t -> id -> Macaddr.t

