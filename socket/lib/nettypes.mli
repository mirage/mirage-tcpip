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
 *)

(** Type representing a byte string (as opposed to a pretty-printed
    string *)
type bytes = string

(** Type representing the hardware address (MAC) of an ethernet
    interface *)
type ethernet_mac

(** Functions converting MAC addresses to bytes/string and vice
    versa *)

val ethernet_mac_of_bytes : bytes -> ethernet_mac

(** Read a MAC address from a colon-separated string (like
    ff:ff:ff:ff:ff:ff) *)
val ethernet_mac_of_string : string -> ethernet_mac option
val ethernet_mac_to_bytes : ethernet_mac -> bytes

(** Return a MAC address as a colon-separated string *)
val ethernet_mac_to_string : ethernet_mac -> string

val ethernet_mac_broadcast: ethernet_mac

(** Functions handling IPv4 addresses *)

(** Type representing IPv4 addresses *)
type ipv4_addr = Unix.inet_addr

(** Read an IPv4 from a tuple of int32 *)
val ipv4_addr_of_tuple : (int32 * int32 * int32 * int32) -> ipv4_addr

(** Read an IPv4 address from a dot-separated string
    (e.g. 127.0.0.1) *)
val ipv4_addr_of_string : string -> ipv4_addr option

(** Return an IPv4 address as a dot-separated string *)
val ipv4_addr_to_string : ipv4_addr -> string

(** Corresponding to 0.0.0.0 *)
val ipv4_blank : ipv4_addr

(** Corresponding to 255.255.255.255 *)
val ipv4_broadcast : ipv4_addr

(** Corresponding to 127.0.0.1 *)
val ipv4_localhost : ipv4_addr

(** Type describing the socket address of a source (optional IPv4 and
    port of the source) *)
type ipv4_src = ipv4_addr option * int

(** Type describing the socket address of an endpoint (IPv4 and port
    of the destination *)
type ipv4_dst = ipv4_addr * int

(** Type for an ARP packet *)
type arp = {
  op: [ `Request |`Reply |`Unknown of int ]; (** operation *)
  sha: ethernet_mac;                         (** source hardware address *)
  spa: ipv4_addr;                            (** source protocol address *)
  tha: ethernet_mac;                         (** target hardware address *)
  tpa: ipv4_addr;                            (** target protocol address *)
}

type peer_uid = int

exception Closed

module type FLOW = sig
  (** Type of an individual flow *)
  type t

  (** Type that manages a collection of flows *)
  type mgr

  (** Types that identifies a flow source and destination endoint *)

  type src
  type dst

  (** Functions to read and write to/from a flow *)

  val read : t -> Cstruct.t option Lwt.t
  val write : t -> Cstruct.t -> unit Lwt.t
  val writev : t -> Cstruct.t list -> unit Lwt.t
  val close : t -> unit Lwt.t

  (** Functions to construct flows *)

  val listen : mgr -> src -> (dst -> t -> unit Lwt.t) -> unit Lwt.t
  val connect : mgr -> ?src:src -> dst -> (t -> 'a Lwt.t) -> 'a Lwt.t
end

module type DATAGRAM = sig

  (** Datagram manager *)
  type mgr

  (** Types that identifies a datagram source and destination
      endpoint *)

  type src
  type dst

  (** Type of a message *)
  type msg

  (** Receive and send functions *)

  val recv : mgr -> src -> (dst -> msg -> unit Lwt.t) -> unit Lwt.t
  val send : mgr -> ?src:src -> dst -> msg -> unit Lwt.t
end

module type CHANNEL = sig

  type mgr
  type t
  type src
  type dst

  val read_char: t -> char Lwt.t
  val read_until: t -> char -> (bool * Cstruct.t) Lwt.t
  val read_some: ?len:int -> t -> Cstruct.t Lwt.t
  val read_stream: ?len: int -> t -> Cstruct.t Lwt_stream.t
  val read_line: t -> Cstruct.t list Lwt.t

  val write_char : t -> char -> unit
  val write_string : t -> string -> int -> int -> unit
  val write_buffer : t -> Cstruct.t -> unit
  val write_line : t -> string -> unit

  val flush : t -> unit Lwt.t
  val close : t -> unit Lwt.t

  val listen : mgr -> src -> (dst -> t -> unit Lwt.t) -> unit Lwt.t
  val connect : mgr -> ?src:src -> dst -> (t -> 'a Lwt.t) -> 'a Lwt.t
end

module type RPC = sig

  type tx
  type rx

  type 'a req
  type 'a res

  type mgr

  type src
  type dst

  val request : mgr -> ?src:src -> dst -> tx req -> rx res Lwt.t
  val respond : mgr -> src -> (dst -> rx req -> tx res Lwt.t) -> unit Lwt.t
end
