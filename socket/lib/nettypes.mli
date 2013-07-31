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

(** Functions and type definitions common to all modules. *)

(** Functions handling IPv4 addresses. *)

(** Type representing IPv4 addresses. *)
type ipv4_addr = Unix.inet_addr

(** [ipv4_addr_of_tuple (a,b,c,d)] is an address whose dot separated
    string representation is a.b.c.d. *)
val ipv4_addr_of_tuple : (int32 * int32 * int32 * int32) -> ipv4_addr

(** [ipv4_addr_of_string "a.b.c.d"] is [Some addr] if "a.b.c.d" is a
    dot separated string representation of a valid IPv4, or [None]
    otherwise. *)
val ipv4_addr_of_string : string -> ipv4_addr option

(** [ipv4_addr_to_string addr] is the dot separated string
    representing [addr]. *)
val ipv4_addr_to_string : ipv4_addr -> string

(** [ipv4_blank] is the address whose dot separated string
    representation is "0.0.0.0". *)
val ipv4_blank : ipv4_addr

(** [ipv4_broadcast] is the address whose dot separated string
    representation is "255.255.255.255". *)
val ipv4_broadcast : ipv4_addr

(** [ipv4_localhost] is the address whose dot separated string
    representation is "127.0.0.1". *)
val ipv4_localhost : ipv4_addr

(** Type of source socket addresses. *)
type ipv4_src = ipv4_addr option * int

(** Type of destination socket addresses. *)
type ipv4_dst = ipv4_addr * int

(** Type of an ARP packet. *)
type arp = {
  op: [ `Request |`Reply |`Unknown of int ]; (** operation *)
  sha: Macaddr.t;                         (** source hardware address *)
  spa: ipv4_addr;                            (** source protocol address *)
  tha: Macaddr.t;                         (** target hardware address *)
  tpa: ipv4_addr;                            (** target protocol address *)
}

type peer_uid = int

exception Closed

(** Type of an unbuffered byte-stream network protocol, e.g. TCP with
    each write being a segment. *)
module type FLOW = sig

  (** Type of an individual flow. *)
  type t

  (** Type that manages a collection of flows. *)
  type mgr

  (** Types that identifies a flow source and destination endoint. *)

  type src
  type dst

  (** Functions to read and write to/from a flow. *)

  val read    : t -> Cstruct.t option Lwt.t
  val write   : t -> Cstruct.t -> unit Lwt.t
  val writev  : t -> Cstruct.t list -> unit Lwt.t
  val close   : t -> unit Lwt.t

  (** Functions to construct flows. *)

  val listen  : mgr -> src -> (dst -> t -> unit Lwt.t) -> unit Lwt.t
  val connect : mgr -> ?src:src -> dst -> (t -> 'a Lwt.t) -> 'a Lwt.t
end

(** Type of a datagram-based network protocol, e.g. UDP. *)
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

(** Type of a buffered byte-stream network protocol, e.g. TCP with
    each write buffered and TCP segmentation done. *)
module type CHANNEL = sig

  type mgr
  type t
  type src
  type dst

  val read_char    : t -> char Lwt.t
  val read_until   : t -> char -> (bool * Cstruct.t) Lwt.t
  val read_some    : ?len:int -> t -> Cstruct.t Lwt.t
  val read_stream  : ?len: int -> t -> Cstruct.t Lwt_stream.t
  val read_line    : t -> Cstruct.t list Lwt.t

  val write_char   : t -> char -> unit
  val write_string : t -> string -> int -> int -> unit
  val write_buffer : t -> Cstruct.t -> unit
  val write_line   : t -> string -> unit

  val flush        : t -> unit Lwt.t
  val close        : t -> unit Lwt.t

  val listen       : mgr -> src -> (dst -> t -> unit Lwt.t) -> unit Lwt.t
  val connect      : mgr -> ?src:src -> dst -> (t -> 'a Lwt.t) -> 'a Lwt.t
end
