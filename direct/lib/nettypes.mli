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

type bytes = string

type ethernet_mac
val ethernet_mac_of_bytes : string -> ethernet_mac
val ethernet_mac_of_string : string -> ethernet_mac option
val ethernet_mac_to_bytes : ethernet_mac -> bytes
val ethernet_mac_to_string : ethernet_mac -> string
val ethernet_mac_broadcast: ethernet_mac

type ipv4_addr
val ipv4_addr_of_tuple : (int32 * int32 * int32 * int32) -> ipv4_addr
val ipv4_addr_of_string : string -> ipv4_addr option
val ipv4_addr_to_string : ipv4_addr -> string
val ipv4_addr_of_uint32 : int32 -> ipv4_addr
val ipv4_addr_to_uint32 : ipv4_addr -> int32
val ipv4_blank : ipv4_addr
val ipv4_broadcast : ipv4_addr
val ipv4_localhost : ipv4_addr

type ipv4_src = ipv4_addr option * int
type ipv4_dst = ipv4_addr * int

type arp = {
  op: [ `Request |`Reply |`Unknown of int ];
  sha: ethernet_mac;
  spa: ipv4_addr;
  tha: ethernet_mac;
  tpa: ipv4_addr;
}

type peer_uid = int

exception Closed

module type FLOW = sig
  type t
  type mgr

  type src
  type dst

  val read : t -> Cstruct.t option Lwt.t
  val write : t -> Cstruct.t -> unit Lwt.t
  val writev : t -> Cstruct.t list -> unit Lwt.t
  val close : t -> unit Lwt.t

  val listen : mgr -> src -> (dst -> t -> unit Lwt.t) -> unit Lwt.t
  val connect : mgr -> ?src:src -> dst -> (t -> unit Lwt.t) -> unit Lwt.t
end

module type DATAGRAM = sig
  type mgr

  type src
  type dst

  type msg

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
  val connect : mgr -> ?src:src -> dst -> (t -> unit Lwt.t) -> unit Lwt.t
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
