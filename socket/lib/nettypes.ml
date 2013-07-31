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

type ipv4_addr = Unix.inet_addr

(* XXX Inefficient *)
let ipv4_addr_of_tuple (a,b,c,d) =
  let s = Printf.sprintf "%ld.%ld.%ld.%ld" a b c d in
  Unix.inet_addr_of_string s
 
(* Read an IPv4 address dot-separated string *)
let ipv4_addr_of_string x =
  try Some (Unix.inet_addr_of_string x)
  with _ -> None

(* Blank 0.0.0.0 IPv4 address *)
let ipv4_blank = Unix.inet_addr_any
(* Broadcast 255.255.255.255 IPv4 address *)
let ipv4_broadcast = ipv4_addr_of_tuple (255l,255l,255l,255l)
(* Localhost 127.0.0.1 ipv4 address  *)
let ipv4_localhost = ipv4_addr_of_tuple (127l,0l,0l,1l)

let ipv4_addr_to_string s = Unix.string_of_inet_addr s 

type ipv4_src = ipv4_addr option * int
type ipv4_dst = ipv4_addr * int

type arp = {
  op: [ `Request |`Reply |`Unknown of int ];
  sha: Macaddr.t;
  spa: ipv4_addr;
  tha: Macaddr.t;
  tpa: ipv4_addr;
}

type peer_uid = int

exception Closed

module type FLOW = sig
  (* Type of an individual flow *)
  type t
  (* Type that manages a collection of flows *)
  type mgr
  (* Type that identifies a flow source and destination endpoint *)
  type src
  type dst

  (* Read and write to a flow *)
  val read: t -> Cstruct.t option Lwt.t
  val write: t -> Cstruct.t -> unit Lwt.t
  val writev: t -> Cstruct.t list -> unit Lwt.t

  val close: t -> unit Lwt.t

  (* Flow construction *)
  val listen: mgr -> src -> (dst -> t -> unit Lwt.t) -> unit Lwt.t
  val connect: mgr -> ?src:src -> dst -> (t -> 'a Lwt.t) -> 'a Lwt.t
end

module type DATAGRAM = sig
  (* Datagram manager *)
  type mgr

  (* Identify flow and destination endpoints *)
  type src
  type dst

  (* Types of msg *)
  type msg

  (* Receive and send functions *)
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
  val read_stream: ?len:int -> t -> Cstruct.t Lwt_stream.t
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
