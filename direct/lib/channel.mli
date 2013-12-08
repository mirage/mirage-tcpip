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

(** Buffered streams over TCP or shared memory. *)

open Nettypes

module TCPv4 : CHANNEL with
      type src = ipv4_src
  and type dst = ipv4_dst
  and type mgr = Manager.t

module Shmem : CHANNEL with
      type src = peer_uid
  and type dst = peer_uid
  and type mgr = Manager.t

type t

val read_char: t -> char Lwt.t
(** [read_char c] returns one character from [c]. *)

val read_some: ?len:int -> t -> Cstruct.t Lwt.t
(** [read_some ?len c] reads up to [len] characters from [c], or reads
    as much characters as possible if [len] is [None]. *)

val read_stream: ?len:int -> t -> Cstruct.t Lwt_stream.t
(** [read_stream ?len c] creates a [Lwt_steam.t] using [read_some]. *)

val read_until: t -> char -> (bool * Cstruct.t) Lwt.t
(** [read_until c ch] reads from [c] until [ch] is found if [ch]
    belongs to the set of characters in the channel, or reads until
    EOF otherwise. *)

val read_exactly: t -> int -> Cstruct.t Lwt.t
(** [read_exactly len c] reads exactly [len] characters from [c] and blocks until
 * [len] characters are available. *)


val read_line: t -> Cstruct.t list Lwt.t
(** [read_line c] returns a list of views corresponding to one line
    (e.g. that finishes by LF or CRLF). *)

val write_char : t -> char -> unit
(** [write_char c ch] writes [ch] into [c]. *)

val write_string : t -> string -> int -> int -> unit
(** [write_string c buf off len] writes [len] characters from [buf]
    starting at [off] to [c]. *)

val write_buffer : t -> Cstruct.t -> unit
(** [write_buffer c buf] do a zero-copy write of [buf] to [c]. *)

val write_line : t -> string -> unit
(** Like [write_string] but appends a LF at the end of the string. *)

val flush : t -> unit Lwt.t
val close : t -> unit Lwt.t

val connect :
  Manager.t -> [> 
   | `Shmem of peer_uid option * peer_uid * (t -> unit Lwt.t)
   | `TCPv4 of ipv4_src option * ipv4_dst * (t -> unit Lwt.t)
  ] -> unit Lwt.t

val listen :
  Manager.t -> [> 
   | `Shmem of peer_uid * (peer_uid -> t -> unit Lwt.t)
   | `TCPv4 of ipv4_src * (ipv4_dst -> t -> unit Lwt.t)
  ] -> unit Lwt.t
