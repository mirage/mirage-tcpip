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

type ipv4_src = ipv4_addr option * int
type ipv4_dst = ipv4_addr * int

module TCPv4 : FLOW with
      type mgr = Manager.t
  and type src = ipv4_src
  and type dst = ipv4_dst

module Shmem : FLOW with
      type mgr = Manager.t
  and type src = peer_uid
  and type dst = peer_uid

type t
val read: t -> Cstruct.t option Lwt.t
val write: t -> Cstruct.t -> unit Lwt.t
val writev: t -> Cstruct.t list -> unit Lwt.t
val close: t -> unit Lwt.t

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

