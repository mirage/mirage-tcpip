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

open Nettypes

type t
val input: t -> src:ipv4_addr -> dst:ipv4_addr -> Cstruct.t -> unit Lwt.t

val get_frame: dest_ip:ipv4_addr -> source_port:int -> dest_port:int -> t -> Frame.t Lwt.t

val output : t -> Frame.t -> unit Lwt.t

val write: dest_ip:ipv4_addr -> source_port:int -> dest_port:int -> t -> Cstruct.t -> unit Lwt.t

val writev: dest_ip:ipv4_addr -> source_port:int -> dest_port:int -> t -> Cstruct.t list -> unit Lwt.t

val listen: t -> int -> (src:ipv4_addr -> dst:ipv4_addr -> source_port:int -> Cstruct.t -> unit Lwt.t) -> unit Lwt.t

val create : Ipv4.t -> t * unit Lwt.t
