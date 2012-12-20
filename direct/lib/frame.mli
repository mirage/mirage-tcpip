(*
 * Copyright (c) 2012 Citrix Systems Inc
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

type t
(** Represents a (potentially nested) protocol frame within a
    (potentially larger) frame. For example we could create
    an ethernet frame and nest an IPv4 frame inside. *)

val of_buffer: Cstruct.t -> int -> t
(** [of_buffer buffer sizeof_header] constructs a fresh, non-nested
    frame from the given buffer with a fixed header of size
    [sizeof_header] *)

val of_t: t -> int -> t
(** [of_t sizeof_header] constructs a nested frame with a fixed
    header of size [sizeof_header] from an existing frame. *)

val get_header: t -> Cstruct.t
(** [get_header t] returns the Cstruct.t "view" of the header
    of this frame only. *)

val get_payload: t -> Cstruct.t
(** [get_payload t] returns the Cstruct.t "view" of the payload
    of this frame only. *)

val set_payload_len: t -> int -> unit
(** [set_payload_len t len] truncates the payload length of [t]
    to [len]. This recursively truncates the payloads of any
    parent frame. *)

val get_whole_buffer: t -> Cstruct.t
(** [get_whole_buffer t] returns the entire outermost frame,
    ready for transmission on a network. *)

