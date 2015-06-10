(*
 * Copyright (c) 2015 Thomas Gazagnaire <thomas@gazagnaire.org>
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

(** Logging module for TCP *)

type t
(** The type for managing logging values. *)

val create: ?enabled:bool -> string -> t
(** Create a new section. By default, the section is disabled. *)

val enable: t -> unit
(** Enable a section. *)

val disable: t -> unit
(** Disable a section. *)

val enabled: t -> bool
(** [enabled t] is [true] iff [t] is enabled. *)

val name: t -> string
(** [name t] is the section name. *)

val f: t -> ('a, Format.formatter, unit) format -> 'a
(** Print some information on a logger. *)
