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

val create: ?enabled:bool -> ?stats:bool -> string -> t
(** Create a new section. By default, the section is disabled and the
    stats are printed. *)

val enable: t -> unit
(** Enable a section. *)

val disable: t -> unit
(** Disable a section. *)

val set_stats: t -> bool -> unit
(** Display the stats on every debug line. *)

val stats: t -> bool
(** Check if the stats are displayed. *)

val enabled: t -> bool
(** [enabled t] is [true] iff [t] is enabled. *)

val name: t -> string
(** [name t] is the section name. *)

val f: t -> (Format.formatter -> unit) -> unit
(** Print a formatted entry into a logger. *)

val s: t -> string -> unit
(** Print a string into a logger. *)

val ps: Format.formatter -> string -> unit
(** Same as {!format.pp_print_string}. *)

val pf: Format.formatter -> ('a, Format.formatter, unit) format -> 'a
(** Same as {!Format.fprintf}, to be used with {!f}. *)

val pp_print_list:
  ?pp_sep:(Format.formatter -> unit -> unit) ->
  (Format.formatter -> 'a -> unit) -> (Format.formatter -> 'a list -> unit)
(** [pp_print_list ?pp_sep pp_v ppf l] prints the list [l]. [pp_v] is
    used on the elements of [l] and each element is separated by
    a call to [pp_sep] (defaults to {!pp_print_cut}). Does nothing on
    empty lists.

    @since 4.02.0
*)
