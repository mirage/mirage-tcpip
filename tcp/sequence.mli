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

type t

(* a < b *)
val lt : t -> t -> bool

(* a <= b *)
val leq : t -> t -> bool

(* a > b *)
val gt : t -> t -> bool

(* a >= b *)
val geq : t -> t -> bool

(* b <= a <= c *)
val between : t -> t -> t -> bool

(* a + b *)
val add: t -> t -> t

(* a - b *)
val sub: t -> t -> t

(* a++ *)
val incr: t -> t

val compare: t -> t -> int
val of_int32: int32 -> t
val of_int: int -> t
val to_int32: t -> int32
val to_int: t -> int
val to_string: t -> string
val of_string: string -> t
