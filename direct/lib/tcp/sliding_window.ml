(*
 * Copyright (c) 2012 Anil Madhavapeddy <anil@recoil.org>
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

open Printf

(* Type of sequence number. TODO functorize *)
type seq = Sequence.t
type seq_waiters = unit Lwt.u Lwt_sequence.t

(* Window advances left to right only. No going backwards! *)
type t = {
  mutable l: seq;
  mutable m: seq;
  mutable r: seq;
}

(* Initialise a new window with initial [isn] and maximum size [mss] *)
let create ~isn ~mss =
  let l = isn in
  let m = isn in
  let r = Sequence.add isn mss in
  { l; m; r }

(* Test if a sequence number is valid for a window *)
let valid t seq =
  printf "SW.valid %s <= %s <= %s\n" (Sequence.to_string t.l)
    (Sequence.to_string seq) (Sequence.to_string t.r);
  Sequence.between seq t.l t.r

let get_l t = t.l
let get_m t = t.m
let get_r t = t.r

(* TODO enforce l <= m <= r in these additions *)
let add_l t seq =
  printf "SW.incr_l %s + %s\n" (Sequence.to_string t.l) (Sequence.to_string seq);
  t.l <- Sequence.add t.l seq

let add_m t seq =
  printf "SW.incr_m %s + %s\n" (Sequence.to_string t.m) (Sequence.to_string seq);
  t.m <- Sequence.add t.m seq

let add_r t seq =
  printf "SW.incr_r %s + %s\n" (Sequence.to_string t.r) (Sequence.to_string seq);
  t.r <- Sequence.add t.r seq

let set_l t seq =
  printf "SW.set_l %s = %s\n" (Sequence.to_string t.l) (Sequence.to_string seq);
  t.l <- seq

let set_m t seq =
  printf "SW.set_m %s = %s\n" (Sequence.to_string t.m) (Sequence.to_string seq);
  t.m <- seq

let set_r t seq =
  printf "SW.set_r %s = %s\n" (Sequence.to_string t.r) (Sequence.to_string seq);
  t.r <- seq

let get_l_m t = Sequence.sub t.m t.l
let get_l_r t = Sequence.sub t.r t.l
let get_m_r t = Sequence.sub t.r t.m

let to_string t =
  sprintf "[%s %s %s]" (Sequence.to_string t.l) (Sequence.to_string t.m) 
    (Sequence.to_string t.r)
