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

type section = int

type t = {
  name: string;
  id  : int;
  mutable enabled: bool;
  mutable stats: bool;
}

let c = ref 0

let f t fmt =
  if t.enabled && t.stats then
    let stats = Stats.create () in
    Format.printf ("Tcp.%s%a: " ^^ fmt ^^ "\n%!") t.name Stats.pp stats
  else if t.enabled then
    Format.printf ("Tcp.%s: " ^^ fmt ^^ "\n%!") t.name
  else
    Format.ifprintf Format.std_formatter fmt

let create ?(enabled=false) ?(stats=true) name =
  incr c;
  { name; id = !c; stats; enabled }

let enable  t = t.enabled <- true
let disable t = t.enabled <- false
let enabled t = t.enabled
let name    t = t.name
let stats   t = t.stats
let set_stats t b = t.stats <- b

let rec pp_print_list ?(pp_sep = Format.pp_print_cut) pp_v ppf = function
  | [] -> ()
  | [v] -> pp_v ppf v
  | v :: vs ->
    pp_v ppf v;
    pp_sep ppf ();
    pp_print_list ~pp_sep pp_v ppf vs
