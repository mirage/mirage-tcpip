(*
 * Copyright (c) 2013 Balraj Singh <bs375@cl.cam.ac.uk>
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

let lastprinttime = ref (Clock.time ())
let totaltime = ref 0.0
let epochlen = 1.0

type t = {
    name: string;
    mutable total: float;
    mutable recent: float;
    mutable start: float;
    mutable on: bool;
  }


let hashtbl_find h k =
  try Some (Hashtbl.find h k) with Not_found -> None

let profiles = Hashtbl.create 7 

let start s =
  match (hashtbl_find profiles s) with
  | Some p ->
      if p.on then begin
	printf "Profiler error: %s was running and started again - ignoring start\n%!" s
      end else begin
	p.on <- true;
	p.start <- (Clock.time ());
      end
  | None ->
      let name = s in
      let total = 0.0 in
      let recent = 0.0 in
      let start = (Clock.time ()) in
      let on = true in
      Hashtbl.add profiles s {name; total; recent; start; on}
	
let finish s =
  let ctime = Clock.time () in
  let finish_p s = match (hashtbl_find profiles s) with
  | Some p ->
      if p.on then begin
	p.on <- false;
	let pt = ctime -. p.start in
	p.total <- p.total +. pt;
	p.recent <- p.recent +. pt
      end else begin
	printf "Profiler error: %s was not running but finished - ignoring finish\n%!" s
      end
  | None ->
      printf "Profiler error: %s never started\n%!" s
  in
  finish_p s;
  let printone s p =
    printf "  %s: total=%f recent=%f\n%!" s p.total p.recent;
    p.recent <- 0.0
  in
  let etime = ctime -. !lastprinttime in
  if etime >= epochlen then begin
    lastprinttime := ctime;
    totaltime := !totaltime +. etime;
    printf "Elapsed time = %f, Total time = %f\n%!" etime !totaltime;
    Hashtbl.iter printone profiles;
    printf " \n%!"
  end


