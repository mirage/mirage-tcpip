(*
 * Copyright (c) 2011-2014 Anil Madhavapeddy <anil@recoil.org>
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


module Make (IP:V1_LWT.IPV4)(TM:T.LWT_TIME)(C:T.CLOCK)(R:T.RANDOM): sig

  type flow
  type id = IP.t
  type +'a io = 'a Lwt.t
  type t 
  type buffer = Cstruct.t

  type error = [
   | `Unknown_error of string
  ]

  val read : flow -> [`Ok of buffer | `Eof | `Error of error ] Lwt.t
  val write : flow -> buffer -> unit Lwt.t
  val writev : flow -> buffer list -> unit Lwt.t
  val write_nodelay : flow -> buffer -> unit Lwt.t
  val writev_nodelay : flow -> buffer list -> unit Lwt.t
  val close : flow -> unit Lwt.t

  val listen : t -> int ->
    (Ipaddr.V4.t * int -> flow -> unit Lwt.t) -> unit Lwt.t

  val create_connection : t ->
    Ipaddr.V4.t * int -> (flow -> unit Lwt.t) -> unit Lwt.t

  val connect : id -> [ `Ok of t ] Lwt.t
  val disconnect : t -> unit Lwt.t
end

