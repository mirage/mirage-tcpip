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

module type S =
  functor (IP:V1_LWT.IP) ->
  functor (TM:V1_LWT.TIME) ->
  functor (C:V1.CLOCK) ->
  functor (R:V1.RANDOM) ->
  sig
    include V1_LWT.TCP
      with type ip = IP.t
       and type ipaddr = IP.ipaddr
       and type ipinput = src:IP.ipaddr -> dst:IP.ipaddr -> Cstruct.t -> unit Lwt.t
    val connect : ip -> [> `Ok of t | `Error of error ] Lwt.t
    val watch: log:(string -> unit Lwt.t) -> t -> listeners:(int -> callback option) ->  unit Lwt.t
  end

module Make_ext (KV: KV.S): S

module Make: S
