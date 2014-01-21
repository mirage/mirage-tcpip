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

val get_options : Cstruct.t -> Options.t list
val set_options : Cstruct.t -> Options.ts -> int
val get_payload : Cstruct.t -> Cstruct.t

type id = {
  dest_port: int;               (* Remote TCP port *)
  dest_ip: Ipaddr.V4.t;         (* Remote IP address *)
  local_port: int;              (* Local TCP port *)
  local_ip: Ipaddr.V4.t;        (* Local IP address *)
}

module Make(Ipv4:V1_LWT.IPV4) : sig
  val xmit : ip:Ipv4.t -> id:id ->
    ?rst:bool -> ?syn:bool -> ?fin:bool -> ?psh:bool ->
    rx_ack:Sequence.t option -> seq:Sequence.t -> window:int -> options:Options.ts ->
    Cstruct.t list -> unit Lwt.t
end
