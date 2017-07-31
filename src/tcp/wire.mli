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

open Result

module Make (Ip:Mirage_protocols_lwt.IP) : sig

  type error = Mirage_protocols.Ip.error
  (** The type for TCP wire errors. *)

  val pp_error: error Fmt.t
  (** [pp_error] is the pretty-printer for TCP wire {!error}s. *)

  type t
  (** The type for TCP wire values. *)

  val pp: t Fmt.t
  (** [pp] is the pretty-printer for TCP wire values. *)

  val dst_port : t -> int
  (** Remote TCP port *)

  val dst: t -> Ip.ipaddr
  (** Remote IP address *)

  val src_port : t -> int
  (** Local TCP port *)

  val src: t -> Ip.ipaddr
  (** Local IP address *)

  val v: src:Ip.ipaddr -> src_port:int -> dst:Ip.ipaddr -> dst_port:int -> t
  (** [v ~src ~src_port ~dst ~dst_port] is the wire value [v] with the
      corresponding local and remote IP/TCP parameters. *)

  val xmit: ip:Ip.t -> t ->
    ?rst:bool -> ?syn:bool -> ?fin:bool -> ?psh:bool ->
    rx_ack:Sequence.t option -> seq:Sequence.t -> window:int ->
    options:Options.t list ->
    Cstruct.t -> (unit, error) result Lwt.t
  (** [xmit] emits a TCP packet over the network. *)

end
