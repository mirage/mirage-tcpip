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

open !Result

module Make(Ip:Mirage_protocols_lwt.IP)(Time:Mirage_time_lwt.S)(Clock:Mirage_clock.MCLOCK)(Random:Mirage_random.C) : sig

  (** Overall state of the TCP stack *)
  type t
  type pcb
  type error = private [> Mirage_protocols.Tcp.error]
  type write_error = private [> Mirage_protocols.Tcp.write_error]

  val pp_error: error Fmt.t
  val pp_write_error: write_error Fmt.t

  (** State for an individual connection *)
  type connection = pcb * unit Lwt.t

  val pp_pcb : Format.formatter -> pcb -> unit
  val pp_stats : Format.formatter -> t -> unit

  val ip : t -> Ip.t

  val input: t -> listeners:(int -> (pcb -> unit Lwt.t) option)
    -> src:Ip.ipaddr -> dst:Ip.ipaddr -> Cstruct.t -> unit Lwt.t

  val connect: t -> dst:Ip.ipaddr -> dst_port:int ->
    (connection, error) result Lwt.t

  val close: pcb -> unit Lwt.t

  val dst: pcb -> (Ip.ipaddr * int)

  (* Blocking read for a segment *)
  val read: pcb -> Cstruct.t option Lwt.t

  (* Number of bytes of data that can be written - can be checked before
     calling write to see if it will block. *)
  val write_available : pcb -> int
  val write_wait_for : pcb -> int -> unit Lwt.t

  (* write - blocks if the write buffer is full *)
  val write: pcb -> Cstruct.t -> (unit, write_error) result Lwt.t
  val writev: pcb -> Cstruct.t list -> (unit, write_error) result Lwt.t

  (* version of write with Nagle disabled - will block if write
     buffer is full *)
  val write_nodelay: pcb -> Cstruct.t -> (unit, write_error) result Lwt.t
  val writev_nodelay: pcb -> Cstruct.t list -> (unit, write_error) result Lwt.t

  val create: Ip.t -> Clock.t -> t
end
