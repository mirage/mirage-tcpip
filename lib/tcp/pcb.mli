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

module Make(Ip:V1_LWT.IP)(Time:V1_LWT.TIME)(Clock:V1.MCLOCK)(Random:V1.RANDOM) : sig

  (** Overall state of the TCP stack *)
  type t
  type pcb

  (** State for an individual connection *)
  type connection = pcb * unit Lwt.t

  (** Result of attempting to open a connection *)
  type connection_result = [ `Ok of connection | `Rst | `Timeout ]

  val pp_pcb : Format.formatter -> pcb -> unit
  val pp_stats : Format.formatter -> t -> unit

  val ip : t -> Ip.t

  val input: t -> listeners:(int -> (pcb -> unit Lwt.t) option)
    -> src:Ip.ipaddr -> dst:Ip.ipaddr -> Cstruct.t -> unit Lwt.t

  val connect: t -> dst:Ip.ipaddr -> dst_port:int -> connection_result Lwt.t

  val close: pcb -> unit Lwt.t

  val dst: pcb -> (Ip.ipaddr * int)

  (* Blocking read for a segment *)
  val read: pcb -> Cstruct.t option Lwt.t

  (* Number of bytes of data that can be written - can be checked before
     calling write to see if it will block. *)
  val write_available : pcb -> int
  val write_wait_for : pcb -> int -> unit Lwt.t

  (* write - blocks if the write buffer is full *)
  val write: pcb -> Cstruct.t -> (unit, string) Result.result Lwt.t
  val writev: pcb -> Cstruct.t list -> (unit, string) Result.result Lwt.t

  (* version of write with Nagle disabled - will block if write
     buffer is full *)
  val write_nodelay: pcb -> Cstruct.t -> (unit, string) Result.result Lwt.t
  val writev_nodelay: pcb -> Cstruct.t list -> (unit, string) Result.result Lwt.t

  val create: Ip.t -> Clock.t -> t
end
