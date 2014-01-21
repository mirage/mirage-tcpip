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

module Make(Ipv4:V1_LWT.IPV4)(Time:T.LWT_TIME)(Clock:T.CLOCK) : sig
  type t
  type pcb
  type listener
  type connection = (pcb * unit Lwt.t) 

  val input: t -> src:Ipaddr.V4.t -> dst:Ipaddr.V4.t -> Cstruct.t -> unit Lwt.t

  val connect: t -> dest_ip:Ipaddr.V4.t -> dest_port:int -> connection option Lwt.t

  val listen: t -> int -> (connection Lwt_stream.t * listener)
  val closelistener: listener -> unit

  val close: pcb -> unit Lwt.t

  val get_dest: pcb -> (Ipaddr.V4.t * int)

  (* Blocking read for a segment *)
  val read: pcb -> Cstruct.t option Lwt.t

  (* Number of bytes of data that can be written - can be checked before
     calling write to see if it will block. *)
  val write_available : pcb -> int
  val write_wait_for : pcb -> int -> unit Lwt.t

  (* write - blocks if the write buffer is full *)
  val write: pcb -> Cstruct.t -> unit Lwt.t
  val writev: pcb -> Cstruct.t list -> unit Lwt.t

  (* version of write with Nagle disabled - will block if write
     buffer is full *)
  val write_nodelay: pcb -> Cstruct.t -> unit Lwt.t
  val writev_nodelay: pcb -> Cstruct.t list -> unit Lwt.t

  val create: Ipv4.t -> t
  (* val tcpstats: t -> unit *)
end
