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

open Cstruct

val get_tcpv4_src_port : t -> uint16
val set_tcpv4_src_port : t -> uint16 -> unit

val get_tcpv4_dst_port : t -> uint16
val set_tcpv4_dst_port : t -> uint16 -> unit

val get_tcpv4_sequence : t -> uint32
val set_tcpv4_sequence : t -> uint32 -> unit

val get_tcpv4_ack_number : t -> uint32
val set_tcpv4_ack_number : t -> uint32 -> unit

val get_tcpv4_window : t -> uint16
val set_tcpv4_window : t -> uint16 -> unit

val get_tcpv4_checksum : t -> uint16
val set_tcpv4_checksum : t -> uint16 -> unit

val get_tcpv4_urg_ptr : t -> uint16
val set_tcpv4_urg_ptr : t -> uint16 -> unit

val get_data_offset : t -> int
val set_data_offset : t -> int -> unit

val sizeof_tcpv4 : int

val set_tcpv4_flags : t -> int -> unit

val get_fin : t -> bool
val get_syn : t -> bool
val get_rst : t -> bool
val get_psh : t -> bool
val get_ack : t -> bool
val get_urg : t -> bool
val get_ece : t -> bool
val get_cwr : t -> bool

val set_fin : t -> unit
val set_syn : t -> unit
val set_rst : t -> unit
val set_psh : t -> unit
val set_ack : t -> unit
val set_urg : t -> unit
val set_ece : t -> unit
val set_cwr : t -> unit

val get_options : t -> Options.t list
val set_options : t -> Options.ts -> int

val get_payload : t -> t

type id = {
  dest_port: int;               (* Remote TCP port *)
  dest_ip: Nettypes.ipv4_addr;           (* Remote IP address *)
  local_port: int;              (* Local TCP port *)
  local_ip: Nettypes.ipv4_addr;          (* Local IP address *)
}

val xmit : ip:Ipv4.t -> id:id -> ?rst:bool -> ?syn:bool -> ?fin:bool -> ?psh:bool ->
  rx_ack:Sequence.t option -> seq:Sequence.t -> window:int -> options:Options.ts ->
  Cstruct.t list -> unit Lwt.t
