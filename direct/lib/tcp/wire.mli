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

val get_tcpv4_src_port : buf -> uint16
val set_tcpv4_src_port : buf -> uint16 -> unit

val get_tcpv4_dst_port : buf -> uint16
val set_tcpv4_dst_port : buf -> uint16 -> unit

val get_tcpv4_sequence : buf -> uint32
val set_tcpv4_sequence : buf -> uint32 -> unit

val get_tcpv4_ack_number : buf -> uint32
val set_tcpv4_ack_number : buf -> uint32 -> unit

val get_tcpv4_window : buf -> uint16
val set_tcpv4_window : buf -> uint16 -> unit

val get_tcpv4_checksum : buf -> uint16
val set_tcpv4_checksum : buf -> uint16 -> unit

val get_tcpv4_urg_ptr : buf -> uint16
val set_tcpv4_urg_ptr : buf -> uint16 -> unit

val get_data_offset : buf -> int
val set_data_offset : buf -> int -> unit

val sizeof_tcpv4 : int

val set_tcpv4_flags : buf -> int -> unit

val get_fin : buf -> bool
val get_syn : buf -> bool
val get_rst : buf -> bool
val get_psh : buf -> bool
val get_ack : buf -> bool
val get_urg : buf -> bool
val get_ece : buf -> bool
val get_cwr : buf -> bool

val set_fin : buf -> unit
val set_syn : buf -> unit
val set_rst : buf -> unit
val set_psh : buf -> unit
val set_ack : buf -> unit
val set_urg : buf -> unit
val set_ece : buf -> unit
val set_cwr : buf -> unit

val get_options : buf -> Options.t list
val set_options : buf -> Options.ts -> int

val get_payload : buf -> buf

type id = {
  dest_port: int;               (* Remote TCP port *)
  dest_ip: Nettypes.ipv4_addr;           (* Remote IP address *)
  local_port: int;              (* Local TCP port *)
  local_ip: Nettypes.ipv4_addr;          (* Local IP address *)
}

val xmit : ip:Ipv4.t -> id:id -> ?rst:bool -> ?syn:bool -> ?fin:bool -> ?psh:bool ->
  rx_ack:Sequence.t option -> seq:Sequence.t -> window:int -> options:Options.ts ->
  OS.Io_page.t list -> unit Lwt.t
