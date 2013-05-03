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

(** Send and receive UDP packets. *)

open Nettypes

(** Values of type [t] are facilities used to send and react to UDP
    packets on a given IPv4 address, included in the type. *)
type t

(** Type of callbacks used by [listen]. [cb ~src ~dst ~source_port
    data] is a thread that process some [data] coming from address
    [src] and port [source_port], sent at address [dst]. *)
type callback = src:ipv4_addr -> dst:ipv4_addr -> source_port:int -> Cstruct.t -> unit Lwt.t

(** [create ip] is a pair whose first element is a freshly created
    value of type [t] and second element a cancellable thread that
    will perform cleanup operations when cancelled. *)
val create : Ipv4.t -> t * unit Lwt.t

(** [listen udp port cb] installs [cb] to handle UDP packets incoming
    at [port], and return a cancellable thread that will uninstall
    [cb] when cancelled. *)
val listen: t -> int -> callback -> unit Lwt.t

(** [write ~source_port ~dest_ip ~dest_port udp data] is a thread that
    sends [data] from [~source_port] at [~dest_ip], [~dest_port]. *)
val write: source_port:int -> dest_ip:ipv4_addr -> dest_port:int -> t -> Cstruct.t -> unit Lwt.t

(** Same as above but sends a vector of messages instead of just
    one. *)
val writev: source_port:int -> dest_ip:ipv4_addr -> dest_port:int -> t -> Cstruct.t list -> unit Lwt.t


