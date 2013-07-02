(*
 * Copyright (c) 2010-2011 Anil Madhavapeddy <anil@recoil.org>
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
 *
 *)

open Nettypes
open Printf

(** Type of an ARP record. ARP records are included in Ethif.t
    values. They contain, among other bits, a list of bound IPs, and a
    IPv4 -> MAC hashtbl. *)
type t

(** [create ~get_etherbuf ~output ~get_mac] creates a value of type
    [t]. *)
val create: get_etherbuf:(unit -> Cstruct.t Lwt.t) ->
  output:(Cstruct.t -> unit Lwt.t) -> get_mac:(unit -> ethernet_mac) -> t

(** [set_ips arp] sets the bound IP address list, which will xmit a
    GARP packet also. *)
val set_ips: t -> ipv4_addr list -> unit Lwt.t

(** [get_ips arp] gets the bound IP address list in the [arp]
    value. *)
val get_ips: t -> ipv4_addr list

(** [add_ip arp ip] adds [ip] to the bound IP address list in the
    [arp] value, which will xmit a GARP packet also. *)
val add_ip: t -> ipv4_addr -> unit Lwt.t

(** [remove_ip arp ip] removes [ip] to the bound IP address list in
    the [arp] value, which will xmit a GARP packet also. *)
val remove_ip: t -> ipv4_addr -> unit Lwt.t

(** [input arp frame] will handle an ethernet frame containing an ARP
    packet. If it is a response, it will update its cache, otherwise
    will try to satisfy the request. *)
val input: t -> Cstruct.t -> unit Lwt.t

(** [query arp ip] queries the cache in [arp] for an ARP entry
    corresponding to [ip], which may result in the sender sleeping
    waiting for a response. *)
val query: t -> ipv4_addr -> ethernet_mac Lwt.t

