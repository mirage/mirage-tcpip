(*
 * Copyright (c) 2011 Anil Madhavapeddy <anil@recoil.org>
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

(* The manager process binds application ports to interfaces, and
   will eventually deal with load balancing and route determination
   (e.g. if a remote target is on the same host, swap to shared memory *)

open Nettypes

(** Type representing an IPv4 configuration for an interface. *)
type config = [ `DHCP | `IPv4 of ipv4_addr * ipv4_addr * ipv4_addr list ]

(** Textual id identifying a network interface, typically "tap0" on
    UNIX and "0" on Xen. *)
type id = OS.Netif.id

(** Type representing a network interface, including facilities to
    send data (Ethernet frames, IP packets, ICMP, UDP, TCP, ...)
    through it. *)
type interface

(** Type of a manager. *)
type t

(** Type of the callback function provided at manager creation
    time. *)
type callback = t -> interface -> id -> unit Lwt.t

(** Accesors for components of the interface type *)

val get_id    : interface -> id
val get_ethif : interface -> Ethif.t
val get_ipv4  : interface -> Ipv4.t
val get_icmp  : interface -> Icmp.t
val get_udp   : interface -> Udp.t
val get_tcp   : interface -> Tcp.Pcb.t

(** [create callback] will create a manager that will use
    [OS.Netif.create] to watch for network interfaces, create a value
    of type interface for each of those devices and call [callback] of
    each of them. The return value is a cancellable thread that will
    free all interface values when cancelled. *)
val create : callback -> unit Lwt.t

(** [configure intf cfg] applies [cfg] to [intf]. After this step,
    depending on the configuration (DHCP or static address), [intf]
    will either perform a DHCP discovery or assign itself a specified
    address, and will be able to receive and send packets at the
    resulting address. *)
val configure: interface -> config -> unit Lwt.t

(** [set_promiscuous mgr id f] will install [f] as the promiscuous
    callback for [id] if it exists, or raise [Not_found]
    otherwise. See the documentation of module [Ethif] for more
    information about registering a callback for the promiscuous
    mode. *)
val set_promiscuous: t -> id -> (id -> Ethif.packet -> unit Lwt.t) -> unit

(** [inject_packet mgr id frame] will write [frame] into [id]'s
    buffer, causing [frame] to be emitted on the network. *)
val inject_packet : t -> id -> Cstruct.t -> unit Lwt.t

(** [tcpv4_of_addr mgr ip] returns all the TCP threads that operate on
    [ip]. *)
val tcpv4_of_addr : t -> ipv4_addr option -> Tcp.Pcb.t list

(** Like [tcpv4_of_addr] returns UDP threads. *)
val udpv4_of_addr : t -> ipv4_addr option -> Udp.t list

(** [tcpv4_of_dst_addr mgr ip] returns a TCP threads able to talk to
    remote address [ip]. *)
val tcpv4_of_dst_addr : t -> ipv4_addr -> Tcp.Pcb.t

(** [get_intf_mac mgr id] returns the MAC address of interface [id].*)
val get_intf_mac : t -> id -> ethernet_mac

(** [get_intf_ipv4addr mgr id] returns the IPv4 address of interface
    [id] if it exists, or raise [Not_found] otherwise. *)
val get_intf_ipv4addr : t -> id -> ipv4_addr

val get_intfs : t -> (id * interface) list
