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

open Lwt
open Nettypes
open Printf

type id = string
type config = [ `DHCP | `IPv4 of Ipaddr.V4.t * Ipaddr.V4.t * Ipaddr.V4.t list ]

(* Interfaces are a NOOP for the moment, as we depend on them being
   configured externally *)
type interface = unit
let configure () config = return ()

type t = {
  udpv4: Lwt_unix.file_descr;
  udpv4_listen_ports: (ipv4_src, Lwt_unix.file_descr) Hashtbl.t;
}

type callback = t -> interface -> id -> unit Lwt.t

let get_intf intf = ""

let get_intfs _ = []

(* Manage the protocol threads *)
let create listener =
  let open Lwt_unix in
  let udpv4 = socket PF_INET SOCK_DGRAM 0 in
  let udpv4_listen_ports = Hashtbl.create 7 in
  let t = { udpv4; udpv4_listen_ports } in
  listener t () ""

let get_udpv4 t =
  t.udpv4

(* TODO: sort out cleanup of fds *)
let register_udpv4_listener mgr src fd =
  Hashtbl.add mgr.udpv4_listen_ports src fd

let get_udpv4_listener mgr (addr,port) =
  try
    return (Hashtbl.find mgr.udpv4_listen_ports (addr,port))
  with Not_found -> begin
    let open Lwt_unix in
    let fd = socket PF_INET SOCK_DGRAM 0 in
    let addr' = match addr with None -> Ipaddr.V4.any |Some x -> x in
    bind fd (ADDR_INET (inet_addr_of_ipaddr addr',port));
    register_udpv4_listener mgr (addr,port) fd;
    return fd
  end

let attach t id =
  failwith "Socket mirage doesn't support interface attachment"
let detach t id =
  failwith "Socket mirage doesn't support interface detachment"
let inject_packet t id buf =
  failwith "Socket mirage doesn't support packet injection"
let get_intf_name t id =
  failwith "Socket mirage doesn't support dev name"
let get_intf_mac t id =
  failwith "Socket mirage doesn't support dev mac address"
let set_promiscuous t id f =
  failwith "Socket mirage doesn't support dev promiscuous mode"
