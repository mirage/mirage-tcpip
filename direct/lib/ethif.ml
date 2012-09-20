(*
 * Copyright (c) 2010-2011 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (c) 2011 Richard Mortier <richard.mortier@nottingham.ac.uk>
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
open Lwt
open Nettypes
open Printf

type packet =
| Input of Cstruct.buf
| Output of Cstruct.buf list

type t = {
  ethif: OS.Netif.t;
  mac: ethernet_mac;
  arp: Arp.t;
  mutable ipv4: (OS.Io_page.t -> unit Lwt.t);
  mutable promiscuous:( packet -> unit Lwt.t) option;
}

cstruct ethernet {
  uint8_t        dst[6];
  uint8_t        src[6];
  uint16_t       ethertype
} as big_endian

let default_process t frame =
    match get_ethernet_ethertype frame with
      |0x0806 -> (* ARP *)
          Arp.input t.arp frame
      |0x0800 -> (* IPv4 *)
          let payload = Cstruct.shift frame sizeof_ethernet in 
            t.ipv4 payload
      |0x86dd -> (* IPv6 *)
          return (printf "Ethif: discarding ipv6\n%!")
      |etype ->
          return (printf "Ethif: unknown frame %x\n%!" etype)

(* Handle a single input frame *)
let input t frame =
  match t.promiscuous with  
    | None -> default_process t frame
    | Some(promiscuous) -> promiscuous (Input frame)

let set_promiscuous t f =  
    t.promiscuous <- Some(f)

let disable_promiscuous t =
    t.promiscuous <- None

(* Loop and listen for frames *)
let rec listen t =
  OS.Netif.listen t.ethif (input t)

(* Return an Ethernet buffer. The caller is responsible for creating a
 * sub-view of the payload. *)
let get_etherbuf t =
  OS.Netif.get_writebuf t.ethif

let write t buf =
  lwt () = match t.promiscuous with Some f -> f (Output [ buf ]) | None -> return () in
  OS.Netif.write t.ethif buf

let writev t bufs =
  lwt () = match t.promiscuous with Some f -> f (Output bufs) | None -> return () in
  OS.Netif.writev t.ethif bufs

let create ethif =
  let ipv4 = (fun _ -> return ()) in
  let mac = ethernet_mac_of_bytes (OS.Netif.mac ethif) in
  let arp =
    let get_mac () = mac in
    let get_etherbuf () = OS.Netif.get_writebuf ethif in
    let output buf = OS.Netif.write ethif buf in
    Arp.create ~output ~get_mac ~get_etherbuf in
  let t = { ethif; ipv4; mac; arp; promiscuous=None; } in
  let listen = listen t in
  (t, listen)

let add_ip t = Arp.add_ip t.arp
let remove_ip t = Arp.remove_ip t.arp
let query_arp t = Arp.query t.arp

let attach t = function
  |`IPv4 fn -> t.ipv4 <- fn

let detach t = function
  |`IPv4 -> t.ipv4 <- (fun _ -> return ())

let mac t = t.mac
let get_ethif t = t.ethif
