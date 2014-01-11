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

type error = [
  | `Unknown_error of string
]

type packet =
| Input of Cstruct.t
| Output of Cstruct.t list

type state = {
  netif: Netif.t;
  mac: Macaddr.t;
  arp: Arp.t;
  mutable ipv4: (Cstruct.t -> unit Lwt.t);
  mutable promiscuous:( packet -> unit Lwt.t) option;
}

type t = state * unit Lwt.t

cstruct ethernet {
  uint8_t        dst[6];
  uint8_t        src[6];
  uint16_t       ethertype
} as big_endian

let default_process t frame =
  match get_ethernet_ethertype frame with
  | 0x0806 -> Arp.input t.arp frame (* ARP *)
  | 0x0800 -> (* IPv4 *)
    let payload = Cstruct.shift frame sizeof_ethernet in
    t.ipv4 payload
  | 0x86dd -> return () (* IPv6 *) (*printf "Ethif: discarding ipv6\n%!"*)
  | etype  -> return () (*printf "Ethif: unknown frame %x\n%!" etype*)

(* Handle a single input frame *)
let input t frame =
  match t.promiscuous with
  | None -> default_process t frame
  | Some promiscuous -> promiscuous (Input frame)

let set_promiscuous (t,_) f =
    t.promiscuous <- f

let get_frame _t =
  return (Io_page.to_cstruct (Io_page.get 1))

let write (t,_) frame =
  match t.promiscuous with
  |Some f -> f (Output [frame]) >>= fun () -> Netif.write t.netif frame
  |None -> Netif.write t.netif frame

let writev (t,_) bufs =
  match t.promiscuous with
  |Some f -> f (Output bufs) >>= fun () -> Netif.writev t.netif bufs
  |None -> Netif.writev t.netif bufs

(* Loop and listen for frames *)
let listen t =
  Netif.listen t.netif (input t)

let connect netif = 
  try_lwt
  let ipv4 = fun (_:Cstruct.t) -> return () in
  (* TODO: there's a race here if the MAC can change in the future *)
  let mac = Netif.mac netif in
  let arp =
    let get_mac () = mac in
    let get_etherbuf () = return (Io_page.to_cstruct (Io_page.get 1)) in
    let output buf = Netif.write netif buf in
    Arp.create ~output ~get_mac ~get_etherbuf in
  let t = { netif; ipv4; mac; arp; promiscuous=None; } in
  let listen = listen t in
  return (`Ok (t, listen))
  with _ -> return (`Error (`Unknown_error "TODO"))

let add_ipv4 (t,_) = Arp.add_ip t.arp
let remove_ipv4 (t,_) = Arp.remove_ip t.arp
let query_arp (t,_) = Arp.query t.arp

let attach (t,_) = function
  |`IPv4 fn -> t.ipv4 <- fn

let detach (t,_) = function
  |`IPv4 -> t.ipv4 <- fun (_:Cstruct.t) -> return ()

let mac (t,_) = t.mac
let get_netif (t,_) = t.netif
