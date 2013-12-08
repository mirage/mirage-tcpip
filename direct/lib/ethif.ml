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
| Input of Cstruct.t
| Output of Cstruct.t list

type t = {
  netif: Netif.t;
  mac: Macaddr.t;
  arp: Arp.t;
  mutable ipv4: (Cstruct.t -> unit Lwt.t);
  mutable promiscuous:( packet -> unit Lwt.t) option;
}

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

let set_promiscuous t f =
    t.promiscuous <- Some f

let disable_promiscuous t =
    t.promiscuous <- None

let get_frame t =
  return (Io_page.to_cstruct (Io_page.get 1))

let write t frame =
  match t.promiscuous with
  |Some f -> f (Output [frame]) >>= fun () -> Netif.write t.netif frame
  |None -> Netif.write t.netif frame

let writev t bufs =
  match t.promiscuous with
  |Some f -> f (Output bufs) >>= fun () -> Netif.writev t.netif bufs
  |None -> Netif.writev t.netif bufs

let create netif =
  let ipv4 = fun (_:Cstruct.t) -> return () in
  (* TODO: there's a race here if the MAC can change in the future *)
  let mac = Netif.mac netif in
  let arp =
    let get_mac () = mac in
    let get_etherbuf () = return (Io_page.to_cstruct (Io_page.get 1)) in
    let output buf = Netif.write netif buf in
    Arp.create ~output ~get_mac ~get_etherbuf in
  let t = { netif; ipv4; mac; arp; promiscuous=None; } in
  let rec listen_t fn =
    Netif.read t.netif (Io_page.get 1)
    >>= function
    | `Error (`Unknown err)  -> fail (Failure ("failed to read from Netif: %s" ^ err))
    | `Error `Disconnected -> return ()
    | `Error _ -> fail (Failure "failed to read from Netif")
    | `Ok buf -> begin
        ignore_result (input t buf);
        listen_t fn
    end
  in
  t, (listen_t input)

let add_ip t = Arp.add_ip t.arp
let remove_ip t = Arp.remove_ip t.arp
let query_arp t = Arp.query t.arp

let attach t = function
  |`IPv4 fn -> t.ipv4 <- fn

let detach t = function
  |`IPv4 -> t.ipv4 <- fun (_:Cstruct.t) -> return ()

let mac t = t.mac
let get_netif t = t.netif
