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

type id = OS.Netif.id

type interface = {
  id    : id;
  ethif : Ethif.t;
  ipv4  : Ipv4.t;
  icmp  : Icmp.t;
  udp   : Udp.t;
  tcp   : Tcp.Pcb.t;
}

let get_id t    = t.id
let get_ethif t = t.ethif
let get_ipv4 t  = t.ipv4
let get_icmp t  = t.icmp
let get_udp t   = t.udp
let get_tcp t   = t.tcp

type callback = t -> interface -> id -> unit Lwt.t

and t = {
  cb: callback;
  listeners: (id, interface) Hashtbl.t
}

type config = [ `DHCP | `IPv4 of ipv4_addr * ipv4_addr * ipv4_addr list ]

(* Configure an interface based on the Config module *)
let configure i =
  function
  |`DHCP ->
    Printf.printf "Manager: Interface %s to DHCP\n%!" (OS.Netif.string_of_id i.id);
    lwt t, th = Dhcp.Client.create i.ipv4 i.udp in
    Printf.printf "Manager: DHCP done\n%!";
    return ()
  |`IPv4 (addr, netmask, gateways) ->
    Printf.printf "Manager: Interface %s to %s nm %s gw [%s]\n%!"
      (OS.Netif.string_of_id i.id)
      (ipv4_addr_to_string addr)
      (ipv4_addr_to_string netmask)
      (String.concat ", " (List.map ipv4_addr_to_string gateways));
    Ipv4.set_ip i.ipv4 addr >>
    Ipv4.set_netmask i.ipv4 netmask >>
    Ipv4.set_gateways i.ipv4 gateways >>
    return ()

(* Plug in a new network interface with given id *)
let plug t netif =
  let id = OS.Netif.id netif in
  Printf.printf "Manager: plug %s\n%!" (OS.Netif.string_of_id id);
  let (ethif, ethif_t) = Ethif.create netif in
  let (ipv4, ipv4_t)   = Ipv4.create ethif in
  let (icmp, icmp_t)   = Icmp.create ipv4 in
  let (tcp, tcp_t)     = Tcp.Pcb.create ipv4 in
  let (udp, udp_t)     = Udp.create ipv4 in
  let i = { id; ipv4; icmp; ethif; tcp; udp } in
  (* The interface thread should be cancellable by exceptions from the
     rest of the threads, as a debug measure.
     TODO: think about cancellation strategy here
     TODO: think about restart strategies here *)
  (* Register the interface_t with the manager interface *)
  Hashtbl.add t.listeners id i;
  Printf.printf "Manager: plug done, to listener\n%!"

(* Unplug a network interface. TODO: Cancel its thread as well. *)
let unplug t id =
  Hashtbl.remove t.listeners id

(* Manage the protocol threads. The listener becomes a new thread
   that is spawned when a new interface shows up. *)
let create cb =
  Printf.printf "Manager: create\n%!";
  let listeners = Hashtbl.create 1 in
  let t = { cb; listeners } in
  lwt intfs = OS.Netif.create () in
  let () = List.iter (plug t) intfs in
  (* Now asynchronously launching the callbacks! *)
  Hashtbl.iter (fun id intf ->
      Lwt.async (fun () -> t.cb t intf id)) t.listeners;
  let th,_ = Lwt.task () in
  Lwt.on_cancel th (fun _ ->
    Printf.printf "Manager: cancel\n%!";
    Hashtbl.iter (fun id _ -> unplug t id) listeners);
  Printf.printf "Manager: init done\n%!";
  th

(* Find the interfaces associated with the address *)
let i_of_ip t = function
  | None ->
    Hashtbl.fold (fun _ i a -> i :: a) t.listeners []
  | Some addr ->
    Hashtbl.fold
      (fun _ i a -> if Ipv4.get_ip i.ipv4 = addr then i :: a else a)
      t.listeners []

let match_ip_match ip netmask dst_ip =
  let src_match = Int32.logand ip netmask in
  let dst_match = Int32.logand dst_ip netmask in
    (src_match = dst_match)

(* Get an appropriate interface for a dest ip *)
let i_of_dst_ip t addr =
  let ret = ref None in
  let netmask = ref 0l in
  let addr = Nettypes.ipv4_addr_to_uint32 addr in 
  let _ = Hashtbl.iter
      (fun _ i ->
         let l_ip =  Nettypes.ipv4_addr_to_uint32 
                       (Ipv4.get_ip i.ipv4) in
         let l_mask = Nettypes.ipv4_addr_to_uint32 
                        (Ipv4.get_netmask i.ipv4) in
           (* Need to consider also default gateways as 
           * well as same subnet forwarding *)
          if (( (Int32.logor (!netmask) l_mask) <> !netmask) &&
               (match_ip_match l_ip l_mask addr)) then (
                 ret := Some(i);
                 netmask :=  Nettypes.ipv4_addr_to_uint32 
                               (Ipv4.get_netmask i.ipv4)
               )
      ) t.listeners in
    match !ret with
      | None -> failwith("No_Path_dst")
      | Some(ret) -> ret

(* Match an address and port to a TCP thread *)
let tcpv4_of_addr t addr = List.map (fun x -> x.tcp) (i_of_ip t addr)

(* TODO: do actual route selection *)
let udpv4_of_addr (t:t) addr = List.map (fun x -> x.udp) (i_of_ip t addr)

let tcpv4_of_dst_addr t addr =
  let x = i_of_dst_ip t addr in
    x.tcp

let inject_packet t id frame =
  try_lwt
    let intf = Hashtbl.find t.listeners id in
      Ethif.write intf.ethif frame
  with exn ->
    return (Printf.eprintf "Net.Manager.inject_packet : %s\n%!"
              (Printexc.to_string exn))

let get_intfs t = Hashtbl.fold (fun k v a -> (k,v)::a) t.listeners []

let get_intf_mac t id =
  let intf = Hashtbl.find t.listeners id in
  Ethif.mac intf.ethif

let get_intf_ipv4addr t id =
  let intf = Hashtbl.find t.listeners id in
  Ipv4.get_ip intf.ipv4

let set_promiscuous t id f =
  let intf = Hashtbl.find t.listeners id in
  Ethif.set_promiscuous intf.ethif (f id)

