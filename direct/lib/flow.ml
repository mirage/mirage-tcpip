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

open Lwt
open Nettypes

module TCPv4 = struct

  type t = Tcp.Pcb.pcb
  type mgr = Manager.t
  type src = ipv4_src
  type dst = ipv4_dst

  let read t =
    Tcp.Pcb.read t

  let rec write t view =
    Tcp.Pcb.write t view

  let writev t views =
    Tcp.Pcb.writev t views

  let close t =
    Tcp.Pcb.close t

  let listen mgr src fn =
    let addr, port = src in
    let tcps = Manager.tcpv4_of_addr mgr addr in
    lwt str_lst = Lwt_list.map_s (fun tcp -> return (Tcp.Pcb.listen tcp port)) tcps in
    let rec accept (st, l) =
      lwt c = Lwt_stream.get st in
      match c with 
      | None -> begin
	  return ()
      end
      | Some (fl, th) -> begin
        let _ = fn (Tcp.Pcb.get_dest fl) fl  in
        accept (st, l) 
      end
    in
    let _ = Lwt_list.iter_p accept str_lst in
    let th,_ = Lwt.task () in
    let cancelone (_, l) = Tcp.Pcb.closelistener l in
    Lwt.on_cancel th (fun () -> List.iter cancelone str_lst);
    th

  let connect mgr ?src dst fn =
    let (daddr, dport) = dst in
    let tcp =
      match src with
      | None -> Manager.tcpv4_of_dst_addr mgr daddr
      | Some s ->
	  (* TODO - change interface to make clear that sport is ignored *)
	  let (saddr, _) = s in
	  match (Manager.tcpv4_of_addr mgr saddr) with
	  | [] -> Manager.tcpv4_of_dst_addr mgr daddr
	  | h :: _ -> h
    in
    lwt conn = Tcp.Pcb.connect tcp daddr dport in
      match conn with
        | None ->
            (Printf.printf "Failed to connect to %s:%d\n%!"
               (Ipaddr.V4.to_string daddr)  dport;
             return ())
        | Some (fl, _) -> fn fl 

end

(* Shared mem communication across VMs, not yet implemented *)
module Shmem = struct
  type t = unit
  type mgr = Manager.t
  type src = int
  type dst = int

  let read t = fail (Failure "read")
  let write t view = fail (Failure "write")
  let writev t views = fail (Failure "writev")
  let close t = fail (Failure "close")

  let listen mgr src fn = fail (Failure "listen")
  let connect mgr ?src dst fn = fail (Failure "connect")

end

type t =
  | TCPv4 of TCPv4.t
  | Shmem of Shmem.t

type mgr = Manager.t

let read = function
  | TCPv4 t -> TCPv4.read t
  | Shmem t -> Shmem.read t

let write = function
  | TCPv4 t -> TCPv4.write t
  | Shmem t -> Shmem.write t

let writev = function
  | TCPv4 t -> TCPv4.writev t
  | Shmem t -> Shmem.writev t

let close = function
  | TCPv4 t -> TCPv4.close t
  | Shmem t -> Shmem.close t

let connect mgr = function
  |`TCPv4 (src, dst, fn) ->
     TCPv4.connect mgr ?src dst (fun t -> fn (TCPv4 t))
  |`Shmem (src, dst, fn) ->
     Shmem.connect mgr ?src dst (fun t -> fn (Shmem t))
  |_ -> fail (Failure "unknown protocol")

let listen mgr = function
  |`TCPv4 (src, fn) ->
     TCPv4.listen mgr src (fun dst t -> fn dst (TCPv4 t))
  |`Shmem (src, fn) ->
     Shmem.listen mgr src (fun dst t -> fn dst (Shmem t))
  |_ -> fail (Failure "unknown protocol")


