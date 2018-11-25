(*
 * Copyright (c) 2011-2014 Anil Madhavapeddy <anil@recoil.org>
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

open Lwt.Infix

let src = Logs.Src.create "tcpip-stack-direct" ~doc:"Pure OCaml TCP/IP stack"
module Log = (val Logs.src_log src : Logs.LOG)

type direct_ipv4_input = src:Ipaddr.V4.t -> dst:Ipaddr.V4.t -> Cstruct.t -> unit Lwt.t
module type UDPV4_DIRECT = Mirage_protocols_lwt.UDPV4
  with type ipinput = direct_ipv4_input

module type TCPV4_DIRECT = Mirage_protocols_lwt.TCPV4
  with type ipinput = direct_ipv4_input

module Make
    (Time    : Mirage_time.S)
    (Random  : Mirage_random.C)
    (Ipv4    : Mirage_protocols_lwt.IPV4)
    (Icmpv4  : Mirage_protocols_lwt.ICMPV4)
    (Udpv4   : UDPV4_DIRECT)
    (Tcpv4   : TCPV4_DIRECT) = struct
  type +'a io = 'a Lwt.t
  type buffer = Cstruct.t
  type ipv4addr = Ipaddr.V4.t
  type tcpv4 = Tcpv4.t
  type udpv4 = Udpv4.t
  type ipv4 = Ipv4.t

  module UDPV4 = Udpv4
  module TCPV4 = Tcpv4
  module IPV4  = Ipv4

  type t = {
    ipv4  : Ipv4.t;
    icmpv4: Icmpv4.t;
    udpv4 : Udpv4.t;
    tcpv4 : Tcpv4.t;
    udpv4_listeners: (int, Udpv4.callback) Hashtbl.t;
    tcpv4_listeners: (int, Tcpv4.listener) Hashtbl.t;
  }

  let pp fmt t =
    Format.fprintf fmt "ip=%a" (Fmt.list Ipaddr.V4.pp_hum) (Ipv4.get_ip t.ipv4)

  let tcpv4 { tcpv4; _ } = tcpv4
  let udpv4 { udpv4; _ } = udpv4
  let ipv4 { ipv4; _ } = ipv4

  let err_invalid_port p = Printf.sprintf "invalid port number (%d)" p

  let listen_udpv4 t ~port callback =
    if port < 0 || port > 65535
    then raise (Invalid_argument (err_invalid_port port))
    else Hashtbl.replace t.udpv4_listeners port callback


  let listen_tcpv4 ?keepalive t ~port process =
    if port < 0 || port > 65535
    then raise (Invalid_argument (err_invalid_port port))
    else Hashtbl.replace t.tcpv4_listeners port { Tcpv4.process; keepalive }

  let udpv4_listeners t ~dst_port =
    try Some (Hashtbl.find t.udpv4_listeners dst_port)
    with Not_found -> None

  let tcpv4_listeners t dst_port =
    try Some (Hashtbl.find t.tcpv4_listeners dst_port)
    with Not_found -> None

  let listen t =
    Logs.warn (fun f -> f "deprecated listen on stack %a" pp t);
    let task, _ = Lwt.task () in
    task

  let connect ipv4 icmpv4 udpv4 tcpv4 =
    let t = { ipv4; icmpv4; tcpv4; udpv4;
              udpv4_listeners = Hashtbl.create 7 ; tcpv4_listeners = Hashtbl.create 7 } in
    Log.info (fun f -> f "stack assembled: %a" pp t);
    (match
       Ipv4.register ipv4 `TCP (Tcpv4.input tcpv4 ~listeners:(tcpv4_listeners t)),
       Ipv4.register ipv4 `UDP (Udpv4.input udpv4 ~listeners:(udpv4_listeners t)),
       Ipv4.register ipv4 `ICMP (Icmpv4.input icmpv4)
     with
     | Ok (), Ok (), Ok () -> Lwt.return_unit
     | _ -> Lwt.fail_with "conflict ipv4") >>= fun () ->
    Lwt.return t


  let disconnect t =
    (* TODO: kill the listening thread *)
    Log.info (fun f -> f "disconnect called (currently a noop): %a" pp t);
    Lwt.return_unit
end
