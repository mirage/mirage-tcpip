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

let src = Logs.Src.create "flow" ~doc:"Mirage TCP Flow module"
module Log = (val Logs.src_log src : Logs.LOG)

module Make(IP:V1_LWT.IP)(TM:V1_LWT.TIME)(C:V1.MCLOCK)(R:V1_LWT.RANDOM) = struct

  module Pcb = Pcb.Make(IP)(TM)(C)(R)

  type flow = Pcb.pcb
  type ip = IP.t
  type ipaddr = IP.ipaddr
  type buffer = Cstruct.t
  type +'a io = 'a Lwt.t
  type ipinput = src:ipaddr -> dst:ipaddr -> buffer -> unit io
  type t = Pcb.t
  type callback = flow -> unit Lwt.t

  type error = V1.Tcp.error
  type write_error = V1.Flow.write_error

  let pp_error = Mirage_pp.pp_tcp_error
  let pp_write_error = Mirage_pp.pp_flow_write_error

  let log_failure daddr dport = function
    | `Timeout ->
      Log.debug (fun fmt ->
        fmt "Timeout attempting to connect to %a:%d\n%!"
          Ipaddr.pp_hum (IP.to_uipaddr daddr) dport)
    | `Refused ->
      Log.debug (fun fmt ->
        fmt "Refused connection to %a:%d\n%!"
          Ipaddr.pp_hum (IP.to_uipaddr daddr) dport)
    | (`Msg s) ->
      Log.debug (fun fmt ->
        fmt "%s error connecting to %a:%d\n%!"
          s Ipaddr.pp_hum (IP.to_uipaddr daddr) dport)

  let dst = Pcb.dst
  let close t = Pcb.close t
  let input = Pcb.input

  let read t =
    (* TODO better error interface in Pcb *)
    Pcb.read t >>= function
    | None   -> Lwt.return @@ Ok `Eof
    | Some t -> Lwt.return @@ Ok (`Data t)

  let write t view = Pcb.write t view
  let writev t views = Pcb.writev t views
  let write_nodelay t view = Pcb.write_nodelay t view
  let writev_nodelay t views = Pcb.writev_nodelay t views
  let connect ipv4 clock = Lwt.return (Pcb.create ipv4 clock)
  let disconnect _ = Lwt.return_unit

  let create_connection tcp (daddr, dport) =
    Pcb.connect tcp ~dst:daddr ~dst_port:dport >>= function
    | Error e -> log_failure daddr dport e; Lwt.return @@ Error e
    | Ok (fl, _) -> Lwt.return (Ok fl)

end
