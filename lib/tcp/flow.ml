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

(* TODO: modify V1.TCP to have a proper return type *)

exception Refused

let debug = Log.create "Flow"

module Make(IP:V1_LWT.IP)(TM:V1_LWT.TIME)(C:V1.CLOCK)(R:V1.RANDOM) = struct

  module Pcb = Pcb.Make(IP)(TM)(C)(R)

  type flow = Pcb.pcb
  type ip = IP.t
  type ipaddr = IP.ipaddr
  type buffer = Cstruct.t
  type +'a io = 'a Lwt.t
  type ipinput = src:ipaddr -> dst:ipaddr -> buffer -> unit io
  type t = Pcb.t
  type callback = flow -> unit Lwt.t

  type error = [
    | `Unknown of string
    | `Timeout
    | `Refused
  ]

  let err_timeout daddr dport =
    Log.f debug (fun fmt ->
        Log.pf fmt "Failed to connect to %a:%d\n%!"
          Ipaddr.pp_hum (IP.to_uipaddr daddr) dport);
    Lwt.return (`Error `Timeout)

  let err_refused daddr dport =
    Log.f debug (fun fmt ->
        Log.pf fmt "Refused connection to %a:%d\n%!"
          Ipaddr.pp_hum (IP.to_uipaddr daddr) dport);
    Lwt.return (`Error `Refused)

  let ok x = Lwt.return (`Ok x)

  let error_message = function
    | `Unknown msg -> msg
    | `Timeout -> "Timeout while attempting to connect"
    | `Refused -> "Connection refused"

  let err_rewrite = function
    | `Error (`Bad_state _) -> `Error `Refused
    | `Ok () as x -> x

  let err_raise = function
    | `Error (`Bad_state _) -> Lwt.fail Refused
    | `Ok () -> Lwt.return_unit

  let id = Pcb.ip
  let get_dest = Pcb.get_dest
  let close t = Pcb.close t
  let input = Pcb.input

  let read t =
    (* TODO better error interface in Pcb *)
    Pcb.read t >>= function
    | None   -> Lwt.return `Eof
    | Some t -> Lwt.return (`Ok t)

  let write t view = Pcb.write t view >|= err_rewrite
  let writev t views = Pcb.writev t views >|= err_rewrite
  let write_nodelay t view = Pcb.write_nodelay t view >>= err_raise
  let writev_nodelay t views = Pcb.writev_nodelay t views >>= err_raise
  let connect ipv4 = ok (Pcb.create ipv4)
  let disconnect _ = Lwt.return_unit

  let create_connection tcp (daddr, dport) =
    Pcb.connect tcp ~dest_ip:daddr ~dest_port:dport >>= function
    | `Timeout    -> err_timeout daddr dport
    | `Rst        -> err_refused daddr dport
    | `Ok (fl, _) -> ok fl

end
