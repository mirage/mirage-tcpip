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

open Lwt

module Make(IP:V1_LWT.IPV4)(TM:V1_LWT.TIME)(C:V1.CLOCK)(R:V1.RANDOM) = struct

  module Pcb = Pcb.Make(IP)(TM)(C)(R)

  type flow = Pcb.pcb
  type ipv4 = IP.t
  type ipv4addr = Ipaddr.V4.t
  type buffer = Cstruct.t
  type +'a io = 'a Lwt.t
  type ipv4input = src:ipv4addr -> dst:ipv4addr -> buffer -> unit io
  type t = Pcb.t
  type callback = flow -> unit Lwt.t

  type error = [
    | `Unknown of string
    | `Timeout
    | `Refused
  ]

  let id t = Pcb.ip t

  let get_dest t = Pcb.get_dest t

  let read t =
    (* TODO better error interface in Pcb *)
    Pcb.read t >>= function
    | None -> return `Eof
    | Some t -> return (`Ok t)

  let write t view =
    Pcb.write t view >>= fun () ->
    return (`Ok ())

  let writev t views =
    Pcb.writev t views >>= fun () ->
    return (`Ok ())

  let rec write_nodelay t view =
    Pcb.write_nodelay t view

  let writev_nodelay t views =
    Pcb.writev_nodelay t views

  let close t =
    Pcb.close t

  let create_connection tcp (daddr, dport) =
    Pcb.connect tcp daddr dport >>= function
    | `Timeout ->
      Printf.printf "Failed to connect to %s:%d\n%!" (Ipaddr.V4.to_string daddr) dport;
      return (`Error `Timeout)
    | `Rst ->
      Printf.printf "Refused connection to %s:%d\n%!" (Ipaddr.V4.to_string daddr) dport;
      return (`Error `Refused)
    | `Ok (fl, _) ->
      return (`Ok fl)

  let input t ~listeners ~src ~dst buf =
    Pcb.input t ~listeners ~src ~dst buf

  let connect ipv4 =
    return (`Ok (Pcb.create ipv4))

  let disconnect t =
    return ()
end
