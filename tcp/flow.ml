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

module type S =
  functor (IP:V1_LWT.IP) ->
  functor (TM:V1_LWT.TIME) ->
  functor (C:V1.CLOCK) ->
  functor (R:V1.RANDOM) ->
  sig
    include V1_LWT.TCP
      with type ip = IP.t
       and type ipaddr = IP.ipaddr
       and type ipinput = src:IP.ipaddr -> dst:IP.ipaddr -> Cstruct.t -> unit Lwt.t
    val connect : ip -> [> `Ok of t | `Error of error ] Lwt.t
    val watch: log:(string -> unit Lwt.t) -> t -> listeners:(int -> callback option) ->  unit Lwt.t
  end

module Make_ext
    (KV: KV.S)(IP:V1_LWT.IP)(TM:V1_LWT.TIME)(C:V1.CLOCK)(R:V1.RANDOM) =
struct

  module Pcb = Pcb.Make(KV)(IP)(TM)(C)(R)

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

  let error_message = function
    | `Unknown msg -> msg
    | `Timeout -> "Timeout while attempting to connect"
    | `Refused -> "Connection refused"

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

  let write_nodelay t view =
    Pcb.write_nodelay t view

  let writev_nodelay t views =
    Pcb.writev_nodelay t views

  let close t =
    Pcb.close t

  let create_connection tcp (daddr, dport) =
    Pcb.connect tcp ~dest_ip:daddr ~dest_port:dport >>= function
    | `Timeout ->
      (* Printf.printf "Failed to connect to %s:%d\n%!" *)
        (* (Ipaddr.V4.to_string daddr) dport; *)
      return (`Error `Timeout)
    | `Rst ->
      (* Printf.printf "Refused connection to %s:%d\n%!" *)
        (* (Ipaddr.V4.to_string daddr) dport; *)
      return (`Error `Refused)
    | `Ok (fl, _) ->
      return (`Ok fl)

  let input t ~listeners ~src ~dst buf =
    let t = Pcb.with_listeners listeners t in
    Pcb.input t ~src ~dst buf

  let connect ipv4 = Pcb.create ipv4 >|= fun t -> `Ok t

  let disconnect _ =
    return_unit

  let watch ~log t ~listeners =
    let t = Pcb.with_listeners listeners t in
    Pcb.watch ~log t

end

module Make = Make_ext(KV.Global)
