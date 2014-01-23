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

module Make(IP:V1_LWT.IPV4)(TM:T.LWT_TIME)(C:T.CLOCK)(R:T.RANDOM) = struct

  module Pcb = Pcb.Make(IP)(TM)(C)(R)

  type flow = Pcb.pcb
  type id = IP.t
  type t = Pcb.t
  type buffer = Cstruct.t
  type +'a io = 'a Lwt.t
  type error = [
   | `Unknown_error of string
  ]

  let read t =
    (* TODO better error interface in Pcb *)
    Pcb.read t
    >>= function
    | None -> return `Eof
    | Some t -> return (`Ok t)

  let write t view =
    Pcb.write t view

  let writev t views =
    Pcb.writev t views

  let rec write_nodelay t view =
    Pcb.write_nodelay t view

  let writev_nodelay t views =
    Pcb.writev_nodelay t views

  let close t =
    Pcb.close t

  let listen tcp port fn =
    let (st, l) = Pcb.listen tcp port in
    let rec accept () =
      Lwt_stream.get st
      >>= function
      | None -> return_unit
      | Some (fl, th) -> begin
          let _ = fn (Pcb.get_dest fl) fl  in
          accept ()
        end
    in
    (* TODO cancellation *)
    accept ()

  let create_connection tcp (daddr, dport) fn =
    Pcb.connect tcp daddr dport
    >>= function
    | None -> 
      Printf.printf "Failed to connect to %s:%d\n%!"
        (Ipaddr.V4.to_string daddr) dport;
      return_unit
    | Some (fl, _) ->
      fn fl 

  let connect ipv4 =
    return (`Ok (Pcb.create ipv4))

  let disconnect t =
    return ()
end
