(*
 * Copyright (c) 2015 Magnus Skjegstad <magnus@skjegstad.com>
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
open Common

module Time = struct
  type 'a io = 'a Lwt.t
  include Lwt_unix
end

module Clock = Unix

module Console = Console_unix

module S = struct
  module B = Basic_backend.Make
  module V = Vnetif.Make(B)
  module E = Ethif.Make(V)
  module I = Ipv4.Make(E)(Clock)(Time)
  module U = Udp.Make(I)
  module T = Tcp.Flow.Make(I)(Time)(Clock)(Random)
  module S = Tcpip_stack_direct.Make(Console)(Time)(Random)(V)(E)(I)(U)(T)
  include S
end

let create_stack c backend ip netmask gw =
  or_error "backend" S.V.connect backend >>= fun netif ->
  (* Printf.printf (Printf.sprintf "Connected to backend with mac %s" (Macaddr.to_string (S.V.mac netif))) *)
  or_error "ethif" S.E.connect netif >>= fun ethif ->
  or_error "ipv4" S.I.connect ethif >>= fun ipv4 ->
  or_error "udpv4" S.U.connect ipv4 >>= fun udpv4 ->
  or_error "tcpv4" S.T.connect ipv4 >>= fun tcpv4 ->
  let config = {
    V1_LWT.name = "stack";
    console = c; 
    interface = netif;
    mode = `IPv4 (ip, netmask, gw);
  } in
  or_error "stack" (S.connect config ethif ipv4 udpv4) tcpv4

