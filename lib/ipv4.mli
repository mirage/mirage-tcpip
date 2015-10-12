(*
 * Copyright (c) 2010 Anil Madhavapeddy <anil@recoil.org>
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

module Make (N:V1_LWT.ETHIF) (A: V1_LWT.ARP) : sig
  module Routing : sig
    (* this exception can be thrown by `write` or `writev` when the destination
       IP address's link-layer address can't be found by ARP *)
    exception No_route_to_destination_address of Ipaddr.V4.t
  end
  include V1_LWT.IPV4 with type ethif = N.t
  val connect :
    ?ip:Ipaddr.V4.t ->
    ?netmask:Ipaddr.V4.t ->
    ?gateways:Ipaddr.V4.t list ->
    ethif -> A.t -> [> `Ok of t | `Error of error ] Lwt.t
    (** Connect to an ipv4 device.
        Default ip is {!Ipaddr.V4.any}
        Default netmask is {!Ipaddr.V4.any}
        Default gateways are [[]]. *)

end
