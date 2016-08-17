(*
 * Copyright (c) 2014 Nicolas Ojeda Bar <n.oje.bar@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS l SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)


let src = Logs.Src.create "ipv6" ~doc:"Mirage IPv6"
module Log = (val Logs.src_log src : Logs.LOG)
module I = Ipaddr

open Lwt.Infix

module Make (E : V1_LWT.ETHIF) (T : V1_LWT.TIME) (C : V1.MCLOCK) = struct
  type ethif    = E.t
  type 'a io    = 'a Lwt.t
  type buffer   = Cstruct.t
  type ipaddr   = Ipaddr.V6.t
  type callback = src:ipaddr -> dst:ipaddr -> buffer -> unit Lwt.t
  type prefix   = Ipaddr.V6.Prefix.t

  type t =
    { ethif : E.t;
      clock : C.t;
      mutable ctx : Ndpv6.context }

  type error =
    [ `Unimplemented
    | `Unknown of string ]

  let start_ticking t =
    let rec loop () =
      let now = C.elapsed_ns t.clock in
      let ctx, bufs = Ndpv6.tick ~now t.ctx in
      t.ctx <- ctx;
      Lwt_list.iter_s (E.writev t.ethif) bufs >>= fun () ->
      T.sleep_ns (Duration.of_sec 1) >>= loop
    in
    loop ()

  let allocate_frame t ~dst ~proto =
    Ndpv6.allocate_frame t.ctx dst proto

  let writev t frame bufs =
    let now = C.elapsed_ns t.clock in
    let dst =
      Ndpv6.ipaddr_of_cstruct
        (Ipv6_wire.get_ipv6_dst (Cstruct.shift frame Ethif_wire.sizeof_ethernet))
    in
    let ctx, bufs = Ndpv6.send ~now t.ctx dst frame bufs in
    t.ctx <- ctx;
    Lwt_list.iter_s (E.writev t.ethif) bufs

  let write t frame buf =
    writev t frame [buf]

  let input t ~tcp ~udp ~default buf =
    let now = C.elapsed_ns t.clock in
    let _, bufs, actions = Ndpv6.handle ~now t.ctx buf in
    Lwt_list.iter_s (function
        | `Tcp (src, dst, buf) -> tcp ~src ~dst buf
        | `Udp (src, dst, buf) -> udp ~src ~dst buf
        | `Default (proto, src, dst, buf) -> default ~proto ~src ~dst buf
      ) actions >>= fun () ->
    Lwt_list.iter_s (E.writev t.ethif) bufs

  let disconnect _ = (* TODO *)
    Lwt.return_unit

  let checksum = Ndpv6.checksum

  let src t ~dst = Ndpv6.select_source t.ctx dst

  let set_ip t ip =
    let now = C.elapsed_ns t.clock in
    let ctx, bufs = Ndpv6.add_ip ~now t.ctx ip in
    t.ctx <- ctx;
    Lwt_list.iter_s (E.writev t.ethif) bufs

  let get_ip t =
    Ndpv6.get_ip t.ctx

  let set_ip_gateways t ips =
    let now = C.elapsed_ns t.clock in
    let ctx = Ndpv6.add_routers ~now t.ctx ips in
    t.ctx <- ctx;
    Lwt.return_unit

  let get_ip_gateways t =
    Ndpv6.get_routers t.ctx

  let get_ip_netmasks t =
    Ndpv6.get_prefix t.ctx

  let set_ip_netmask t pfx =
    let now = C.elapsed_ns t.clock in
    let ctx = Ndpv6.add_prefix ~now t.ctx pfx in
    t.ctx <- ctx;
    Lwt.return_unit

  let pseudoheader t ~dst ~proto len =
    let ph = Cstruct.create (16 + 16 + 8) in
    let src = src t ~dst in
    Ndpv6.ipaddr_to_cstruct_raw src ph 0;
    Ndpv6.ipaddr_to_cstruct_raw dst ph 16;
    Cstruct.BE.set_uint32 ph 32 (Int32.of_int len);
    Cstruct.set_uint8 ph 36 0;
    Cstruct.set_uint8 ph 37 0;
    Cstruct.set_uint8 ph 38 0;
    Cstruct.set_uint8 ph 39 (match proto with | `UDP -> 17 | `TCP -> 6);
    ph

  type uipaddr = I.t
  let to_uipaddr ip = I.V6 ip
  let of_uipaddr ip = Some (I.to_v6 ip)

  let (>>=?) (x,f) g = match x with
    | Some x -> f x >>= g
    | None -> g ()

  let connect ?ip ?netmask ?gateways ethif clock =
    Log.info (fun f -> f "IP6: Starting");
    let now = C.elapsed_ns clock in
    let ctx, bufs = Ndpv6.local ~now (E.mac ethif) in
    let t = {ctx; clock; ethif} in
    Lwt_list.iter_s (E.writev t.ethif) bufs >>= fun () ->
    (ip, set_ip t) >>=? fun () ->
    (netmask, Lwt_list.iter_s (set_ip_netmask t)) >>=? fun () ->
    (gateways, set_ip_gateways t) >>=? fun () ->
    Lwt.async (fun () -> start_ticking t);
    Lwt.return (`Ok t)

end
