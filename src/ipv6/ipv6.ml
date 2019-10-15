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

module Make (E : Mirage_protocols.ETHERNET)
            (R : Mirage_random.S)
            (T : Mirage_time.S)
            (C : Mirage_clock.MCLOCK) = struct
  type ipaddr   = Ipaddr.V6.t
  type callback = src:ipaddr -> dst:ipaddr -> Cstruct.t -> unit Lwt.t

  let pp_ipaddr = Ipaddr.V6.pp

  type t =
    { ethif : E.t;
      mutable ctx : Ndpv6.context }

  type error = [ Mirage_protocols.Ip.error | `Ethif of E.error ]

  let pp_error ppf = function
    | #Mirage_protocols.Ip.error as e -> Mirage_protocols.Ip.pp_error ppf e
    | `Ethif e -> E.pp_error ppf e

  let output t (dst, size, fill) =
    E.write t.ethif dst `IPv6 ~size fill

  let output_ign t a = output t a >|= fun _ -> ()

  let start_ticking t =
    let rec loop () =
      let now = C.elapsed_ns () in
      let ctx, outs = Ndpv6.tick ~now t.ctx in
      t.ctx <- ctx;
      Lwt_list.iter_s (output_ign t) outs (* MCP: replace with propagation *) >>= fun () ->
      T.sleep_ns (Duration.of_sec 1) >>= loop
    in
    loop ()

  let mtu t = E.mtu t.ethif - Ipv6_wire.sizeof_ipv6

  let write t ?fragment:_ ?ttl:_ ?src:_ dst proto ?(size = 0) headerf bufs =
    let now = C.elapsed_ns () in
    (* TODO fragmentation! *)
    let payload = Cstruct.concat bufs in
    let size' = size + Cstruct.len payload in
    let fillf _ip6hdr buf =
      let h_len = headerf buf in
      if h_len > size then begin
        Log.err (fun m -> m "provided headerf exceeds size") ;
        invalid_arg "headerf exceeds size"
      end ;
      Cstruct.blit payload 0 buf h_len (Cstruct.len payload);
      h_len + Cstruct.len payload
    in
    let ctx, outs = Ndpv6.send ~now t.ctx dst proto size' fillf in
    t.ctx <- ctx;
    let fail_any progress data =
      let squeal = function
      | Ok () as ok -> Lwt.return ok
      | Error e ->
        Log.warn (fun f -> f "ethif write errored: %a" E.pp_error e);
        Lwt.return @@ Error (`Ethif e)
      in
      match progress with
      | Ok () -> output t data >>= squeal
      | Error e -> Lwt.return @@ Error e
    in
    (* MCP - it's not totally clear to me that this the right behavior
       for writev. *)
    Lwt_list.fold_left_s fail_any (Ok ()) outs

  let input t ~tcp ~udp ~default buf =
    let now = C.elapsed_ns () in
    let _, outs, actions = Ndpv6.handle ~now ~random:R.generate t.ctx buf in
    Lwt_list.iter_s (function
        | `Tcp (src, dst, buf) -> tcp ~src ~dst buf
        | `Udp (src, dst, buf) -> udp ~src ~dst buf
        | `Default (proto, src, dst, buf) -> default ~proto ~src ~dst buf
      ) actions >>= fun () ->
    (* MCP: replace below w/proper error propagation *)
    Lwt_list.iter_s (output_ign t) outs

  let disconnect _ = (* TODO *)
    Lwt.return_unit

  let src t ~dst = Ndpv6.select_source t.ctx dst

  let set_ip t ip =
    let now = C.elapsed_ns () in
    let ctx, outs = Ndpv6.add_ip ~now t.ctx ip in
    t.ctx <- ctx;
    (* MCP: replace the below *)
    Lwt_list.iter_s (output_ign t) outs

  let get_ip t =
    Ndpv6.get_ip t.ctx

  let set_ip_gateways t ips =
    let now = C.elapsed_ns () in
    let ctx = Ndpv6.add_routers ~now t.ctx ips in
    t.ctx <- ctx;
    Lwt.return_unit

  let set_ip_netmask t pfx =
    let now = C.elapsed_ns () in
    let ctx = Ndpv6.add_prefix ~now t.ctx pfx in
    t.ctx <- ctx;
    Lwt.return_unit

  let pseudoheader t ?src:source dst proto len =
    let ph = Cstruct.create (16 + 16 + 8) in
    let src = match source with None -> src t ~dst | Some x -> x in
    Ndpv6.ipaddr_to_cstruct_raw src ph 0;
    Ndpv6.ipaddr_to_cstruct_raw dst ph 16;
    Cstruct.BE.set_uint32 ph 32 (Int32.of_int len);
    Cstruct.set_uint8 ph 36 0;
    Cstruct.set_uint8 ph 37 0;
    Cstruct.set_uint8 ph 38 0;
    Cstruct.set_uint8 ph 39 (Ipv6_wire.protocol_to_int proto);
    ph

  let (>>=?) (x,f) g = match x with
    | Some x -> f x >>= g
    | None -> g ()

  let connect ?ip ?netmask ?gateways ethif =
    Log.info (fun f -> f "IP6: Starting");
    let now = C.elapsed_ns () in
    let ctx, outs = Ndpv6.local ~now ~random:R.generate (E.mac ethif) in
    let t = {ctx; ethif} in
    (* MCP: replace this error swallowing with proper propagation *)
    Lwt_list.iter_s (output_ign t) outs >>= fun () ->
    (ip, Lwt_list.iter_s (set_ip t)) >>=? fun () ->
    (netmask, Lwt_list.iter_s (set_ip_netmask t)) >>=? fun () ->
    (gateways, set_ip_gateways t) >>=? fun () ->
    Lwt.async (fun () -> start_ticking t);
    Lwt.return t

end
