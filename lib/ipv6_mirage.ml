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

module type IP = sig
  type ethif
  type 'a io
  type buffer
  type ipaddr
  type callback = src:ipaddr -> dst:ipaddr -> buffer -> unit io

  type t

  val id : t -> ethif
  val writev : t -> ipaddr -> (buffer -> buffer list) -> unit io
  val input : t -> tcp:callback -> udp:callback -> default:(proto:int -> callback) -> buffer -> unit io
  val connect : ethif -> [> `Ok of t] io
  val get_gateways : t -> ipaddr list
  val get_ips : t -> ipaddr list
end

module type IPV6 = sig
  include IP with type ipaddr = Ipaddr.V6.t
end

let (>>=) = Lwt.(>>=)
let (>|=) = Lwt.(>|=)

module Make (E : V2_LWT.ETHIF) (T : V2_LWT.TIME) (C : V2.CLOCK) = struct
  type ethif    = E.t
  type 'a io    = 'a Lwt.t
  type buffer   = Cstruct.t
  type ipaddr = Ipaddr.V6.t
  type callback = src:ipaddr -> dst:ipaddr -> buffer -> unit Lwt.t

  type t =
    { ethif : E.t;
      mutable state : Ipv6.state;
      mutable nc : Ipv6.nb_info Ipv6.IpMap.t }

  let id { ethif } = ethif

  let rec tick state =
    Printf.printf "Ticking...\n%!";
    run state @@ Ipv6.tick ~st:state.state ~nc:state.nc ~now:(Ipv6.Time.of_float @@ C.time ())

  and run state (st, nc, pkts, timers) =
    state.state <- st;
    state.nc <- nc;
    List.iter (fun dt ->
        let dt = Ipv6.Time.Span.to_float dt in
        Printf.printf "Setting up a timer in %.1fs\n%!" dt;
        Lwt.ignore_result (T.sleep @@ dt >>= fun () -> tick state)) timers;
    Lwt_list.iter_s (E.writev state.ethif) pkts

  let writev state dst datav =
    let now = Ipv6.Time.of_float @@ C.time () in
    let src = Ipv6.select_source_address state.state in
    let nc, pkts, timers = Ipv6.output ~now ~st:state.state ~nc:state.nc ~src ~dst datav in
    run state (state.state, nc, pkts, timers)

  let input state ~tcp ~udp ~default buf =
    let r, pkts_timers =
      Ipv6.handle_packet ~now:(Ipv6.Time.of_float @@ C.time ()) ~st:state.state ~nc:state.nc buf
    in
    run state pkts_timers >>= fun () ->
    match r with
    | `None -> Lwt.return_unit
    | `Tcp (src, dst, pkt) -> tcp ~src ~dst pkt
    | `Udp (src, dst, pkt) -> udp ~src ~dst pkt
    | `Default (proto, src, dst, pkt) -> default ~proto ~src ~dst pkt

  let connect ethif =
    let state = {state = Ipv6.create (E.mac ethif); nc = Ipv6.IpMap.empty; ethif} in
    T.sleep 10.0 >>= fun () ->
    Printf.printf "Starting\n%!";
    run state @@
    Ipv6.add_ip ~now:(Ipv6.Time.of_float @@ C.time ()) ~st:state.state ~nc:state.nc
      (Ipv6.Macaddr.link_local_addr (E.mac ethif)) >>= fun () ->
    Lwt.return (`Ok state)

  let get_gateways state =
    List.map fst state.state.Ipv6.router_list

  let get_ips state =
    let rec loop = function
      | [] -> []
      | (_, Ipv6.TENTATIVE _) :: rest -> loop rest
      | (ip, (Ipv6.PREFERRED _ | Ipv6.DEPRECATED _)) :: rest -> ip :: loop rest
    in
    loop state.state.Ipv6.my_ips
end
