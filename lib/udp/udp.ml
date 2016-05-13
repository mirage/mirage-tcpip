(*
 * Copyright (c) 2010-2014 Anil Madhavapeddy <anil@recoil.org>
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
open Result

let src = Logs.Src.create "udp" ~doc:"Mirage UDP"
module Log = (val Logs.src_log src : Logs.LOG)

let pp_ips = Format.pp_print_list Ipaddr.pp_hum

module Make(Ip: V1_LWT.IP) = struct

  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t
  type ip = Ip.t
  type ipaddr = Ip.ipaddr
  type ipinput = src:ipaddr -> dst:ipaddr -> buffer -> unit io
  type callback = src:ipaddr -> dst:ipaddr -> src_port:int -> Cstruct.t -> unit Lwt.t

  (** IO operation errors *)
  type error = [
    | `Unknown of string (** an undiagnosed error *)
  ]

  type t = {
    ip : Ip.t;
  }

  let id {ip} = ip

  let input ~listeners t ~src ~dst buf =
    let open Udp_parse in
    match parse_udp_header buf with
    | Error s ->
      Log.debug (fun f -> f "Discarding received UDP message: error parsing: %s" s); Lwt.return_unit
    | Ok { src_port; dst_port; payload } -> 
      match listeners ~dst_port with
      | None    -> Lwt.return_unit
      | Some fn ->
        fn ~src ~dst ~src_port payload

  let writev ?source_port ~dest_ip ~dest_port t bufs =
    begin match source_port with
      | None   -> Lwt.fail (Failure "TODO; random source port")
      | Some p -> Lwt.return p
    end >>= fun source_port ->
    let frame, header_len = Ip.allocate_frame t.ip ~dst:dest_ip ~proto:`UDP in
    let frame = Cstruct.set_len frame (header_len + Udp_wire.sizeof_udp) in
    let udp_buf = Cstruct.shift frame header_len in
    let ph = Ip.pseudoheader t.ip ~dst:dest_ip ~proto:`UDP (Cstruct.lenv bufs) in
    match Udp_print.print_udp_header ~udp_buf ~src_port:source_port
            ~dst_port:dest_port ~pseudoheader:ph ~payload:bufs with
    | Ok () -> 
      Ip.writev t.ip frame bufs
    | Error s -> Log.debug (fun f -> f "Discarding transmitted UDP message: error writing: %s" s);
      Lwt.return_unit

  let write ?source_port ~dest_ip ~dest_port t buf =
    writev ?source_port ~dest_ip ~dest_port t [buf]

  let connect ip =
    let ips = List.map Ip.to_uipaddr @@ Ip.get_ip ip in
    Log.info (fun f -> f "UDP interface disconnected on %a" pp_ips ips);
    Lwt.return (`Ok { ip })

  let disconnect t =
    let ips = List.map Ip.to_uipaddr @@ Ip.get_ip t.ip in
    Log.info (fun f -> f "UDP interface disconnected on %a" pp_ips ips);
    Lwt.return_unit

end
