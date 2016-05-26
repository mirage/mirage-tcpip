(*
 * Copyright (c) 2012 Anil Madhavapeddy <anil@recoil.org>
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

let src = Logs.Src.create "Wire" ~doc:"Mirage TCP Wire module"
module Log = (val Logs.src_log src : Logs.LOG)

let count_tcp_to_ip = MProf.Counter.make ~name:"tcp-to-ip"

let set_options buf ts =
  Options.marshal buf ts

module Make (Ip:V1_LWT.IP) = struct
  type id = {
    dest_port: int;             (* Remote TCP port *)
    dest_ip: Ip.ipaddr;         (* Remote IP address *)
    local_port: int;            (* Local TCP port *)
    local_ip: Ip.ipaddr;        (* Local IP address *)
  }

  let wire ~local_ip ~local_port ~dest_ip ~dest_port =
    { dest_port ; dest_ip; local_port ; local_ip }

  let local_port_of_id id = id.local_port

  let dest_of_id id = (id.dest_ip, id.dest_port)

  let pp_id fmt id =
    let uip = Ip.to_uipaddr in
    Format.fprintf fmt "remote %a,%d to local %a, %d"
      Ipaddr.pp_hum (uip id.dest_ip) id.dest_port Ipaddr.pp_hum (uip id.local_ip) id.local_port

  let xmit ~ip ~id ?(rst=false) ?(syn=false) ?(fin=false) ?(psh=false)
      ~rx_ack ~seq ~window ~options payload =
    (* Make a TCP/IP header frame *)
    let frame, header_len = Ip.allocate_frame ip ~dst:id.dest_ip ~proto:`TCP in
    (* Shift this out by the combined ethernet + IP header sizes *)
    let tcp_buf = Cstruct.shift frame header_len in
    let pseudoheader = Ip.pseudoheader ip ~dst:id.dest_ip ~proto:`TCP (Cstruct.lenv payload) in
    match Tcp_marshal.to_cstruct ~buf:tcp_buf ~src_port:id.local_port
      ~dst_port:id.dest_port ~seq ~rx_ack ~pseudoheader ~options ~syn ~rst ~fin
      ~psh ~window ~payload with
    | Result.Error s ->
      Log.info (fun fmt -> fmt "Error transmitting TCP packet: %s" s);
      Lwt.return_unit
    | Result.Ok len ->
      let frame = Cstruct.set_len frame (header_len + len) in
      MProf.Counter.increase count_tcp_to_ip (Cstruct.lenv payload + (if syn then 1 else 0));
      Ip.writev ip frame payload

end
