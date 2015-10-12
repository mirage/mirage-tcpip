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

let debug = Log.create "Wire"

module Tcp_wire = Wire_structs.Tcp_wire

let count_tcp_to_ip = MProf.Counter.make ~name:"tcp-to-ip"

let get_options buf =
  if Tcp_wire.get_data_offset buf > 20 then
    Options.unmarshal (Cstruct.shift buf Tcp_wire.sizeof_tcp) else []

let set_options buf ts =
  Options.marshal buf ts

let get_payload buf =
  Cstruct.shift buf (Tcp_wire.get_data_offset buf)

module Make (Ip:V1_LWT.IP) = struct
  type id = {
    dest_port: int;               (* Remote TCP port *)
    dest_ip: Ip.ipaddr;         (* Remote IP address *)
    local_port: int;              (* Local TCP port *)
    local_ip: Ip.ipaddr;        (* Local IP address *)
  }

  let xmit ~ip ~id ?(rst=false) ?(syn=false) ?(fin=false) ?(psh=false)
      ~rx_ack ~seq ~window ~options datav =
    (* Make a TCP/IP header frame *)
    let frame, header_len = Ip.allocate_frame ip ~dst:id.dest_ip ~proto:`TCP in
    (* Shift this out by the combined ethernet + IP header sizes *)
    let tcp_frame = Cstruct.shift frame header_len in
    (* Append the TCP options to the header *)
    let options_frame = Cstruct.shift tcp_frame Tcp_wire.sizeof_tcp in
    let options_len =
      match options with
      |[] -> 0
      |options -> Options.marshal options_frame options
    in
    let tcp_frame = Cstruct.set_len tcp_frame (Tcp_wire.sizeof_tcp + options_len) in
    (* At this point, extend the IPv4 view by the TCP+options size *)
    let frame = Cstruct.set_len frame (header_len + Tcp_wire.sizeof_tcp + options_len) in
    let sequence = Sequence.to_int32 seq in
    let ack_number =
      match rx_ack with Some n -> Sequence.to_int32 n |None -> 0l
    in
    let data_off = (Tcp_wire.sizeof_tcp / 4) + (options_len / 4) in
    Tcp_wire.set_tcp_src_port tcp_frame id.local_port;
    Tcp_wire.set_tcp_dst_port tcp_frame id.dest_port;
    Tcp_wire.set_tcp_sequence tcp_frame sequence;
    Tcp_wire.set_tcp_ack_number tcp_frame ack_number;
    Tcp_wire.set_data_offset tcp_frame data_off;
    Tcp_wire.set_tcp_flags tcp_frame 0;
    if rx_ack <> None then Tcp_wire.set_ack tcp_frame;
    if rst then Tcp_wire.set_rst tcp_frame;
    if syn then Tcp_wire.set_syn tcp_frame;
    if fin then Tcp_wire.set_fin tcp_frame;
    if psh then Tcp_wire.set_psh tcp_frame;
    Tcp_wire.set_tcp_window tcp_frame window;
    Tcp_wire.set_tcp_checksum tcp_frame 0;
    Tcp_wire.set_tcp_urg_ptr tcp_frame 0;
    let checksum = Ip.checksum frame (tcp_frame :: datav) in
    Tcp_wire.set_tcp_checksum tcp_frame checksum;
    (* PERF: uncommenting the next expression results in ~10% perf degradation
    Log.f debug (fun fmt ->
        Log.pf fmt
          "xmit checksum=%04x %a.%d->%a.%d rst=%b syn=%b fin=%b psh=%b \
           seq=%lu ack=%lu options=%a datalen=%d datafrag=%d dataoff=%d olen=%d"
          checksum
          Ipaddr.pp_hum (Ip.to_uipaddr id.local_ip) id.local_port
          Ipaddr.pp_hum (Ip.to_uipaddr id.dest_ip)  id.dest_port
          rst syn fin psh sequence ack_number Options.pps options
          (Cstruct.lenv datav) (List.length datav) data_off options_len); *)
    MProf.Counter.increase count_tcp_to_ip (Cstruct.lenv datav + (if syn then 1 else 0));
    Ip.writev ip frame datav

end
