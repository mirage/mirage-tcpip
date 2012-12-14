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

cstruct tcpv4 {
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t sequence;
  uint32_t ack_number;
  uint8_t  dataoff;
  uint8_t  flags;
  uint16_t window;
  uint16_t checksum;
  uint16_t urg_ptr
} as big_endian

cstruct pseudo_header {
  uint32_t src;
  uint32_t dst;
  uint8_t res;
  uint8_t proto;
  uint16_t len
} as big_endian 

open Cstruct

(* XXX note that we overwrite the lower half of dataoff
 * with 0, so be careful when implemented CWE flag which 
 * sits there *)
let get_data_offset buf = ((get_tcpv4_dataoff buf) lsr 4) * 4
let set_data_offset buf v = set_tcpv4_dataoff buf (v lsl 4)

let get_fin buf = ((get_uint8 buf 13) land (1 lsl 0)) > 0
let get_syn buf = ((get_uint8 buf 13) land (1 lsl 1)) > 0
let get_rst buf = ((get_uint8 buf 13) land (1 lsl 2)) > 0
let get_psh buf = ((get_uint8 buf 13) land (1 lsl 3)) > 0
let get_ack buf = ((get_uint8 buf 13) land (1 lsl 4)) > 0
let get_urg buf = ((get_uint8 buf 13) land (1 lsl 5)) > 0
let get_ece buf = ((get_uint8 buf 13) land (1 lsl 6)) > 0
let get_cwr buf = ((get_uint8 buf 13) land (1 lsl 7)) > 0

let set_fin buf = set_uint8 buf 13 ((get_uint8 buf 13) lor (1 lsl 0))
let set_syn buf = set_uint8 buf 13 ((get_uint8 buf 13) lor (1 lsl 1))
let set_rst buf = set_uint8 buf 13 ((get_uint8 buf 13) lor (1 lsl 2))
let set_psh buf = set_uint8 buf 13 ((get_uint8 buf 13) lor (1 lsl 3))
let set_ack buf = set_uint8 buf 13 ((get_uint8 buf 13) lor (1 lsl 4))
let set_urg buf = set_uint8 buf 13 ((get_uint8 buf 13) lor (1 lsl 5))
let set_ece buf = set_uint8 buf 13 ((get_uint8 buf 13) lor (1 lsl 6))
let set_cwr buf = set_uint8 buf 13 ((get_uint8 buf 13) lor (1 lsl 7))

let get_options buf =
  if get_data_offset buf > 20 then
    Options.unmarshal (shift buf sizeof_tcpv4) else []

let set_options buf ts =
  Options.marshal buf ts

let get_payload buf =
  Cstruct.shift buf (get_data_offset buf)

open Lwt
open Nettypes
open Printf

type id = {
  dest_port: int;               (* Remote TCP port *)
  dest_ip: ipv4_addr;           (* Remote IP address *)
  local_port: int;              (* Local TCP port *)
  local_ip: ipv4_addr;          (* Local IP address *)
}

let checksum ~src ~dst =
  let pbuf = Cstruct.sub (Cstruct.of_bigarray (OS.Io_page.get ())) 0 sizeof_pseudo_header in
  fun data ->
    set_pseudo_header_src pbuf (ipv4_addr_to_uint32 src);
    set_pseudo_header_dst pbuf (ipv4_addr_to_uint32 dst);
    set_pseudo_header_res pbuf 0;
    set_pseudo_header_proto pbuf 6;
    set_pseudo_header_len pbuf (Cstruct.lenv data);
    Checksum.ones_complement_list (pbuf::data)

(* Output a general TCP packet, checksum it, and if a reference is provided,
   also record the sent packet for retranmission purposes *)
let xmit ~ip ~id ?(rst=false) ?(syn=false) ?(fin=false) ?(psh=false) ~rx_ack ~seq ~window ~options datav =
  let sequence = Sequence.to_int32 seq in
  let ack_number = match rx_ack with Some n -> Sequence.to_int32 n |None -> 0l in
  lwt ipv4_frame = Ipv4.get_frame  ~proto:`TCP ~dest_ip:id.dest_ip ip in
  let ipv4_payload = Frame.get_payload ipv4_frame in
  let options_len =
    match options with
    |[] -> 0
    |options -> Options.marshal (Cstruct.shift ipv4_payload sizeof_tcpv4) options
  in
  let data_off = (sizeof_tcpv4 / 4) + (options_len / 4) in
  set_tcpv4_src_port ipv4_payload id.local_port;
  set_tcpv4_dst_port ipv4_payload id.dest_port;
  set_tcpv4_sequence ipv4_payload sequence;
  set_tcpv4_ack_number ipv4_payload ack_number;
  set_data_offset ipv4_payload data_off;
  set_tcpv4_flags ipv4_payload 0;
  if rx_ack <> None then set_ack ipv4_payload;
  if rst then set_rst ipv4_payload;
  if syn then set_syn ipv4_payload;
  if fin then set_fin ipv4_payload;
  if psh then set_psh ipv4_payload;
  set_tcpv4_window ipv4_payload window;
  set_tcpv4_checksum ipv4_payload 0;
  set_tcpv4_urg_ptr ipv4_payload 0;
  Frame.set_payload_len ipv4_frame (sizeof_tcpv4 + options_len);
  let header = Frame.get_payload ipv4_frame in
  let checksum = checksum ~src:id.local_ip ~dst:id.dest_ip (header::datav) in
  set_tcpv4_checksum ipv4_payload checksum;
  (*
  printf "TCP.xmit checksum %04x %s.%d->%s.%d rst %b syn %b fin %b psh %b seq %lu ack %lu %s datalen %d datafrag %d dataoff %d olen %d\n%!"
    checksum
    (ipv4_addr_to_string id.local_ip) id.local_port (ipv4_addr_to_string id.dest_ip) id.dest_port
    rst syn fin psh sequence ack_number (Options.prettyprint options) 
    (Cstruct.lenv datav) (List.length datav) data_off options_len;
  *)
  match datav with
  |[] -> Ipv4.write ip ipv4_frame
  |_ -> Ipv4.writev ip ipv4_frame datav
