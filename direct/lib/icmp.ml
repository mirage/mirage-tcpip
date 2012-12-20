(*
 * Copyright (c) 2010-2011 Anil Madhavapeddy <anil@recoil.org>
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
open Printf
open Nettypes

cstruct icmpv4 {
  uint8_t ty;
  uint8_t code;
  uint16_t csum;
  uint16_t id;
  uint16_t seq
} as big_endian

type t = {
  ip: Ipv4.t;
}

let input t src hdr buf =
  match get_icmpv4_ty buf with
  |0 -> (* echo reply *)
    return (printf "ICMP: discarding echo reply\n%!")
  |8 -> (* echo request *)
    (* convert the echo request into an echo reply *)
    let csum =
      let orig_csum = get_icmpv4_csum buf in
      let shift = if orig_csum > 0xffff -0x0800 then 0x0801 else 0x0800 in
      (orig_csum + shift) land 0xffff in
    set_icmpv4_ty buf 0;
    set_icmpv4_csum buf csum;
    (* stick an IPv4 header on the front and transmit *)
    lwt ipv4_frame = Ipv4.get_frame ~proto:`ICMP ~dest_ip:src t.ip in
    Frame.set_payload_len ipv4_frame 0;
    Ipv4.writev t.ip ipv4_frame [buf]
  |ty ->
    printf "ICMP unknown ty %d\n" ty; 
    return ()

let create ip =
  let t = { ip } in
  Ipv4.attach ip (`ICMP (input t));
  let th,_ = Lwt.task () in
  Lwt.on_cancel th (fun () ->
    printf "ICMP: shutting down\n%!";
    Ipv4.detach ip `ICMP;
  );
  t, th
