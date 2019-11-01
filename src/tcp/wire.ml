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

module Make (Ip:Mirage_protocols.IP) = struct

  type error = Mirage_protocols.Ip.error

  let pp_error = Mirage_protocols.Ip.pp_error

  type t = {
    dst_port: int;             (* Remote TCP port *)
    dst: Ip.ipaddr;            (* Remote IP address *)
    src_port: int;             (* Local TCP port *)
    src: Ip.ipaddr;            (* Local IP address *)
  }

  let v ~src ~src_port ~dst ~dst_port = { dst_port ; dst ; src_port ; src }

  let src t = t.src
  let dst t = t.dst
  let src_port t = t.src_port
  let dst_port t = t.dst_port

  let pp ppf t =
    Fmt.pf ppf "remote %a,%d to local %a, %d"
      Ip.pp_ipaddr t.dst t.dst_port Ip.pp_ipaddr t.src t.src_port

  let xmit ~ip { src_port; dst_port; dst; _ } ?(rst=false) ?(syn=false)
      ?(fin=false) ?(psh=false)
      ~rx_ack ~seq ~window ~options payload
    =
    let (ack, ack_number) = match rx_ack with
      | None -> (false, Sequence.zero)
      | Some n -> (true, n)
    in
    let header = {
        sequence = seq; Tcp_packet.ack_number; window;
        urg = false; ack; psh; rst; syn; fin;
        options;
        src_port; dst_port;
      }
    in
    (* Make a TCP/IP header frame *)
    let tcp_size = Tcp_wire.sizeof_tcp + Options.lenv options + Cstruct.len payload in
    let fill_buffer buf =
      let pseudoheader = Ip.pseudoheader ip dst `TCP tcp_size in
      match Tcp_packet.Marshal.into_cstruct header buf ~pseudoheader ~payload with
      | Error s ->
        Log.err (fun l -> l "Error writing TCP packet header: %s" s) ;
        0
        (* TODO: better to avoid this entirely, now we're sending empty IP
             frame and drop the payload.. oops *)
      | Ok l ->
        Cstruct.blit payload 0 buf l (Cstruct.len payload) ;
        MProf.Counter.increase count_tcp_to_ip
          (Cstruct.len payload + if syn then 1 else 0) ;
        tcp_size
    in
    Ip.write ip ~fragment:false dst `TCP ~size:tcp_size fill_buffer [] >|= function
    | Ok () -> Ok ()
    (* swallow errors so normal recovery mechanisms can be used *)
    (* For errors which aren't transient, or are too long-lived for TCP to recover
     * from, this will eventually result in a higher-level notification
     * that communication over the TCP flow has failed *)
    | Error e ->
      Log.warn (fun l -> l "Error sending TCP packet via IP: %a" Ip.pp_error e);
      Ok ()
end
