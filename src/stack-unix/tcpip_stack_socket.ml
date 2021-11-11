(*
 * Copyright (c) 2014 Anil Madhavapeddy <anil@recoil.org>
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

let src = Logs.Src.create "tcpip-stack-socket" ~doc:"Platform's native TCP/IP stack"
module Log = (val Logs.src_log src : Logs.LOG)

module V4 = struct
  module TCPV4 = Tcpv4_socket
  module UDPV4 = Udpv4_socket
  module IPV4  = Ipv4_socket

  type t = {
    udpv4 : UDPV4.t;
    tcpv4 : TCPV4.t;
    stop : unit Lwt.u;
    switched_off : unit Lwt.t;
  }

  let udpv4 { udpv4; _ } = udpv4
  let tcpv4 { tcpv4; _ } = tcpv4
  let ipv4 _ = ()

  let listen_udpv4 t ~port callback =
    UDPV4.listen t.udpv4 ~port callback

  let listen_tcpv4 ?keepalive t ~port callback =
    TCPV4.listen t.tcpv4 ~port ?keepalive callback

  let listen t = t.switched_off

  let connect udpv4 tcpv4 =
    Log.info (fun f -> f "IPv4 socket stack: connect");
    let switched_off, stop = Lwt.wait () in
    TCPV4.set_switched_off tcpv4 switched_off;
    UDPV4.set_switched_off udpv4 switched_off;
    Lwt.return { tcpv4; udpv4; stop; switched_off }

  let disconnect t =
    TCPV4.disconnect t.tcpv4 >>= fun () ->
    UDPV4.disconnect t.udpv4 >|= fun () ->
    Lwt.wakeup_later t.stop ()
end

module V6 = struct
  module TCP = Tcpv6_socket
  module UDP = Udpv6_socket
  module IP  = Ipv6_socket

  type t = {
    udp : UDP.t;
    tcp : TCP.t;
    stop : unit Lwt.u;
    switched_off : unit Lwt.t;
  }

  let udp { udp; _ } = udp
  let tcp { tcp; _ } = tcp
  let ip _ = ()

  let listen_udp t ~port callback =
    UDP.listen t.udp ~port callback

  let listen_tcp ?keepalive t ~port callback =
    TCP.listen t.tcp ~port ?keepalive callback

  let listen t = t.switched_off

  let connect udp tcp =
    Log.info (fun f -> f "IPv6 socket stack: connect");
    let switched_off, stop = Lwt.wait () in
    UDP.set_switched_off udp switched_off;
    TCP.set_switched_off tcp switched_off;
    Lwt.return { tcp; udp; stop; switched_off }

  let disconnect t =
    TCP.disconnect t.tcp >>= fun () ->
    UDP.disconnect t.udp >|= fun () ->
    Lwt.wakeup_later t.stop ()
end

module V4V6 = struct
  module TCP = Tcpv4v6_socket
  module UDP = Udpv4v6_socket
  module IP  = Ipv4v6_socket

  type t = {
    udp : UDP.t;
    tcp : TCP.t;
    stop : unit Lwt.u;
    switched_off : unit Lwt.t;
  }

  let udp { udp; _ } = udp
  let tcp { tcp; _ } = tcp
  let ip _ = ()

  let listen_udp t ~port callback =
    UDP.listen t.udp ~port callback

  let listen_tcp ?keepalive t ~port callback =
    TCP.listen t.tcp ~port ?keepalive callback

  let listen t = t.switched_off

  let connect udp tcp =
    Log.info (fun f -> f "Dual IPv4 and IPv6 socket stack: connect");
    let switched_off, stop = Lwt.wait () in
    UDP.set_switched_off udp switched_off;
    TCP.set_switched_off tcp switched_off;
    Lwt.return { tcp; udp; stop; switched_off }

  let disconnect t =
    TCP.disconnect t.tcp >>= fun () ->
    UDP.disconnect t.udp >|= fun () ->
    Lwt.wakeup_later t.stop ()
end
