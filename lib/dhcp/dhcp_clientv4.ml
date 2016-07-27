(*
 * Copyright (c) 2006-2011 Anil Madhavapeddy <anil@recoil.org>
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
 *
 *)

let src = Logs.Src.create "dhcp-clientv4" ~doc:"Mirage TCPIP's IPv4 DHCP client"
module Log = (val Logs.src_log src : Logs.LOG)

open Lwt.Infix

module Make
    (Time : V1_LWT.TIME)
    (Random : V1.RANDOM)
    (Udp : V1_LWT.UDPV4) = struct

  type offer = {
    ip_addr: Ipaddr.V4.t;
    netmask: Ipaddr.V4.t option;
    gateways: Ipaddr.V4.t list;
    dns: Ipaddr.V4.t list;
    lease: int32;
    xid: int32;
  }

  type state =
    | Disabled
    | Request_sent of int32
    | Offer_accepted of offer
    | Lease_held of offer
    | Shutting_down

  type t = {
    udp: Udp.t;
    mac: Macaddr.t;
    mutable state: state;
    new_offer: offer -> unit Lwt.t;
  }

  [%%cstruct
  type dhcp = {
      op: uint8_t;
      htype:  uint8_t;
      hlen:   uint8_t;
      hops:   uint8_t;
      xid:    uint32_t;
      secs:   uint16_t;
      flags:  uint16_t;
      ciaddr: uint32_t;
      yiaddr: uint32_t;
      siaddr: uint32_t;
      giaddr: uint32_t;
      chaddr: uint8_t [@len 16];
      sname:  uint8_t [@len 64];
      file:   uint8_t [@len 128];
      cookie: uint32_t;
    } [@@big_endian]
  ]
  [%%cenum
  type mode =
    | BootRequest [@id 1]
    | BootReply
    [@@uint8_t]
  ]

  (* Send a client broadcast packet *)
  let output_broadcast t ~xid ~yiaddr ~siaddr ~options =
    let options = Dhcpv4_option.Packet.to_bytes options in
    let options_len = Bytes.length options in
    let total_len = options_len + sizeof_dhcp in
    let buf = Cstruct.create total_len in
    Cstruct.memset buf 0x00;
    set_dhcp_op buf (mode_to_int BootRequest);
    set_dhcp_htype buf 1;
    set_dhcp_hlen buf 6;
    set_dhcp_xid buf xid;
    set_dhcp_secs buf 10; (* TODO dynamic timer *)
    set_dhcp_yiaddr buf (Ipaddr.V4.to_int32 yiaddr);
    set_dhcp_siaddr buf (Ipaddr.V4.to_int32 siaddr);
    let macaddr = Macaddr.to_bytes t.mac in
    set_dhcp_chaddr (macaddr ^ (Bytes.make 10 '\000')) 0 buf;
    (* fields intentionally left blank: hops, flags, ciaddr, giaddr, sname, file *)
    set_dhcp_cookie buf 0x63825363l;
    Cstruct.blit_from_string options 0 buf sizeof_dhcp options_len;
    let buf = Cstruct.set_len buf (sizeof_dhcp + options_len) in
    Log.info (fun f -> f "Sending DHCP broadcast (length %d)" total_len);
    Udp.write ~dst:Ipaddr.V4.broadcast ~src_port:68 ~dst_port:67 t.udp buf

  (* Receive a DHCP UDP packet *)
  let input t ~src:_ ~dst:_ ~src_port:_ buf =
    let ciaddr = Ipaddr.V4.of_int32 (get_dhcp_ciaddr buf) in
    let yiaddr = Ipaddr.V4.of_int32 (get_dhcp_yiaddr buf) in
    let siaddr = Ipaddr.V4.of_int32 (get_dhcp_siaddr buf) in
    let giaddr = Ipaddr.V4.of_int32 (get_dhcp_giaddr buf) in
    let xid = get_dhcp_xid buf in
    let of_byte x =
      Printf.sprintf "%02x" (Char.code x) in
    let chaddr_to_string x =
      let chaddr_size = (Bytes.length x) in
      let dst_buffer = (Bytes.make (chaddr_size * 2) '\000') in
      for i = 0 to (chaddr_size - 1) do
        let thischar = of_byte x.[i] in
        Bytes.set dst_buffer (i*2) (Bytes.get thischar 0);
        Bytes.set dst_buffer ((i*2)+1) (Bytes.get thischar 1)
      done;
      dst_buffer
    in
    let chaddr = (chaddr_to_string) (copy_dhcp_chaddr buf) in
    let options = Cstruct.(copy buf sizeof_dhcp (len buf - sizeof_dhcp)) in
    let packet = Dhcpv4_option.Packet.of_bytes options in
    (* For debugging, print out the DHCP response *)
    Log.info (fun f -> f 
      "@[<v 2>DHCP response:@ \
        input ciaddr %a yiaddr %a@ \
        siaddr %a giaddr %a@ \
        chaddr %s sname %s file %s@]"
      Ipaddr.V4.pp_hum ciaddr Ipaddr.V4.pp_hum yiaddr
      Ipaddr.V4.pp_hum siaddr Ipaddr.V4.pp_hum giaddr
      chaddr (copy_dhcp_sname buf) (copy_dhcp_file buf)
    );
    (* See what state our Netif is in and if this packet is useful *)
    let open Dhcpv4_option.Packet in
    match t.state with
    | Request_sent xid -> begin
        (* we are expecting an offer *)
        match packet.op, xid with
        |`Offer, offer_xid when offer_xid=xid ->  begin
            Log.info (fun f -> f 
              "DHCP: offer received: %a@\n\
               DHCP options: %s"
              Ipaddr.V4.pp_hum yiaddr
              (prettyprint packet)
            );
            let netmask = find packet
                (function `Subnet_mask addr -> Some addr |_ -> None) in
            let gateways = findl packet
                (function `Router addrs -> Some addrs |_ -> None) in
            let dns = findl packet
                (function `DNS_server addrs -> Some addrs |_ -> None) in
            let lease = 0l in
            let offer = { ip_addr=yiaddr; netmask; gateways; dns; lease; xid } in
            (* RFC2131 defines the 'siaddr' as the address of the server which
               will take part in the next stage of the bootstrap process (eg
               'delivery of an operating system executable image'). This
               may or may not be the address of the DHCP server. However
               'a DHCP server always returns its own address in the server
               identifier option' *)
            let server_identifier = find packet
                (function `Server_identifier addr -> Some addr | _ -> None) in
            let options = { op=`Request;
                            opts= `Requested_ip yiaddr :: (
                              match server_identifier with
                              | Some x -> [ `Server_identifier x ]
                              | None -> [])
                          } in
            t.state <- Offer_accepted offer;
            output_broadcast t ~xid ~yiaddr ~siaddr ~options
          end
        |_ ->
          Log.info (fun f -> f "DHCP: offer not for us"); Lwt.return_unit
      end
    | Offer_accepted info -> begin
        (* we are expecting an ACK *)
        match packet.op, xid with
        |`Ack, ack_xid when ack_xid = info.xid -> begin
            let lease =
              match find packet (function `Lease_time lt -> Some lt |_ -> None) with
              | None -> 300l (* Just leg it and assume a lease time of 5 minutes *)
              | Some x -> x in
            let info = { info with lease=lease } in
            (* TODO also merge in additional requested options here *)
            t.state <- Lease_held info;
            t.new_offer info
          end
        |_ -> Log.info (fun f -> f "DHCP: ack not for us"); Lwt.return_unit
      end
    | Shutting_down -> Lwt.return_unit
    | Lease_held _  -> Log.info (fun f -> f "DHCP input: lease already held"); Lwt.return_unit
    | Disabled      -> Log.info (fun f -> f "DHCP input: disabled"); Lwt.return_unit

  (* Start a DHCP discovery off on an interface *)
  let start_discovery t =
    Time.sleep_ns (Duration.of_ms 200)
    >>= fun () ->
    let xid = Random.int32 Int32.max_int in
    let yiaddr = Ipaddr.V4.any in
    let siaddr = Ipaddr.V4.any in
    let options = { Dhcpv4_option.Packet.op=`Discover; opts= [
        (`Parameter_request [`Subnet_mask; `Router; `DNS_server; `Broadcast]);
        (`Host_name "miragevm")
      ] } in
    Log.info (fun f -> f "DHCP: start discovery");
    t.state <- Request_sent xid;
    output_broadcast t ~xid ~yiaddr ~siaddr ~options >>= fun () ->
    Lwt.return_unit

  (* DHCP state thred *)
  let rec dhcp_thread t =
    (* For now, just send out regular discoveries until we have a lease *)
    match t.state with
    |Disabled |Request_sent _ ->
      start_discovery t
      >>= fun () ->
      Time.sleep_ns (Duration.of_sec 10)
      >>= fun () ->
      dhcp_thread t
    |Shutting_down ->
      Log.info (fun f -> f "DHCP thread: done"); Lwt.return_unit
    |_ ->
      (* TODO: This should be looking at the lease time *)
      Time.sleep_ns (Duration.of_hour 1)
      >>= fun () ->
      dhcp_thread t

  let pp_opt pp f = function
    | None -> Format.pp_print_string f "None"
    | Some x -> pp f x

  (* Create a DHCP thread *)
  let create mac udp =
    let state = Disabled in
    (* For now, just block on the first offer
       and shut down DHCP after. TODO: full protocol *)
    let offer_stream, offer_push = Lwt_stream.create () in
    let new_offer info =
      Log.info (fun f -> f "DHCP: offer received@\nIPv4: %a@\nNetmask: %a\nGateways: [%s]"
                         Ipaddr.V4.pp_hum info.ip_addr
                         (pp_opt Ipaddr.V4.pp_hum) info.netmask
                         (String.concat ", " (List.map Ipaddr.V4.to_string info.gateways)));
      offer_push (Some info);
      Lwt.return_unit
    in
    let t = { mac; udp; state; new_offer } in
    (* TODO cancellation *)
    let _ = dhcp_thread t in
    t, offer_stream

  let listen t ~dst_port =
    match dst_port with
    | 68 (* TODO services module from Uri? *) -> Some (input t)
    | _ -> None
end
