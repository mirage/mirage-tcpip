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

open Lwt
open Printf

module Make (Console : V1_LWT.CONSOLE)
    (Time : V1_LWT.TIME)
    (Random : V1.RANDOM)
    (Ethif : V2_LWT.ETHIF)
    (Ipv4 : V2_LWT.IPV4 with type ethif = Ethif.t)
    (Udp : V2_LWT.UDP with type ip = Ipv4.t and type ipaddr = Ipaddr.V4.t) = struct

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
    c: Console.t;
    udp: Udp.t;
    ip: Ipv4.t;
    mutable state: state;
    new_offer: offer -> unit Lwt.t;
  }

  cstruct dhcp {
      uint8_t op;
      uint8_t htype;
      uint8_t hlen;
      uint8_t hops;
      uint32_t xid;
      uint16_t secs;
      uint16_t flags;
      uint32_t ciaddr;
      uint32_t yiaddr;
      uint32_t siaddr;
      uint32_t giaddr;
      uint8_t chaddr[16];
      uint8_t sname[64];
      uint8_t file[128];
      uint32_t cookie
    } as big_endian

      cenum mode {
      BootRequest = 1;
      BootReply
    } as uint8_t

  (* Send a client broadcast packet *)
  let output_broadcast t ~xid ~yiaddr ~siaddr ~options =
    let options = Dhcpv4_option.Packet.to_bytes options in
    let options_len = String.length options in
    let total_len = options_len + sizeof_dhcp in
    let buf = Io_page.(to_cstruct (get 1)) in
    set_dhcp_op buf (mode_to_int BootRequest);
    set_dhcp_htype buf 1;
    set_dhcp_hlen buf 6;
    set_dhcp_hops buf 0;
    set_dhcp_xid buf xid;
    set_dhcp_secs buf 10; (* TODO dynamic timer *)
    set_dhcp_flags buf 0;
    set_dhcp_ciaddr buf 0l;
    set_dhcp_yiaddr buf (Ipaddr.V4.to_int32 yiaddr);
    set_dhcp_siaddr buf (Ipaddr.V4.to_int32 siaddr);
    set_dhcp_giaddr buf 0l;
    (* TODO add a pad/fill function in cstruct *)
    let ethif = Ipv4.id t.ip in
    let macaddr = Macaddr.to_bytes (Ethif.mac ethif) in
    set_dhcp_chaddr (macaddr ^ (String.make 10 '\000')) 0 buf;
    set_dhcp_sname (String.make 64 '\000') 0 buf;
    set_dhcp_file (String.make 128 '\000') 0 buf;
    set_dhcp_cookie buf 0x63825363l;
    Cstruct.blit_from_string options 0 buf sizeof_dhcp options_len;
    let buf = Cstruct.set_len buf (sizeof_dhcp + options_len) in
    Console.log_s t.c (sprintf "Sending DHCP broadcast len %d" total_len)
    >>= fun () ->
    Udp.write ~dest_ip:Ipaddr.V4.broadcast ~source_port:68 ~dest_port:67 t.udp buf

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
      let chaddr_size = (String.length x) in
      let dst_buffer = (String.make (chaddr_size * 2) '\000') in
      for i = 0 to (chaddr_size - 1) do
        let thischar = of_byte x.[i] in
        String.set dst_buffer (i*2) (String.get thischar 0);
        String.set dst_buffer ((i*2)+1) (String.get thischar 1)
      done;
      dst_buffer
    in
    let chaddr = (chaddr_to_string) (copy_dhcp_chaddr buf) in
    let options = Cstruct.(copy buf sizeof_dhcp (len buf - sizeof_dhcp)) in
    let packet = Dhcpv4_option.Packet.of_bytes options in
    (* For debugging, print out the DHCP response *)
    Console.log_s t.c (sprintf "DHCP: input ciaddr %s yiaddr %s siaddr %s giaddr %s chaddr %s sname %s file %s\n"
                         (Ipaddr.V4.to_string ciaddr) (Ipaddr.V4.to_string yiaddr)
                         (Ipaddr.V4.to_string siaddr) (Ipaddr.V4.to_string giaddr)
                         (chaddr) (copy_dhcp_sname buf) (copy_dhcp_file buf))
    >>= fun () ->
    (* See what state our Netif is in and if this packet is useful *)
    let open Dhcpv4_option.Packet in
    match t.state with
    | Request_sent xid -> begin
        (* we are expecting an offer *)
        match packet.op, xid with
        |`Offer, offer_xid when offer_xid=xid ->  begin
            Console.log_s t.c (sprintf "DHCP: offer received: %s\n%!" (Ipaddr.V4.to_string yiaddr))
            >>= fun () ->
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
            let options = { op=`Request; opts=
                                           `Requested_ip yiaddr :: (
                                             match server_identifier with
                                             | Some x -> [ `Server_identifier x ]
                                             | None -> []
                                           )
                          } in
            t.state <- Offer_accepted offer;
            output_broadcast t ~xid ~yiaddr ~siaddr ~options
          end
        |_ ->
          Console.log_s t.c "DHCP: offer not for us"
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
        |_ -> Console.log_s t.c "DHCP: ack not for us"
      end
    | Shutting_down -> return_unit
    | Lease_held _ -> Console.log_s t.c "DHCP input: lease already held"
    | Disabled -> Console.log_s t.c "DHCP input: disabled"

  (* Start a DHCP discovery off on an interface *)
  let start_discovery t =
    Time.sleep 0.2
    >>= fun () ->
    let xid = Random.int32 Int32.max_int in
    let yiaddr = Ipaddr.V4.any in
    let siaddr = Ipaddr.V4.any in
    let options = { Dhcpv4_option.Packet.op=`Discover; opts= [
        (`Parameter_request [`Subnet_mask; `Router; `DNS_server; `Broadcast]);
        (`Host_name "miragevm")
      ] } in
    Console.log_s t.c (sprintf "DHCP: start discovery\n%!")
    >>= fun () ->
    t.state <- Request_sent xid;
    output_broadcast t ~xid ~yiaddr ~siaddr ~options >>= fun () ->
    return_unit

  (* DHCP state thred *)
  let rec dhcp_thread t =
    (* For now, just send out regular discoveries until we have a lease *)
    match t.state with
    |Disabled |Request_sent _ ->
      start_discovery t
      >>= fun () ->
      Time.sleep 10.0
      >>= fun () ->
      dhcp_thread t
    |Shutting_down ->
      Console.log_s t.c "DHCP thread: done"
    |_ ->
      (* TODO: This should be looking at the lease time *)
      Time.sleep 3600.0
      >>= fun () ->
      dhcp_thread t

  (* Create a DHCP thread *)
  let create c ip udp =
    let state = Disabled in
    (* For now, just block on the first offer
       and shut down DHCP after. TODO: full protocol *)
    let offer_stream, offer_push = Lwt_stream.create () in
    let new_offer info =
      Console.log_s c (sprintf "DHCP: offer %s %s [%s]"
                         (Ipaddr.V4.to_string info.ip_addr)
                         (match info.netmask with |Some ip -> Ipaddr.V4.to_string ip |None -> "None")
                         (String.concat ", " (List.map Ipaddr.V4.to_string info.gateways)))
      >>= fun () ->
      Ipv4.set_ipv4 ip info.ip_addr
      >>= fun () ->
      (match info.netmask with
       |Some nm -> Ipv4.set_ipv4_netmask ip nm
       |None -> return_unit)
      >>= fun () ->
      Ipv4.set_ip_gateways ip info.gateways
      >>= fun () ->
      offer_push (Some info);
      return_unit
    in
    let t = { c; ip; udp; state; new_offer } in
    (* TODO cancellation *)
    let _ = dhcp_thread t in
    t, offer_stream

  let listen t ~dst_port =
    match dst_port with
    | 68 (* TODO services module from Uri? *) -> Some (input t)
    | _ -> None
end
