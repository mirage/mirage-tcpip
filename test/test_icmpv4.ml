open Common

let src = Logs.Src.create "test_icmpv4" ~doc:"ICMP tests"
module Log = (val Logs.src_log src : Logs.LOG)

module B = Basic_backend.Make
module V = Vnetif.Make(B)
module E = Ethernet.Make(V)
module Static_arp = Static_arp.Make(E)

open Lwt.Infix

type decomposed = {
  ipv4_payload : Cstruct.t;
  ipv4_header : Ipv4_packet.t;
  ethernet_payload : Cstruct.t;
  ethernet_header : Ethernet.Packet.t;
}

module Ip = Static_ipv4.Make(E)(Static_arp)
module Icmp = Icmpv4.Make(Ip)

module Udp = Udp.Make(Ip)

type stack = {
  backend : B.t;
  netif : V.t;
  ethif : E.t;
  arp : Static_arp.t;
  ip : Ip.t;
  icmp : Icmp.t;
  udp : Udp.t;
}

let testbind x y =
  match x with
  | Ok p -> y p
  | Error s -> Alcotest.fail s
let (>>=?) = testbind

(* some default addresses which will be on the same class C *)
let listener_address = Ipaddr.V4.of_string_exn "192.168.222.1"
let speaker_address = Ipaddr.V4.of_string_exn "192.168.222.10"

let header_size = Ethernet.Packet.sizeof_ethernet

let get_stack ?(backend = B.create ~use_async_readers:true
                  ~yield:(fun() -> Lwt.pause ()) ())
                  ip =
  let cidr = Ipaddr.V4.Prefix.make 24 ip in
  V.connect backend >>= fun netif ->
  E.connect netif >>= fun ethif ->
  Static_arp.connect ethif >>= fun arp ->
  Ip.connect ~cidr ethif arp >>= fun ip ->
  Icmp.connect ip >>= fun icmp ->
  Udp.connect ip >>= fun udp ->
  Lwt.return { backend; netif; ethif; arp; ip; icmp; udp }

let icmp_listen stack fn =
  let noop = fun ~src:_ ~dst:_ _buf -> Lwt.return_unit in
  V.listen stack.netif ~header_size (* some buffer -> (unit, error) result io *)
    ( E.input stack.ethif ~arpv4:(Static_arp.input stack.arp)
        ~ipv6:(fun _ -> Lwt.return_unit)
        ~ipv4:
          ( Ip.input stack.ip
              ~tcp:noop ~udp:noop
              ~default:(fun ~proto -> match proto with | 1 -> fn | _ -> noop))) >|= fun _ -> ()


let inform_arp stack = Static_arp.add_entry stack.arp
let mac_of_stack stack = E.mac stack.ethif

let short_read () =
  let too_short = Cstruct.create 4 in
  match Icmpv4_packet.Unmarshal.of_cstruct too_short with
  | Ok (icmp, _) ->
    Alcotest.fail (Format.asprintf "processed something too short to be real: %a produced %a"
		     Cstruct.hexdump_pp too_short Icmpv4_packet.pp icmp)
  | Error str -> Printf.printf "short packet rejected successfully! msg: %s\n" str;
    Lwt.return_unit

let echo_request () =
  let seq_no = 0x01 in
  let id_no = 0x1234 in
  let request_payload = Cstruct.of_string "plz reply i'm so lonely" in
  get_stack speaker_address >>= fun speaker ->
  get_stack ~backend:speaker.backend listener_address >>= fun listener ->
  inform_arp speaker listener_address (mac_of_stack listener);
  inform_arp listener speaker_address (mac_of_stack speaker);
  let req = Icmpv4_packet.({code = 0x00; ty = Icmpv4_wire.Echo_request;
                            subheader = Id_and_seq (id_no, seq_no)}) in
  let echo_request = Cstruct.create 2048 in
  Icmpv4_packet.Marshal.into_cstruct req echo_request ~payload:request_payload >>=? fun () ->
  Cstruct.blit request_payload 0 echo_request (Icmpv4_wire.sizeof_icmpv4) (Cstruct.length request_payload);
  let echo_request = Cstruct.sub echo_request 0 (Icmpv4_wire.sizeof_icmpv4 + Cstruct.length request_payload) in
  let check buf =
    let open Icmpv4_packet in
    Log.debug (fun f -> f "Incoming ICMP message: %a" Cstruct.hexdump_pp buf);
    Cstruct.hexdump buf;
    Unmarshal.of_cstruct buf >>=? fun (reply, payload) ->
    match reply.subheader with
    | Next_hop_mtu _ | Pointer _ | Address _ | Unused ->
      Alcotest.fail "received an ICMP message which wasn't an echo-request or reply"
    | Id_and_seq (id, seq) ->
      Alcotest.(check int) "icmp response type" 0x00 (Icmpv4_wire.ty_to_int reply.ty); (* expect an icmp echo reply *)
      Alcotest.(check int) "icmp echo-reply code" 0x00 reply.code; (* should be code 0 *)
      Alcotest.(check int) "icmp echo-reply id" id_no id;
      Alcotest.(check int) "icmp echo-reply seq" seq_no seq;
      Alcotest.(check cstruct) "icmp echo-reply payload" payload request_payload;
      Lwt.return_unit
  in
  Lwt.async (fun () -> Lwt.pick [
    icmp_listen listener (fun ~src ~dst buf ->
        Logs.debug (fun f -> f "listener's ICMP listener invoked");
        Icmp.input listener.icmp ~src ~dst buf);
    icmp_listen speaker (fun ~src:_ ~dst:_ -> check)
  ]);
  Icmp.write speaker.icmp ~dst:listener_address echo_request >>= function
  | Error e -> Alcotest.failf "ICMP echo request write: %a" Icmp.pp_error e
  | Ok () -> Lwt.return_unit

let echo_silent () =
  let open Icmpv4_packet in
  get_stack speaker_address >>= fun speaker ->
  get_stack ~backend:speaker.backend listener_address >>= fun listener ->
  let req = ({code = 0x00; ty = Icmpv4_wire.Echo_request;
	      subheader = Id_and_seq (0xff, 0x4341)}) in
  let echo_request = Marshal.make_cstruct req ~payload:Cstruct.(create 0) in
  let check buf =
    Unmarshal.of_cstruct buf >>=? fun (message, _) ->
    match message.ty with
    | Icmpv4_wire.Echo_reply ->
      Alcotest.fail "received an ICMP echo reply even though we shouldn't have"
    | msg_ty ->
      Printf.printf "received an unexpected ICMP message (type %s); ignoring it"
      (Icmpv4_wire.ty_to_string msg_ty);
      Lwt.return_unit
  in
  let nobody_home = Ipaddr.V4.of_string_exn "192.168.222.90" in
  inform_arp speaker listener_address (mac_of_stack listener);
  inform_arp listener speaker_address (mac_of_stack speaker);
  (* set up an ARP mapping so the listener is more likely to see the echo-request *)
  inform_arp speaker nobody_home (mac_of_stack listener);
  Lwt.async (fun () ->
  Lwt.pick [
    icmp_listen listener (fun ~src ~dst buf -> Icmp.input listener.icmp ~src ~dst buf);
    icmp_listen speaker (fun ~src:_ ~dst:_ -> check);
  ]);
  Icmp.write speaker.icmp ~dst:nobody_home echo_request >>= function
  | Error e -> Alcotest.failf "ICMP echo request write: %a" Icmp.pp_error e
  | Ok () -> Lwt.return_unit

let write_errors () =
  let decompose buf =
    let open Ethernet.Packet in
    let* ethernet_header, ethernet_payload = of_cstruct buf in
    match ethernet_header.ethertype with
    | `IPv6 | `ARP -> Error "not an ipv4 packet"
    | `IPv4 ->
      let* ipv4_header, ipv4_payload =
        Ipv4_packet.Unmarshal.of_cstruct ethernet_payload
      in
      Ok { ethernet_header; ethernet_payload; ipv4_header; ipv4_payload }
  in
  (* for any incoming packet, reject it with would_fragment *)
  let reject_all stack =
    let reject buf =
      match decompose buf with
      | Error s -> Alcotest.fail s
      | Ok decomposed ->
        let reply = Icmpv4_packet.({
            ty = Icmpv4_wire.Destination_unreachable;
            code = Icmpv4_wire.(unreachable_reason_to_int Would_fragment);
            subheader = Next_hop_mtu 576;
          }) in
        let header = Icmpv4_packet.Marshal.make_cstruct reply
            ~payload:decomposed.ethernet_payload in
        let header_and_payload = Cstruct.concat ([header ; decomposed.ethernet_payload]) in
        let open Ipv4_packet in
        Icmp.write stack.icmp ~dst:decomposed.ipv4_header.src header_and_payload >|= Result.get_ok
    in
    V.listen stack.netif ~header_size reject >|= fun _ -> ()
  in
  let check_packet buf : unit Lwt.t =
    let aux buf =
      let open Icmpv4_packet in
      let* icmp, icmp_payload = Unmarshal.of_cstruct buf in
      Alcotest.check Alcotest.int "ICMP message type" 0x03 (Icmpv4_wire.ty_to_int icmp.ty);
      Alcotest.check Alcotest.int "ICMP message code" 0x04 icmp.code;
      match Cstruct.length icmp_payload with
      | 0 -> Alcotest.fail "Error message should've had a payload"
      | _n ->
        (* TODO: packet should have an IP header in it *)
        Alcotest.(check int) "Payload first byte" 0x45 (Cstruct.get_uint8 icmp_payload 0);
        Ok ()
    in
    match aux buf with
    | Error s -> Alcotest.fail s
    | Ok () -> Lwt.return_unit
  in
  let check_rejection stack dst =
    let payload = Cstruct.of_string "!@#$" in
    Lwt.pick [
      icmp_listen stack (fun ~src:_ ~dst:_ buf -> check_packet buf >>= fun () ->
                          V.disconnect stack.netif);
      Mirage_sleep.ns (Duration.of_ms 500) >>= fun () ->
      Udp.write stack.udp ~dst ~src_port:1212 ~dst_port:123 payload
        >|= Result.get_ok >>= fun () ->
        Mirage_sleep.ns (Duration.of_sec 1) >>= fun () ->
      Alcotest.fail "writing thread completed first";
    ]
  in
  get_stack speaker_address >>= fun speaker ->
  get_stack ~backend:speaker.backend listener_address >>= fun listener ->
  inform_arp speaker listener_address (mac_of_stack listener);
  inform_arp listener speaker_address (mac_of_stack speaker);
  Lwt.pick [
    reject_all listener;
    check_rejection speaker listener_address;
  ]

let suite = [
  "short read", `Quick, short_read;
  "echo requests elicit an echo reply", `Quick, echo_request;
  "echo requests for other ips don't elicit an echo reply", `Quick, echo_silent;
  "error messages are written", `Quick, write_errors;
]
