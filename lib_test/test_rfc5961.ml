(*
 * Copyright (c) 2016 Pablo Polvorin <pablo.polvorin@gmail.com>
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
open Common

(*
 * Connects two stacks to the same backend.  One is a complete v4 stack (the sut).
 * The other gives us low level access to inject crafted TCP packets, and check sut behaviour.
 *)
module VNETIF_STACK = Vnetif_common.VNETIF_STACK(Vnetif_backends.Basic)

module V = Vnetif.Make(Vnetif_backends.Basic)
module E = Ethif.Make(V)
module A = Arpv4.Make(E)(Vnetif_common.Clock)(Vnetif_common.Time)
module I = Ipv4.Make(E)(A)
module Wire = Tcp.Wire
module WIRE = Wire.Make(I)
module Console = Vnetif_common.Console
module Tcp_wire = Tcp.Tcp_wire
module Sequence = Tcp.Sequence

let netmask = Ipaddr.V4.of_string_exn "255.255.255.0"
let gw = Ipaddr.V4.of_string_exn "10.0.0.1"
let sut_ip = Ipaddr.V4.of_string_exn "10.0.0.101"
let server_ip = Ipaddr.V4.of_string_exn "10.0.0.100"

(* defaults when injecting packets *)
let options = []
let window = 5120

let create_sut_stack console backend =
    VNETIF_STACK.create_stack console backend sut_ip netmask [gw]

let create_raw_stack backend =
    or_error "backend" V.connect backend >>= fun netif ->
    or_error "ethif" E.connect netif >>= fun ethif ->
    or_error "arpv4" A.connect ethif >>= fun arpv4 ->
    or_error "ipv4" (I.connect ethif) arpv4 >>= fun ip ->
    Lwt.return (netif, ethif, arpv4, ip)

type 'state fsm_result =
    | Fsm_next of 'state
    | Fsm_done
    | Fsm_error of string

(*  This could be moved to a common module and reused for other low level tcp tests *)

(* setups network and run a given sut and raw fsm *)
let run backend fsm sut () =
    let initial_state, fsm_handler = fsm in
    or_error "console" Console.connect "console" >>= fun console ->
    create_sut_stack console backend >>= fun stackv4 ->
    create_raw_stack backend >>= fun (netif, ethif, arp, rawip) ->
    I.set_ip_netmask rawip netmask >>= fun () ->
    I.set_ip rawip server_ip >>= fun () ->
    let error_mbox = Lwt_mvar.create_empty () in
    let stream, pushf = Lwt_stream.create () in

    (* Consume TCP packets one by one, in sequence *)
    let rec fsm_thread state =
        Lwt_stream.next stream >>= fun (src, dst, data) ->
        fsm_handler console rawip state ~src ~dst data >>= function
        | Fsm_next s ->
                fsm_thread s
        | Fsm_done ->
                Lwt.return_unit
        | Fsm_error err ->
                Lwt_mvar.put error_mbox err >>= fun () ->
                (* it will be terminated anyway when the error is picked up *)
                fsm_thread state in

    Lwt.async (fun () ->
        (V.listen netif
          (E.input
             ~arpv4:(A.input arp)
             ~ipv4:(I.input
                      ~tcp: (fun ~src ~dst data -> pushf (Some(src,dst,data)); Lwt.return_unit)
                      ~udp:(fun ~src ~dst data -> Lwt.return_unit)
                      ~default:(fun ~proto ~src ~dst data ->
                          Console.log_s console "DEFAULT")
                      rawip
                   )
             ~ipv6:(fun buf -> return (Console.log console "IP6"))
             ethif) ));

    (* Either both fsm and the sut terminates, or a timeout occurs, or one of the sut/fsm informs an error *)
    Lwt.pick [
        (OS.Time.sleep 5.0 >>= fun () ->
            Lwt.return_some "timed out");

        (Lwt.join [
            (fsm_thread initial_state);

            (* time to let the other end connects to the network and listen.
             * Otherwise initial syn might need to be repeated slowing down the test *)
            (OS.Time.sleep 0.1 >>= fun () -> 
             sut console stackv4 (Lwt_mvar.put error_mbox) >>= fun _ ->
             OS.Time.sleep 0.1);
            ] >>= fun () -> Lwt.return_none);

         (Lwt_mvar.take error_mbox >>= fun cause ->
             Lwt.return_some cause);
        ] >>= function
            | None ->
                    Lwt.return_unit
            | Some err ->
                    Alcotest.fail err;
                    Lwt.return_unit


(* Helper functions *)
let reply_id_from ~src ~dst data =
    let sport = Tcp_wire.get_tcp_src_port data in
    let dport = Tcp_wire.get_tcp_dst_port data in
    {WIRE.dest_port = sport;
     dest_ip = src;
     local_port = dport;
     local_ip = dst}

let ack_for data =
    let data_len = (Cstruct.len (Wire.get_payload data)) +
                   (if Tcp_wire.get_fin data then 1 else 0) +
                   (if Tcp_wire.get_syn data then 1 else 0) in
    let sequence = Sequence.of_int32 (Tcp_wire.get_tcp_sequence data) in
    let ack_n = Sequence.(add sequence (of_int data_len)) in
    ack_n

let ack data =
    Some(ack_for data)

let ack_in_future data off =
    Some Sequence.(add (ack_for data) (of_int off))

let ack_from_past data off =
    Some Sequence.(sub (ack_for data) (of_int off))

let fail_result_not_expected fail = function
    | `Ok data ->
           fail "data not expected"
    | `Error err ->
            fail "error not expected"
    | `Eof ->
            fail "eof"


(* Test scenarios *)


(* Common sut: able to connect, connection not reset, no data received *)
let sut_connects_and_remains_connected console stack fail_callback =
    let conn = VNETIF_STACK.Stackv4.TCPV4.create_connection (VNETIF_STACK.Stackv4.tcpv4 stack) in
    or_error "connect" conn (server_ip, 80) >>= fun flow ->
        (* We must remain blocked on read, connection shouldn't be terminated.
         * If after half second that remains true, assume test succed *)
    Lwt.pick [
        (VNETIF_STACK.Stackv4.TCPV4.read flow >>= fail_result_not_expected fail_callback);
        OS.Time.sleep 0.5 ]


let blind_rst_on_syn_scenario =
    let fsm console ip state ~src ~dst data =
        match state with
        | `WAIT_FOR_SYN ->
            let syn = Tcp_wire.get_syn data in
            if syn then (
                let id = reply_id_from ~src ~dst data in
                (* This -blind- reset must be ignored because of invalid ack. *)
                WIRE.xmit ~ip ~id ~rst:true ~rx_ack:(ack_from_past data 1) ~seq:(Sequence.of_int32 0l) ~window ~options [] >>= fun () ->
                (* The syn-ack must be received and connection established *)
                WIRE.xmit ~ip ~id ~syn:true ~rx_ack:(ack data) ~seq:(Sequence.of_int32 0l) ~window ~options [] >>= fun () ->
                Lwt.return (Fsm_next `WAIT_FOR_ACK)
            ) else
                 Lwt.return (Fsm_error "Expected initial syn request")
         | `WAIT_FOR_ACK ->
            if Tcp_wire.get_ack data then (
                Lwt.return Fsm_done
            ) else
               Lwt.return (Fsm_error "Expected final ack of three step dance")
         | `END ->
               Lwt.return (Fsm_error "nothing expected")  in
    (`WAIT_FOR_SYN, fsm), sut_connects_and_remains_connected

let connection_refused_scenario =
    let fsm console ip state ~src ~dst data =
        match state with
        | `WAIT_FOR_SYN ->
            let syn = Tcp_wire.get_syn data in
            if syn then (
                let id = reply_id_from ~src ~dst data in
                (* refused *)
                WIRE.xmit ~ip ~id ~rst:true ~rx_ack:(ack data) ~seq:(Sequence.of_int32 0l) ~window ~options [] >>= fun () ->
                Lwt.return Fsm_done
            ) else
                 Lwt.return (Fsm_error "Expected initial syn request") in
    let sut console stack fail =
        let conn = VNETIF_STACK.Stackv4.TCPV4.create_connection (VNETIF_STACK.Stackv4.tcpv4 stack) in
        (* connection must be rejected *)
        expect_error `Refused "connect" conn (server_ip, 80) in 
    (`WAIT_FOR_SYN, fsm), sut


let blind_rst_on_established_scenario =
    let fsm console ip state ~src ~dst data =
        match state with
        | `WAIT_FOR_SYN ->
            let syn = Tcp_wire.get_syn data in
            if syn then (
                let id = reply_id_from ~src ~dst data in
                WIRE.xmit ~ip ~id ~syn:true ~rx_ack:(ack data) ~seq:(Sequence.of_int32 0l) ~window ~options [] >>= fun () ->
                Lwt.return (Fsm_next `WAIT_FOR_ACK)
            ) else
                 Lwt.return (Fsm_error "Expected initial syn request")
         | `WAIT_FOR_ACK ->
            if Tcp_wire.get_ack data then (
                (* This -blind- reset is acceptable, but don't exactly match the next sequence (we started at 0, this is 10).
                 * Must trigger a challenge ack and not tear down the connection *)
                let id = reply_id_from ~src ~dst data in
                WIRE.xmit ~ip ~id ~rst:true ~rx_ack:None ~seq:(Sequence.of_int32 10l) ~window ~options [] >>= fun () ->
                Lwt.return (Fsm_next `WAIT_FOR_CHALLENGE)
            ) else
               Lwt.return (Fsm_error "Expected final ack of three way handshake")
         | `WAIT_FOR_CHALLENGE ->
            if (Tcp_wire.get_ack data) && (Tcp_wire.get_tcp_ack_number data = 1l)  then
               Lwt.return Fsm_done
            else
                Lwt.return (Fsm_error "Challenge ack expected") in
    (`WAIT_FOR_SYN, fsm), sut_connects_and_remains_connected

let rst_on_established_scenario =
    let fsm console ip state ~src ~dst data =
        match state with
        | `WAIT_FOR_SYN ->
            let syn = Tcp_wire.get_syn data in
            if syn then (
                let id = reply_id_from ~src ~dst data in
                WIRE.xmit ~ip ~id ~syn:true ~rx_ack:(ack data) ~seq:(Sequence.of_int32 0l) ~window ~options [] >>= fun () ->
                Lwt.return (Fsm_next `WAIT_FOR_ACK)
            ) else
                 Lwt.return (Fsm_error "Expected initial syn request")
         | `WAIT_FOR_ACK ->
            if Tcp_wire.get_ack data then (
                let id = reply_id_from ~src ~dst data in
                (* This reset is acceptable and exactly in sequence. Must trigger a reset on the other end *)
                WIRE.xmit ~ip ~id ~rst:true ~rx_ack:None ~seq:(Sequence.of_int32 1l) ~window ~options [] >>= fun () ->
                Lwt.return Fsm_done
            ) else
               Lwt.return (Fsm_error "Expected final ack of three step dance") in

    let sut console stack fail_callback =
        let conn = VNETIF_STACK.Stackv4.TCPV4.create_connection (VNETIF_STACK.Stackv4.tcpv4 stack) in
        or_error "connect" conn (server_ip, 80) >>= fun flow ->
        VNETIF_STACK.Stackv4.TCPV4.read flow >>= function
            | `Eof ->
                    (* This is the expected when the other end resets *)
                   Lwt.return_unit
            | other ->
                   fail_result_not_expected fail_callback other in
    (`WAIT_FOR_SYN, fsm), sut

let blind_syn_on_established_scenario =
    let fsm console ip state ~src ~dst data =
        match state with
        | `WAIT_FOR_SYN ->
            let syn = Tcp_wire.get_syn data in
            if syn then (
                let id = reply_id_from ~src ~dst data in
                WIRE.xmit ~ip ~id ~syn:true ~rx_ack:(ack data) ~seq:(Sequence.of_int32 0l) ~window ~options [] >>= fun () ->
                Lwt.return (Fsm_next `WAIT_FOR_ACK)
            ) else
                 Lwt.return (Fsm_error "Expected initial syn request")
         | `WAIT_FOR_ACK ->
            if Tcp_wire.get_ack data then (
                let id = reply_id_from ~src ~dst data in
                (* This -blind- syn should trigger a challenge ack and not tear down the connection *)
                WIRE.xmit ~ip ~id ~syn:true ~rx_ack:None ~seq:(Sequence.of_int32 10l) ~window ~options [] >>= fun () ->
                Lwt.return (Fsm_next `WAIT_FOR_CHALLENGE)
            ) else
               Lwt.return (Fsm_error "Expected final ack of three step dance")
         | `WAIT_FOR_CHALLENGE ->
            if (Tcp_wire.get_ack data) && (Tcp_wire.get_tcp_ack_number data = 1l)  then  (
                Lwt.return Fsm_done
            ) else
                Lwt.return (Fsm_error "Challenge ack expected") in
    (`WAIT_FOR_SYN, fsm), sut_connects_and_remains_connected

let blind_data_injection_scenario =
    let page = Io_page.to_cstruct (Io_page.get 1) in
    let fsm console ip state ~src ~dst data =
        match state with
        | `WAIT_FOR_SYN ->
            let syn = Tcp_wire.get_syn data in
            if syn then (
                let id = reply_id_from ~src ~dst data in
                WIRE.xmit ~ip ~id ~syn:true ~rx_ack:(ack data) ~seq:(Sequence.of_int32 1000000l) ~window ~options [] >>= fun () ->
                Lwt.return (Fsm_next `WAIT_FOR_ACK)
            ) else
                 Lwt.return (Fsm_error "Expected initial syn request")
         | `WAIT_FOR_ACK ->
            if Tcp_wire.get_ack data then (
                let id = reply_id_from ~src ~dst data in
                (* This -blind- data should trigger a challenge ack and not tear down the connection *)
                let invalid_ack =  ack_from_past data (window +100) in
                WIRE.xmit ~ip ~id ~rx_ack:invalid_ack ~seq:(Sequence.of_int32 1000001l) ~window ~options [page] >>= fun () ->
                Lwt.return (Fsm_next `WAIT_FOR_CHALLENGE)
            ) else
               Lwt.return (Fsm_error "Expected final ack of three step dance")
         | `WAIT_FOR_CHALLENGE ->
            if (Tcp_wire.get_ack data) && (Tcp_wire.get_tcp_ack_number data = 1000001l)  then
                Lwt.return Fsm_done
            else
                Lwt.return (Fsm_error "Challenge ack expected") in
    (`WAIT_FOR_SYN, fsm), sut_connects_and_remains_connected

let data_repeated_ack_scenario =
    (* This is the just data transmission with ack in the past but within the acceptable window *)
    let page = Io_page.to_cstruct (Io_page.get 1) in
    let fsm console ip state ~src ~dst data =
        match state with
        | `WAIT_FOR_SYN ->
            let syn = Tcp_wire.get_syn data in
            if syn then (
                let id = reply_id_from ~src ~dst data in
                WIRE.xmit ~ip ~id ~syn:true ~rx_ack:(ack data) ~seq:(Sequence.of_int32 1000000l) ~window ~options [] >>= fun () ->
                Lwt.return (Fsm_next `WAIT_FOR_ACK)
            ) else
                 Lwt.return (Fsm_error "Expected initial syn request")
         | `WAIT_FOR_ACK ->
            if Tcp_wire.get_ack data then (
                let id = reply_id_from ~src ~dst data in
                (* Ack is old but within the acceptable window. *)
                let valid_ack = ack_from_past data (window -100) in
                WIRE.xmit ~ip ~id ~rx_ack:valid_ack ~seq:(Sequence.of_int32 1000001l) ~window ~options [page] >>= fun () ->
                Lwt.return (Fsm_next `WAIT_FOR_DATA_ACK)
            ) else
               Lwt.return (Fsm_error "Expected final ack of three step dance")
         | `WAIT_FOR_DATA_ACK ->
            if (Tcp_wire.get_ack data) && (Tcp_wire.get_tcp_ack_number data = Int32.(add 1000001l (of_int (Cstruct.len page))))  then
                Lwt.return Fsm_done
            else
                Lwt.return (Fsm_error "Ack for data expected") in

    let sut console stack fail_callback =
        let conn = VNETIF_STACK.Stackv4.TCPV4.create_connection (VNETIF_STACK.Stackv4.tcpv4 stack) in
        or_error "connect" conn (server_ip, 80) >>= fun flow ->
            (* We should receive the data *)
        VNETIF_STACK.Stackv4.TCPV4.read flow >>= function
            | `Ok data ->
                    Lwt.return_unit
            | other -> fail_result_not_expected fail_callback other in
    (`WAIT_FOR_SYN, fsm), sut


let run_test pcap_file ((initial_state, fsm), sut) () =
    let backend = VNETIF_STACK.create_backend () in
    VNETIF_STACK.record_pcap backend pcap_file  (run backend (initial_state, fsm) sut)

let suite = [
  "blind rst to syn_sent", `Quick,
      run_test "tests/pcap/tcp_blind_rst_on_syn.pcap" blind_rst_on_syn_scenario ;

  "connection refused", `Quick,
      run_test "tests/pcap/tcp_connection_refused.pcap" connection_refused_scenario;

  "blind rst on established", `Quick,
      run_test "tests/pcap/tcp_blind_rst_on_established.pcap" blind_rst_on_established_scenario;

  "rst on established", `Quick,
      run_test "tests/pcap/tcp_rst_on_established.pcap" rst_on_established_scenario;

  "blind syn on established", `Quick,
      run_test "tests/pcap/tcp_blind_syn_on_established.pcap" blind_syn_on_established_scenario;

  "blind data injection", `Quick,
      run_test "tests/pcap/tcp_blind_data_injection.pcap" blind_data_injection_scenario;

  "data repeated ack", `Quick,
      run_test "tests/pcap/tcp_data_repeated_ack.pcap" data_repeated_ack_scenario;
]
