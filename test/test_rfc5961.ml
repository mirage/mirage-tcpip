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
open Common
open Lwt.Infix

open Low_level

(* Test scenarios *)


(* Common sut: able to connect, connection not reset, no data received *)
let sut_connects_and_remains_connected stack fail_callback =
  let conn = VNETIF_STACK.Stack.TCP.create_connection (VNETIF_STACK.Stack.tcp stack) in
  or_error "connect" conn (Ipaddr.V4 server_ip, 80) >>= fun flow ->
  (* We must remain blocked on read, connection shouldn't be terminated.
   * If after half second that remains true, assume test succeeds *)
  Lwt.pick [
    (VNETIF_STACK.Stack.TCP.read flow >>= fail_result_not_expected fail_callback);
    Time.sleep_ns (Duration.of_ms 500) ]


let blind_rst_on_syn_scenario =
  let fsm ip state ~src ~dst data =
    match state with
    | `WAIT_FOR_SYN ->
      let syn = Tcp_wire.get_syn data in
      if syn then (
        let id = reply_id_from ~src ~dst data in
        (* This -blind- reset must be ignored because of invalid ack. *)
        WIRE.xmit ~ip id ~rst:true ~rx_ack:(ack_from_past data 1)
          ~seq:(Sequence.of_int32 0l) ~window ~options (Cstruct.create 0)
        >|= Result.get_ok >>= fun () ->
        (* The syn-ack must be received and connection established *)
        WIRE.xmit ~ip id ~syn:true ~rx_ack:(ack data) ~seq:(Sequence.of_int32 0l) ~window
          ~options (Cstruct.create 0)
          >|= Result.get_ok >>= fun () ->
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
  let fsm ip state ~src ~dst data =
    match state with
    | `WAIT_FOR_SYN ->
      let syn = Tcp_wire.get_syn data in
      if syn then (
        let id = reply_id_from ~src ~dst data in
        (* refused *)
        WIRE.xmit ~ip id ~rst:true ~rx_ack:(ack data) ~seq:(Sequence.of_int32 0l) ~window
          ~options (Cstruct.create 0)
          >|= Result.get_ok >>= fun () ->
        Lwt.return Fsm_done
      ) else
        Lwt.return (Fsm_error "Expected initial syn request") in
  let sut stack _fail =
    let conn = VNETIF_STACK.Stack.TCP.create_connection (VNETIF_STACK.Stack.tcp stack) in
    (* connection must be rejected *)
    expect_error `Refused "connect" conn (Ipaddr.V4 server_ip, 80) in
  (`WAIT_FOR_SYN, fsm), sut


let blind_rst_on_established_scenario =
  let fsm ip state ~src ~dst data =
    match state with
    | `WAIT_FOR_SYN ->
      let syn = Tcp_wire.get_syn data in
      if syn then (
        let id = reply_id_from ~src ~dst data in
        WIRE.xmit ~ip id ~syn:true ~rx_ack:(ack data) ~seq:(Sequence.of_int32 0l) ~window
          ~options (Cstruct.create 0)
          >|= Result.get_ok >>= fun () ->
        Lwt.return (Fsm_next `WAIT_FOR_ACK)
      ) else
        Lwt.return (Fsm_error "Expected initial syn request")
    | `WAIT_FOR_ACK ->
      if Tcp_wire.get_ack data then (
        (* This -blind- reset is acceptable, but don't exactly match the next sequence (we started at 0, this is 10).
         * Must trigger a challenge ack and not tear down the connection *)
        let id = reply_id_from ~src ~dst data in
        WIRE.xmit ~ip id ~rst:true ~rx_ack:None ~seq:(Sequence.of_int32 10l)
          ~window ~options (Cstruct.create 0)
          >|= Result.get_ok >>= fun () ->
        Lwt.return (Fsm_next `WAIT_FOR_CHALLENGE)
      ) else
        Lwt.return (Fsm_error "Expected final ack of three way handshake")
    | `WAIT_FOR_CHALLENGE ->
      if (Tcp_wire.get_ack data) && (Tcp_wire.get_ack_number data = 1l)  then
        Lwt.return Fsm_done
      else
        Lwt.return (Fsm_error "Challenge ack expected") in
  (`WAIT_FOR_SYN, fsm), sut_connects_and_remains_connected

let rst_on_established_scenario =
  let fsm ip state ~src ~dst data =
    match state with
    | `WAIT_FOR_SYN ->
      let syn = Tcp_wire.get_syn data in
      if syn then (
        let id = reply_id_from ~src ~dst data in
        WIRE.xmit ~ip id ~syn:true ~rx_ack:(ack data)
          ~seq:(Sequence.of_int32 0l) ~window
          ~options (Cstruct.create 0)
          >|= Result.get_ok >>= fun () ->
        Lwt.return (Fsm_next `WAIT_FOR_ACK)
      ) else
        Lwt.return (Fsm_error "Expected initial syn request")
    | `WAIT_FOR_ACK ->
      if Tcp_wire.get_ack data then (
        let id = reply_id_from ~src ~dst data in
        (* This reset is acceptable and exactly in sequence. Must trigger a reset on the other end *)
        WIRE.xmit ~ip id ~rst:true ~rx_ack:None ~seq:(Sequence.of_int32 1l)
          ~window ~options (Cstruct.create 0)
          >|= Result.get_ok >>= fun () ->
        Lwt.return Fsm_done
      ) else
        Lwt.return (Fsm_error "Expected final ack of three step dance") in

  let sut stack fail_callback =
    let conn = VNETIF_STACK.Stack.TCP.create_connection (VNETIF_STACK.Stack.tcp stack) in
    or_error "connect" conn (Ipaddr.V4 server_ip, 80) >>= fun flow ->
    VNETIF_STACK.Stack.TCP.read flow >>= function
    | Ok `Eof ->
      (* This is the expected when the other end resets *)
      Lwt.return_unit
    | other ->
      fail_result_not_expected fail_callback other in
  (`WAIT_FOR_SYN, fsm), sut

let blind_syn_on_established_scenario =
  let fsm ip state ~src ~dst data =
    match state with
    | `WAIT_FOR_SYN ->
      let syn = Tcp_wire.get_syn data in
      if syn then (
        let id = reply_id_from ~src ~dst data in
        WIRE.xmit ~ip id ~syn:true ~rx_ack:(ack data)
          ~seq:(Sequence.of_int32 0l) ~window
          ~options (Cstruct.create 0)
          >|= Result.get_ok >>= fun () ->
        Lwt.return (Fsm_next `WAIT_FOR_ACK)
      ) else
        Lwt.return (Fsm_error "Expected initial syn request")
    | `WAIT_FOR_ACK ->
      if Tcp_wire.get_ack data then (
        let id = reply_id_from ~src ~dst data in

        (* This -blind- syn should trigger a challenge ack and not
           tear down the connection *)
        WIRE.xmit ~ip id ~syn:true ~rx_ack:None ~seq:(Sequence.of_int32 10l)
          ~window ~options (Cstruct.create 0)
          >|= Result.get_ok >>= fun () ->
        Lwt.return (Fsm_next `WAIT_FOR_CHALLENGE)
      ) else
        Lwt.return (Fsm_error "Expected final ack of three step dance")
    | `WAIT_FOR_CHALLENGE ->
      if (Tcp_wire.get_ack data) && (Tcp_wire.get_ack_number data = 1l)  then  (
        Lwt.return Fsm_done
      ) else
        Lwt.return (Fsm_error "Challenge ack expected") in
  (`WAIT_FOR_SYN, fsm), sut_connects_and_remains_connected

let blind_data_injection_scenario =
  let page = Cstruct.create 512 in
  let fsm ip state ~src ~dst data =
    match state with
    | `WAIT_FOR_SYN ->
      let syn = Tcp_wire.get_syn data in
      if syn then (
        let id = reply_id_from ~src ~dst data in
        WIRE.xmit ~ip id ~syn:true ~rx_ack:(ack data)
          ~seq:(Sequence.of_int32 1000000l) ~window
          ~options (Cstruct.create 0)
          >|= Result.get_ok >>= fun () ->
        Lwt.return (Fsm_next `WAIT_FOR_ACK)
      ) else
        Lwt.return (Fsm_error "Expected initial syn request")
    | `WAIT_FOR_ACK ->
      if Tcp_wire.get_ack data then (
        let id = reply_id_from ~src ~dst data in
        (* This -blind- data should trigger a challenge ack and not
           tear down the connection *)
        let invalid_ack =  ack_from_past data (window +100) in
        WIRE.xmit ~ip id ~rx_ack:invalid_ack ~seq:(Sequence.of_int32 1000001l)
          ~window ~options page
          >|= Result.get_ok >>= fun () ->
        Lwt.return (Fsm_next `WAIT_FOR_CHALLENGE)
      ) else
        Lwt.return (Fsm_error "Expected final ack of three step dance")
    | `WAIT_FOR_CHALLENGE ->
      if (Tcp_wire.get_ack data) && (Tcp_wire.get_ack_number data = 1000001l)  then
        Lwt.return Fsm_done
      else
        Lwt.return (Fsm_error "Challenge ack expected")
  in
  (`WAIT_FOR_SYN, fsm), sut_connects_and_remains_connected

let data_repeated_ack_scenario =
  (* This is the just data transmission with ack in the past but within the acceptable window *)
  let page = Cstruct.create 512 in
  let fsm ip state ~src ~dst data =
    match state with
    | `WAIT_FOR_SYN ->
      let syn = Tcp_wire.get_syn data in
      if syn then (
        let id = reply_id_from ~src ~dst data in
        WIRE.xmit ~ip id ~syn:true ~rx_ack:(ack data)
          ~seq:(Sequence.of_int32 1000000l) ~window
          ~options (Cstruct.create 0)
          >|= Result.get_ok >>= fun () ->
        Lwt.return (Fsm_next `WAIT_FOR_ACK)
      ) else
        Lwt.return (Fsm_error "Expected initial syn request")
    | `WAIT_FOR_ACK ->
      if Tcp_wire.get_ack data then (
        let id = reply_id_from ~src ~dst data in
        (* Ack is old but within the acceptable window. *)
        let valid_ack = ack_from_past data (window -100) in
        WIRE.xmit ~ip id ~rx_ack:valid_ack ~seq:(Sequence.of_int32 1000001l)
          ~window ~options page
        >|= Result.get_ok >>= fun () ->
        Lwt.return (Fsm_next `WAIT_FOR_DATA_ACK)
      ) else
        Lwt.return (Fsm_error "Expected final ack of three step dance")
    | `WAIT_FOR_DATA_ACK ->
      if (Tcp_wire.get_ack data) && (Tcp_wire.get_ack_number data = Int32.(add 1000001l (of_int (Cstruct.length page))))  then
        Lwt.return Fsm_done
      else
        Lwt.return (Fsm_error "Ack for data expected") in

  let sut stack fail_callback =
    let conn = VNETIF_STACK.Stack.TCP.create_connection (VNETIF_STACK.Stack.tcp stack) in
    or_error "connect" conn (Ipaddr.V4 server_ip, 80) >>= fun flow ->
    (* We should receive the data *)
    VNETIF_STACK.Stack.TCP.read flow >>= function
    | Ok _ -> Lwt.return_unit
    | other -> fail_result_not_expected fail_callback other in
  (`WAIT_FOR_SYN, fsm), sut


let run_test pcap_file ((initial_state, fsm), sut) () =
  let backend = VNETIF_STACK.create_backend () in
  VNETIF_STACK.record_pcap backend pcap_file  (run backend (initial_state, fsm) sut)

let suite = [
  "blind rst to syn_sent", `Quick,
  run_test "tcp_blind_rst_on_syn.pcap" blind_rst_on_syn_scenario ;

  "connection refused", `Quick,
  run_test "tcp_connection_refused.pcap" connection_refused_scenario;

  "blind rst on established", `Quick,
  run_test "tcp_blind_rst_on_established.pcap" blind_rst_on_established_scenario;

  "rst on established", `Quick,
  run_test "tcp_rst_on_established.pcap" rst_on_established_scenario;

  "blind syn on established", `Quick,
  run_test "tcp_blind_syn_on_established.pcap" blind_syn_on_established_scenario;

  "blind data injection", `Quick,
  run_test "tcp_blind_data_injection.pcap" blind_data_injection_scenario;

  "data repeated ack", `Quick,
  run_test "tcp_data_repeated_ack.pcap" data_repeated_ack_scenario;
]
