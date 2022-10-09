open Common

open Low_level
open Lwt.Infix

let close_ack_scenario =
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
        WIRE.xmit ~ip id ~rx_ack:(ack data) ~fin:true ~seq:(Sequence.of_int32 1000001l)
          ~window ~options (Cstruct.create 0)
        >|= Result.get_ok >>= fun () ->
        Lwt.return (Fsm_next `WAIT_FOR_FIN)
      ) else
        Lwt.return (Fsm_error "Expected final ack of three step dance")
    | `WAIT_FOR_FIN ->
      if (Tcp_wire.get_fin data)  then
        let id = reply_id_from ~src ~dst data in
        WIRE.xmit ~ip id ~rx_ack:(ack data) ~seq:(Sequence.of_int32 1000002l)
          ~window:0 ~options (Cstruct.create 0)
        >|= Result.get_ok >>= fun () ->
        Lwt.return Fsm_done
      else
        Lwt.return (Fsm_error "Fin expected") in

  let sut stack _fail_callback =
    let conn = VNETIF_STACK.Stack.TCP.create_connection (VNETIF_STACK.Stack.tcp stack) in
    or_error "connect" conn (Ipaddr.V4 server_ip, 80) >>= fun flow ->
    (* We should receive the data *)
    VNETIF_STACK.Stack.TCP.close flow >>= fun () ->
    Lwt_unix.sleep 4.0 >>= fun () ->
    Alcotest.(check int) "connection is cleaned" 0 (VNETIF_STACK.T.num_open_channels ((VNETIF_STACK.Stack.tcp stack)));
    Lwt.return_unit
  in
  (`WAIT_FOR_SYN, fsm), sut

  let close_reset_scenario =
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
          WIRE.xmit ~ip id ~rx_ack:(ack data) ~fin:true ~seq:(Sequence.of_int32 1000001l)
            ~window ~options (Cstruct.create 0)
          >|= Result.get_ok >>= fun () ->
          Lwt.return (Fsm_next `WAIT_FOR_FIN)
        ) else
          Lwt.return (Fsm_error "Expected final ack of three step dance")
      | `WAIT_FOR_FIN ->
        if (Tcp_wire.get_fin data)  then
          let id = reply_id_from ~src ~dst data in
          WIRE.xmit ~ip id ~rx_ack:None ~rst:true ~seq:(Sequence.of_int32 1000001l)
            ~window:0 ~options (Cstruct.create 0)
          >|= Result.get_ok >>= fun () ->
          Lwt.return (Fsm_next `WAIT_FOR_CHALLENGE_ACK)
        else
          Lwt.return (Fsm_error "Expected fin")
      | `WAIT_FOR_CHALLENGE_ACK ->
        if (Tcp_wire.get_ack data)  then
          let id = reply_id_from ~src ~dst data in
          WIRE.xmit ~ip id ~rx_ack:None ~rst:true ~seq:(Sequence.of_int32 1000002l)
            ~window:0 ~options (Cstruct.create 0)
          >|= Result.get_ok >>= fun () ->
          Lwt.return (Fsm_done)
        else
          Lwt.return (Fsm_error "Expected challenge ack")
    in

    let sut stack _fail_callback =
      let conn = VNETIF_STACK.Stack.TCP.create_connection (VNETIF_STACK.Stack.tcp stack) in
      or_error "connect" conn (Ipaddr.V4 server_ip, 80) >>= fun flow ->
      (* We should receive the data *)
      VNETIF_STACK.Stack.TCP.close flow >>= fun () ->
      Lwt_unix.sleep 4.0 >>= fun () ->
      Alcotest.(check int) "connection is cleaned" 0 (VNETIF_STACK.T.num_open_channels ((VNETIF_STACK.Stack.tcp stack)));
      Lwt.return_unit
    in
    (`WAIT_FOR_SYN, fsm), sut

let run_test pcap_file ((initial_state, fsm), sut) () =
  let backend = VNETIF_STACK.create_backend () in
  VNETIF_STACK.record_pcap backend pcap_file  (run backend (initial_state, fsm) sut)

let suite = [
  "close with ack", `Slow, run_test "close_ack.pcap" close_ack_scenario;
  "close with reset, challenge ack ok", `Slow, run_test "close_reset.pcap" close_reset_scenario;
]
