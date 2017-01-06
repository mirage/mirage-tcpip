open Lwt.Infix

module Stack = Tcpip_stack_socket
module Time = Vnetif_common.Time

type stack_stack = {
  stack : Stack.t;
  icmp  : Icmpv4_socket.t;
  udp   : Udpv4_socket.t;
  tcp   : Tcpv4_socket.t;
}

let or_fail_str ~str f args =
  f args >>= function
  | `Ok p -> Lwt.return p
  | `Error _ -> Alcotest.fail str

let localhost = Ipaddr.V4.of_string_exn "127.0.0.1"

let make_stack ~name ~ip =
  (* define a config record, which should match the type expected of
     Mirage_stack_lwt.stackv4_config *)
  Tcpv4_socket.connect (Some ip) >>= fun tcp ->
  Udpv4_socket.connect (Some ip) >>= fun udp ->
  let config = {
    Mirage_stack_lwt.name;
    interface = [ip];
  } in
  Icmpv4_socket.connect () >>= fun icmp ->
  Stack.connect config udp tcp >>= fun stack ->
  Lwt.return { stack; icmp; udp; tcp }

let two_connect_tcp () =
  let announce flow =
    Tcpv4_socket.read flow >>= function
    | Error _ -> Printf.printf "Error reading!"; Alcotest.fail "Error reading TCP flow"
    | Ok `Eof -> Printf.printf "EOF!"; Lwt.return_unit
    | Ok (`Data buf) -> Printf.printf "Buffer received: %s\n%!" (Cstruct.to_string buf);
      Lwt.return_unit
  in
  let server_port = 14041 in
  make_stack ~name:"server" ~ip:localhost >>= fun server ->
  make_stack ~name:"client" ~ip:localhost >>= fun client ->

  Stack.listen_tcpv4 server.stack ~port:server_port announce;
  Lwt.pick [
    Stack.listen server.stack;
    Stack.TCPV4.create_connection client.tcp (localhost, server_port) >|= Rresult.R.get_ok >>= fun flow ->
    Stack.TCPV4.write flow (Cstruct.of_string "test!") >>= function
    | Ok () -> Stack.TCPV4.close flow
    | Error _ -> Alcotest.fail "Error writing to socket for TCP test"
  ]

let icmp_echo_request () =
  make_stack ~name:"server" ~ip:localhost >>= fun server ->
  make_stack ~name:"client" ~ip:localhost >>= fun client ->
  let echo_request = Icmpv4_packet.(Marshal.make_cstruct
                                      ~payload:(Cstruct.create 0)
                                      { ty = Icmpv4_wire.Echo_request;
                                        code = 0x00;
                                        subheader = Id_and_seq (0x1dea, 0x0001)
                                      }) in
  let received_icmp = ref 0 in
  let log_and_count buf =
    received_icmp := !received_icmp + 1;
    Logs.debug (fun f -> f "received ICMP packet number %d: %a" !received_icmp Cstruct.hexdump_pp buf);
    Lwt.return_unit
  in
  Lwt.pick [
    Icmpv4_socket.listen server.icmp localhost log_and_count;
    Time.sleep_ns (Duration.of_ms 500) >>= fun () ->
    Icmpv4_socket.write client.icmp ~dst:localhost echo_request >|= Rresult.R.get_ok >>= fun () ->
    Time.sleep_ns (Duration.of_sec 10);
  ] >>= fun () -> Alcotest.(check int) "number of ICMP packets received by listener"  1
    !received_icmp; Lwt.return_unit

let suite = [
  "two sockets connect via TCP", `Quick, two_connect_tcp;
  "icmp echo-requests are sent", `Slow, icmp_echo_request;
]
