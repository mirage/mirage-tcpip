open Lwt.Infix

module Stack = Tcpip_stack_socket.V4
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
let localhost_cidr = Ipaddr.V4.Prefix.make 32 localhost

let make_stack ~cidr =
  Tcpv4_socket.connect cidr >>= fun tcp ->
  Udpv4_socket.connect cidr >>= fun udp ->
  Icmpv4_socket.connect () >>= fun icmp ->
  Stack.connect udp tcp >>= fun stack ->
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
  make_stack ~cidr:localhost_cidr >>= fun server ->
  make_stack ~cidr:localhost_cidr >>= fun client ->
  let teardown () =
    Stack.disconnect server.stack >>= fun () ->
    Stack.disconnect client.stack
  in

  Stack.TCPV4.listen (Stack.tcpv4 server.stack) ~port:server_port announce;
  Lwt.pick [
    Stack.listen server.stack;
    Stack.TCPV4.create_connection client.tcp (localhost, server_port) >|= Result.get_ok >>= fun flow ->
    Stack.TCPV4.write flow (Cstruct.of_string "test!") >>= function
    | Ok () -> Stack.TCPV4.close flow >>= fun () -> teardown ()
    | Error _ -> teardown () >>= fun () -> Alcotest.fail "Error writing to socket for TCP test"
  ]

let icmp_echo_request () =
  make_stack ~cidr:localhost_cidr >>= fun server ->
  make_stack ~cidr:localhost_cidr >>= fun client ->

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
    Icmpv4_socket.write client.icmp ~dst:localhost echo_request >|= Result.get_ok >>= fun () ->
    Time.sleep_ns (Duration.of_sec 10);
  ] >>= fun () ->
  Stack.disconnect server.stack >>= fun () ->
  Stack.disconnect client.stack >>= fun () ->
  Icmpv4_socket.disconnect server.icmp >>= fun () ->
  Icmpv4_socket.disconnect client.icmp >|= fun () ->
  Alcotest.(check int) "number of ICMP packets received by listener"
    1 !received_icmp

let no_leak_fds_in_tcpv4 () =
  make_stack ~cidr:localhost_cidr >>= fun stack1 ->
  Stack.TCPV4.listen (Stack.tcpv4 stack1.stack) ~port:1234 (fun _flow -> Lwt.return_unit);
  Stack.disconnect stack1.stack >>= fun () ->
  make_stack ~cidr:localhost_cidr >>= fun stack2 ->
  Stack.TCPV4.listen (Stack.tcpv4 stack2.stack) ~port:1234 (fun _flow -> Lwt.return_unit);
  Stack.disconnect stack2.stack

let no_leak_fds_in_udpv4 () =
  make_stack ~cidr:localhost_cidr >>= fun stack1 ->
  Stack.UDPV4.listen (Stack.udpv4 stack1.stack) ~port:1234 (fun ~src:_ ~dst:_ ~src_port:_ _cs -> Lwt.return_unit);
  Stack.disconnect stack1.stack >>= fun () ->
  make_stack ~cidr:localhost_cidr >>= fun stack2 ->
  Stack.UDPV4.listen (Stack.udpv4 stack2.stack) ~port:1234 (fun ~src:_ ~dst:_ ~src_port:_ _cs -> Lwt.return_unit);
  Stack.disconnect stack2.stack

module Stackv6 = Tcpip_stack_socket.V6

let make_v6_stack () =
  Tcpv6_socket.connect None >>= fun tcp ->
  Udpv6_socket.connect None >>= fun udp ->
  Stackv6.connect udp tcp >|= fun stack ->
  stack

let no_leak_fds_in_tcpv6 () =
  make_v6_stack () >>= fun stack1 ->
  Stackv6.TCP.listen (Stackv6.tcp stack1) ~port:1234 (fun _flow -> Lwt.return_unit);
  Stackv6.disconnect stack1 >>= fun () ->
  make_v6_stack () >>= fun stack2 ->
  Stackv6.TCP.listen (Stackv6.tcp stack2) ~port:1234 (fun _flow -> Lwt.return_unit);
  Stackv6.disconnect stack2

let no_leak_fds_in_udpv6 () =
  make_v6_stack () >>= fun stack1 ->
  Stackv6.UDP.listen (Stackv6.udp stack1) ~port:1234 (fun ~src:_ ~dst:_ ~src_port:_ _cs -> Lwt.return_unit);
  Stackv6.disconnect stack1 >>= fun () ->
  make_v6_stack () >>= fun stack2 ->
  Stackv6.UDP.listen (Stackv6.udp stack2) ~port:1234 (fun ~src:_ ~dst:_ ~src_port:_ _cs -> Lwt.return_unit);
  Stackv6.disconnect stack2

module Stackv4v6 = Tcpip_stack_socket.V4V6

let make_v4v6_stack ipv4_only ipv6_only ipv4 ipv6 =
  Tcpv4v6_socket.connect ~ipv4_only ~ipv6_only ipv4 ipv6 >>= fun tcp ->
  Udpv4v6_socket.connect ~ipv4_only ~ipv6_only ipv4 ipv6 >>= fun udp ->
  Stackv4v6.connect udp tcp >|= fun stack ->
  stack

let ip4_any = Ipaddr.V4.Prefix.global (* 0.0.0.0/0 *)

let no_leak_fds_in_tcpv4v6 () =
  make_v4v6_stack false false ip4_any None >>= fun stack1 ->
  Stackv4v6.TCP.listen (Stackv4v6.tcp stack1) ~port:1234 (fun _flow -> Lwt.return_unit);
  Stackv4v6.disconnect stack1 >>= fun () ->
  make_v4v6_stack false false ip4_any None >>= fun stack2 ->
  Stackv4v6.TCP.listen (Stackv4v6.tcp stack2) ~port:1234 (fun _flow -> Lwt.return_unit);
  Stackv4v6.disconnect stack2

let no_leak_fds_in_udpv4v6 () =
  make_v4v6_stack false false ip4_any None >>= fun stack1 ->
  Stackv4v6.UDP.listen (Stackv4v6.udp stack1) ~port:1234 (fun ~src:_ ~dst:_ ~src_port:_ _cs -> Lwt.return_unit);
  Stackv4v6.disconnect stack1 >>= fun () ->
  make_v4v6_stack false false ip4_any None >>= fun stack2 ->
  Stackv4v6.UDP.listen (Stackv4v6.udp stack2) ~port:1234 (fun ~src:_ ~dst:_ ~src_port:_ _cs -> Lwt.return_unit);
  Stackv4v6.disconnect stack2

let no_leak_fds_in_tcpv4v6_2 () =
  make_v4v6_stack false false localhost_cidr None >>= fun stack1 ->
  Stackv4v6.TCP.listen (Stackv4v6.tcp stack1) ~port:1234 (fun _flow -> Lwt.return_unit);
  Stackv4v6.disconnect stack1 >>= fun () ->
  make_v4v6_stack false false localhost_cidr None >>= fun stack2 ->
  Stackv4v6.TCP.listen (Stackv4v6.tcp stack2) ~port:1234 (fun _flow -> Lwt.return_unit);
  Stackv4v6.disconnect stack2

let no_leak_fds_in_udpv4v6_2 () =
  make_v4v6_stack false false localhost_cidr None >>= fun stack1 ->
  Stackv4v6.UDP.listen (Stackv4v6.udp stack1) ~port:1234 (fun ~src:_ ~dst:_ ~src_port:_ _cs -> Lwt.return_unit);
  Stackv4v6.disconnect stack1 >>= fun () ->
  make_v4v6_stack false false localhost_cidr None >>= fun stack2 ->
  Stackv4v6.UDP.listen (Stackv4v6.udp stack2) ~port:1234 (fun ~src:_ ~dst:_ ~src_port:_ _cs -> Lwt.return_unit);
  Stackv4v6.disconnect stack2

let ip6_local = Some Ipaddr.V6.(Prefix.of_addr localhost)

let no_leak_fds_in_tcpv4v6_3 () =
  make_v4v6_stack false false localhost_cidr ip6_local >>= fun stack1 ->
  Stackv4v6.TCP.listen (Stackv4v6.tcp stack1) ~port:1234 (fun _flow -> Lwt.return_unit);
  Stackv4v6.disconnect stack1 >>= fun () ->
  make_v4v6_stack false false localhost_cidr ip6_local >>= fun stack2 ->
  Stackv4v6.TCP.listen (Stackv4v6.tcp stack2) ~port:1234 (fun _flow -> Lwt.return_unit);
  Stackv4v6.disconnect stack2

let no_leak_fds_in_udpv4v6_3 () =
  make_v4v6_stack false false localhost_cidr ip6_local >>= fun stack1 ->
  Stackv4v6.UDP.listen (Stackv4v6.udp stack1) ~port:1234 (fun ~src:_ ~dst:_ ~src_port:_ _cs -> Lwt.return_unit);
  Stackv4v6.disconnect stack1 >>= fun () ->
  make_v4v6_stack false false localhost_cidr ip6_local >>= fun stack2 ->
  Stackv4v6.UDP.listen (Stackv4v6.udp stack2) ~port:1234 (fun ~src:_ ~dst:_ ~src_port:_ _cs -> Lwt.return_unit);
  Stackv4v6.disconnect stack2

let no_leak_fds_in_tcpv4v6_4 () =
  make_v4v6_stack true false localhost_cidr ip6_local >>= fun stack1 ->
  Stackv4v6.TCP.listen (Stackv4v6.tcp stack1) ~port:1234 (fun _flow -> Lwt.return_unit);
  Stackv4v6.disconnect stack1 >>= fun () ->
  make_v4v6_stack true false localhost_cidr ip6_local >>= fun stack2 ->
  Stackv4v6.TCP.listen (Stackv4v6.tcp stack2) ~port:1234 (fun _flow -> Lwt.return_unit);
  Stackv4v6.disconnect stack2

let no_leak_fds_in_udpv4v6_4 () =
  make_v4v6_stack true false localhost_cidr ip6_local >>= fun stack1 ->
  Stackv4v6.UDP.listen (Stackv4v6.udp stack1) ~port:1234 (fun ~src:_ ~dst:_ ~src_port:_ _cs -> Lwt.return_unit);
  Stackv4v6.disconnect stack1 >>= fun () ->
  make_v4v6_stack true false localhost_cidr ip6_local >>= fun stack2 ->
  Stackv4v6.UDP.listen (Stackv4v6.udp stack2) ~port:1234 (fun ~src:_ ~dst:_ ~src_port:_ _cs -> Lwt.return_unit);
  Stackv4v6.disconnect stack2

let no_leak_fds_in_tcpv4v6_5 () =
  make_v4v6_stack false true localhost_cidr ip6_local >>= fun stack1 ->
  Stackv4v6.TCP.listen (Stackv4v6.tcp stack1) ~port:1234 (fun _flow -> Lwt.return_unit);
  Stackv4v6.disconnect stack1 >>= fun () ->
  make_v4v6_stack false true localhost_cidr ip6_local >>= fun stack2 ->
  Stackv4v6.TCP.listen (Stackv4v6.tcp stack2) ~port:1234 (fun _flow -> Lwt.return_unit);
  Stackv4v6.disconnect stack2

let no_leak_fds_in_udpv4v6_5 () =
  make_v4v6_stack false true localhost_cidr ip6_local >>= fun stack1 ->
  Stackv4v6.UDP.listen (Stackv4v6.udp stack1) ~port:1234 (fun ~src:_ ~dst:_ ~src_port:_ _cs -> Lwt.return_unit);
  Stackv4v6.disconnect stack1 >>= fun () ->
  make_v4v6_stack false true localhost_cidr ip6_local >>= fun stack2 ->
  Stackv4v6.UDP.listen (Stackv4v6.udp stack2) ~port:1234 (fun ~src:_ ~dst:_ ~src_port:_ _cs -> Lwt.return_unit);
  Stackv4v6.disconnect stack2

let suite = [
  "two sockets connect via TCP", `Quick, two_connect_tcp;
  "icmp echo-requests are sent", `Slow, icmp_echo_request;
  "file descriptors are not leaked in tcpv4", `Quick, no_leak_fds_in_tcpv4;
  "file descriptors are not leaked in udpv4", `Quick, no_leak_fds_in_udpv4;
  "file descriptors are not leaked in tcpv6", `Quick, no_leak_fds_in_tcpv6;
  "file descriptors are not leaked in udpv6", `Quick, no_leak_fds_in_udpv6;
  "file descriptors are not leaked in tcpv4v6 (any)", `Quick, no_leak_fds_in_tcpv4v6;
  "file descriptors are not leaked in udpv4v6 (any)", `Quick, no_leak_fds_in_udpv4v6;
  "file descriptors are not leaked in tcpv4v6 (v4)", `Quick, no_leak_fds_in_tcpv4v6_2;
  "file descriptors are not leaked in udpv4v6 (v4)", `Quick, no_leak_fds_in_udpv4v6_2;
  "file descriptors are not leaked in tcpv4v6 (v4v6)", `Quick, no_leak_fds_in_tcpv4v6_3;
  "file descriptors are not leaked in udpv4v6 (v4v6)", `Quick, no_leak_fds_in_udpv4v6_3;
  "file descriptors are not leaked in tcpv4v6 (v4 only)", `Quick, no_leak_fds_in_tcpv4v6_4;
  "file descriptors are not leaked in udpv4v6 (v4 only)", `Quick, no_leak_fds_in_udpv4v6_4;
  "file descriptors are not leaked in tcpv4v6 (v6 only)", `Quick, no_leak_fds_in_tcpv4v6_5;
  "file descriptors are not leaked in udpv4v6 (v6 only)", `Quick, no_leak_fds_in_udpv4v6_5;
]
