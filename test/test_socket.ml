open Lwt.Infix

module Time = Vnetif_common.Time

let or_fail_str ~str f args =
  f args >>= function
  | `Ok p -> Lwt.return p
  | `Error _ -> Alcotest.fail str

let localhost = Ipaddr.V4.of_string_exn "127.0.0.1"
let localhost_cidr = Ipaddr.V4.Prefix.make 32 localhost

module Stackv4v6 = Tcpip_stack_socket.V4V6

let make_v4v6_stack ipv4_only ipv6_only ipv4 ipv6 =
  Tcpv4v6_socket.connect ~ipv4_only ~ipv6_only ipv4 ipv6 >>= fun tcp ->
  Udpv4v6_socket.connect ~ipv4_only ~ipv6_only ipv4 ipv6 >>= fun udp ->
  Stackv4v6.connect udp tcp >|= fun stack ->
  stack

let ip4_any = Ipaddr.V4.Prefix.global (* 0.0.0.0/0 *)

let two_connect_tcp () =
  let announce flow =
    Tcpv4v6_socket.read flow >>= function
    | Error _ -> Printf.printf "Error reading!"; Alcotest.fail "Error reading TCP flow"
    | Ok `Eof -> Printf.printf "EOF!"; Lwt.return_unit
    | Ok (`Data buf) -> Printf.printf "Buffer received: %s\n%!" (Cstruct.to_string buf);
      Lwt.return_unit
  in
  let server_port = 14041 in
  make_v4v6_stack true false localhost_cidr None >>= fun server ->
  make_v4v6_stack true false localhost_cidr None >>= fun client ->
  let teardown () =
    Stackv4v6.disconnect server >>= fun () ->
    Stackv4v6.disconnect client
  in

  Stackv4v6.TCP.listen (Stackv4v6.tcp server) ~port:server_port announce;
  Lwt.pick [
    Stackv4v6.listen server;
    Stackv4v6.TCP.create_connection (Stackv4v6.tcp client) (Ipaddr.V4 localhost, server_port) >|= Result.get_ok >>= fun flow ->
    Stackv4v6.TCP.write flow (Cstruct.of_string "test!") >>= function
    | Ok () -> Stackv4v6.TCP.close flow >>= fun () -> teardown ()
    | Error _ -> teardown () >>= fun () -> Alcotest.fail "Error writing to socket for TCP test"
  ]

let icmp_echo_request () =
  Icmpv4_socket.connect () >>= fun server ->
  Icmpv4_socket.connect () >>= fun client ->
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
    Icmpv4_socket.listen server localhost log_and_count;
    Time.sleep_ns (Duration.of_ms 500) >>= fun () ->
    Icmpv4_socket.write client ~dst:localhost echo_request >|= Result.get_ok >>= fun () ->
    Time.sleep_ns (Duration.of_sec 10);
  ] >>= fun () ->
  Icmpv4_socket.disconnect server >>= fun () ->
  Icmpv4_socket.disconnect client >|= fun () ->
  Alcotest.(check int) "number of ICMP packets received by listener"
    1 !received_icmp

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
