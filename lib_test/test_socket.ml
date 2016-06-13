open Lwt.Infix

module Stack = Tcpip_stack_socket.Make(Console_unix)

type stack_stack = {
  console : Console_unix.t;
  stack : Stack.t;
  icmp  : Icmpv4_socket.t;
  udp   : Udpv4_socket.t;
  tcp   : Tcpv4_socket.t;
}

let or_fail f args =
  f args >>= function
  | `Ok p -> Lwt.return p
  | `Error s -> Alcotest.fail s

let or_fail_str ~str f args =
  f args >>= function
  | `Ok p -> Lwt.return p
  | `Error _ -> Alcotest.fail str

let localhost = Ipaddr.V4.of_string_exn "127.0.0.1"

let make_stack ~name ~ip =
  Console_unix.connect "test_socket" >>= function
  | `Error (`Invalid_console s) -> Alcotest.fail s
  | `Ok console ->
  (* define a config record, which should match the type expected of
     V1_LWT.stackv4_config *)
  or_fail_str ~str:"error initializing TCP socket" Tcpv4_socket.connect (Some ip) >>= fun tcp ->
  or_fail Udpv4_socket.connect (Some ip) >>= fun udp ->
  let open V1_LWT in
  let config = {
    name;
    console;
    interface = [ip];
    mode = ();
  } in
  Icmpv4_socket.connect () >>= fun icmp ->
  or_fail_str ~str:"stack initialization failed" (Stack.connect config udp) tcp >>= fun stack ->
  Lwt.return { console; stack; icmp; udp; tcp }

let two_connect_tcp () =
  let announce flow =
    Tcpv4_socket.read flow >>= function
    | `Eof -> Printf.printf "EOF!"; Lwt.return_unit
    | `Error _ -> Printf.printf "Error reading!"; Alcotest.fail "Error reading TCP flow"
    | `Ok buf -> Printf.printf "Buffer received: %s\n%!" (Cstruct.to_string buf);
      Lwt.return_unit
  in
  let server_port = 14041 in
  make_stack ~name:"server" ~ip:localhost >>= fun server ->
  make_stack ~name:"client" ~ip:localhost >>= fun client ->

  Stack.listen_tcpv4 server.stack server_port announce;
  Lwt.pick [
    Stack.listen server.stack;
    or_fail_str ~str:"couldn't create connection from client to server for TCP socket test"
      (Stack.TCPV4.create_connection client.tcp) (localhost, server_port) >>= fun flow ->
    Stack.TCPV4.write flow (Cstruct.of_string "test!") >>= function
    | `Ok () -> Stack.TCPV4.close flow
    | `Error _ -> Alcotest.fail "Error writing to socket for TCP test"
    | `Eof -> Alcotest.fail "premature EOF - client couldn't write to TCP socket"
  ]

let icmp_echo_request () =
  make_stack ~name:"server" ~ip:localhost >>= fun server ->
  make_stack ~name:"client" ~ip:localhost >>= fun client ->
  let echo_request = Icmpv4_print.echo_request 0x40 0x10 in
  let received_icmp = ref 0 in
  Lwt.pick [
    Icmpv4_socket.listen server localhost (fun buf -> received_icmp :=
                                              !received_icmp + 1;
                                                             Lwt.return_unit);
    OS.Time.sleep 0.5 >>= fun () -> Icmpv4_socket.write client ~dst:localhost echo_request 
  ] >>= fun () -> Alcotest.(check int) "number of ICMP packets received by listener"  1
    !received_icmp; Lwt.return_unit

let suite = [
  "two sockets connect via TCP", `Quick, two_connect_tcp;
  "icmp echo-requests are sent", `Quick, icmp_echo_request;
]
