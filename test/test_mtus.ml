open Lwt.Infix

module Server = struct
  let ip = Ipaddr.V4.of_string_exn "192.168.1.254"
  let netmask = 24
  let gateway = None
end

module Client = struct
  let ip = Ipaddr.V4.of_string_exn "192.168.1.10"
  let netmask = 24
  let gateway = None
end

let server_port = 7

module Backend = Vnetif_backends.Mtu_enforced
module Stack = Vnetif_common.VNETIF_STACK(Backend)

let default_mtu = 1500

let err_fail e =
  let err = Format.asprintf "%a" Stack.Stackv4.TCPV4.pp_error e in
  Alcotest.fail err

let write_err_fail e =
  let err = Format.asprintf "%a" Stack.Stackv4.TCPV4.pp_write_error e in
  Alcotest.fail err

let rec read_all flow so_far =
  Stack.Stackv4.TCPV4.read flow >>= function
  | Error e -> err_fail e
  | Ok `Eof -> Lwt.return @@ List.rev so_far
  | Ok (`Data s) -> read_all flow (s :: so_far)

let read_one flow =
  Stack.Stackv4.TCPV4.read flow >>= function
  | Error e -> err_fail e
  | Ok `Eof -> Alcotest.fail "received EOF when we expected at least some data from read"
  | Ok (`Data s) -> Lwt.return s

let get_stacks ?client_mtu ?server_mtu backend =
  let or_default = function | None -> default_mtu | Some n -> n in
  let client_mtu, server_mtu = or_default client_mtu, or_default server_mtu in
  Client.(Stack.create_stack backend ~mtu:client_mtu ip netmask gateway) >>= fun client ->
  Server.(Stack.create_stack backend ~mtu:server_mtu ip netmask gateway) >>= fun server ->
  let max_mtu = max client_mtu server_mtu in
  Backend.set_mtu max_mtu;
  Lwt.return (server, client)

let start_server ~f server =
  Stack.Stackv4.listen_tcpv4 server ~port:server_port f;
  Stack.Stackv4.listen server

let start_client client =
  Stack.Stackv4.TCPV4.create_connection (Stack.Stackv4.tcpv4 client) (Server.ip, server_port) >>= function
  | Ok connection -> Lwt.return connection
  | Error e -> err_fail e

let connect () =
  let backend = Backend.create () in
  get_stacks ~server_mtu:9000 backend >>= fun (server, client) ->
  Lwt.async (fun () -> start_server ~f:(fun _ -> Lwt.return_unit) server);
  start_client client >>= fun flow ->
    Stack.Stackv4.TCPV4.close flow

let big_server_response () =
  let response = Cstruct.create 7000 in
  Cstruct.memset response 255;
  let backend = Backend.create () in
  get_stacks ~client_mtu:1500 ~server_mtu:9000 backend >>= fun (server, client) ->
  let f flow =
    Stack.Stackv4.TCPV4.write flow response >>= function
    | Error e -> write_err_fail e
    | Ok () -> Stack.Stackv4.TCPV4.close flow
  in
  Lwt.async (fun () -> start_server ~f server);
  start_client client >>= fun flow -> read_all flow [] >>= fun l ->
  Alcotest.(check int) "received size matches sent size" (Cstruct.len response) (Cstruct.len (Cstruct.concat l));
  Stack.Stackv4.TCPV4.close flow

let big_client_request_chunked () =
  let request = Cstruct.create 3750 in
  Cstruct.memset request 255;
  let backend = Backend.create () in
  get_stacks ~client_mtu:1500 ~server_mtu:9000 backend >>= fun (server, client) ->
  let f flow =
    Stack.Stackv4.TCPV4.write flow request >>= function
    | Error e -> write_err_fail e
    | Ok () -> Stack.Stackv4.TCPV4.close flow
  in
  Lwt.async (fun () -> start_server ~f:(fun _flow -> Lwt.return_unit) server);
  start_client client >>= f

let big_server_response_not_chunked () =
  let response = Cstruct.create 7000 in
  Cstruct.memset response 255;
  let backend = Backend.create () in
  get_stacks ~client_mtu:9000 ~server_mtu:9000 backend >>= fun (server, client) ->
  let f flow =
    Stack.Stackv4.TCPV4.write flow response >>= function
    | Error e -> write_err_fail e
    | Ok () -> Stack.Stackv4.TCPV4.close flow
  in
  Lwt.async (fun () -> start_server ~f server);
  start_client client >>= fun flow -> read_one flow >>= fun buf ->
  Alcotest.(check int) "received size matches sent size" (Cstruct.len response) (Cstruct.len buf);
  Stack.Stackv4.TCPV4.close flow

let long_comms amt timeout () =
  (* use the iperf tests to test long-running communication between
   * the two stacks with their different link settings.
   * this helps us find bugs in situations like the TCP window expanding
   * to be larger than the MTU, and the implementation failing to 
   * limit the size of the sent packet in that case. *)
  let module Test = Test_iperf.Test_iperf(Backend) in
  let backend = Backend.create () in
  get_stacks ~client_mtu:1500 ~server_mtu:9000 backend >>= fun (server, client) ->
  Test.V.record_pcap backend
    (Printf.sprintf "tcp_mtus_long_comms_%d.pcap" amt)
    (Test.tcp_iperf ~server ~client amt timeout)

let suite = [
  "connections work", `Quick, connect;
  "large server responses are received", `Quick, big_server_response;
  "large client requests are chunked properly", `Quick, big_client_request_chunked;
  "large messages aren't unnecessarily segmented", `Quick, big_server_response_not_chunked;
  "iperf test doesn't crash", `Quick, long_comms Test_iperf.amt_quick 120.0;
]
