open Lwt.Infix

let server_cidr = Ipaddr.V4.Prefix.of_string_exn "192.168.1.254/24"
let client_cidr = Ipaddr.V4.Prefix.of_string_exn "192.168.1.10/24"

let server_port = 7

module Backend = Vnetif_backends.Frame_size_enforced
module Stack = Vnetif_common.VNETIF_STACK(Backend)

let default_mtu = 1500

let err_fail e =
  let err = Format.asprintf "%a" Stack.Stack.TCP.pp_error e in
  Alcotest.fail err

let write_err_fail e =
  let err = Format.asprintf "%a" Stack.Stack.TCP.pp_write_error e in
  Alcotest.fail err

let rec read_all flow so_far =
  Stack.Stack.TCP.read flow >>= function
  | Error e -> err_fail e
  | Ok `Eof -> Lwt.return @@ List.rev so_far
  | Ok (`Data s) -> read_all flow (s :: so_far)

let read_one flow =
  Stack.Stack.TCP.read flow >>= function
  | Error e -> err_fail e
  | Ok `Eof -> Alcotest.fail "received EOF when we expected at least some data from read"
  | Ok (`Data s) -> Lwt.return s

let get_stacks ?client_mtu ?server_mtu backend =
  let or_default = function | None -> default_mtu | Some n -> n in
  let client_mtu, server_mtu = or_default client_mtu, or_default server_mtu in
  Stack.create_stack ~cidr:client_cidr ~mtu:client_mtu backend >>= fun client ->
  Stack.create_stack ~cidr:server_cidr ~mtu:server_mtu backend >>= fun server ->
  let max_mtu = max client_mtu server_mtu in
  Backend.set_max_ip_mtu backend max_mtu;
  Lwt.return (server, client)

let start_server ~f server =
  Stack.Stack.TCP.listen (Stack.Stack.tcp server) ~port:server_port f;
  Stack.Stack.listen server

let start_client client =
  Stack.Stack.TCP.create_connection (Stack.Stack.tcp client) (Ipaddr.V4 (Ipaddr.V4.Prefix.address server_cidr), server_port) >>= function
  | Ok connection -> Lwt.return connection
  | Error e -> err_fail e

let connect () =
  let backend = Backend.create () in
  get_stacks ~server_mtu:9000 backend >>= fun (server, client) ->
  Lwt.async (fun () -> start_server ~f:(fun _ -> Lwt.return_unit) server);
  start_client client >>= fun flow ->
  Stack.Stack.TCP.close flow

let big_server_response () =
  let response = Cstruct.create 7000 in
  Cstruct.memset response 255;
  let backend = Backend.create () in
  get_stacks ~client_mtu:1500 ~server_mtu:9000 backend >>= fun (server, client) ->
  let f flow =
    Stack.Stack.TCP.write flow response >>= function
    | Error e -> write_err_fail e
    | Ok () -> Stack.Stack.TCP.close flow
  in
  Lwt.async (fun () -> start_server ~f server);
  start_client client >>= fun flow -> read_all flow [] >>= fun l ->
  Alcotest.(check int) "received size matches sent size" (Cstruct.length response) (Cstruct.length (Cstruct.concat l));
  Stack.Stack.TCP.close flow

let big_client_request_chunked () =
  let request = Cstruct.create 3750 in
  Cstruct.memset request 255;
  let backend = Backend.create () in
  get_stacks ~client_mtu:1500 ~server_mtu:9000 backend >>= fun (server, client) ->
  let f flow =
    Stack.Stack.TCP.write flow request >>= function
    | Error e -> write_err_fail e
    | Ok () -> Stack.Stack.TCP.close flow
  in
  Lwt.async (fun () -> start_server ~f:(fun _flow -> Lwt.return_unit) server);
  start_client client >>= f

let big_server_response_not_chunked () =
  let response = Cstruct.create 7000 in
  Cstruct.memset response 255;
  let backend = Backend.create () in
  get_stacks ~client_mtu:9000 ~server_mtu:9000 backend >>= fun (server, client) ->
  let f flow =
    Stack.Stack.TCP.write flow response >>= function
    | Error e -> write_err_fail e
    | Ok () -> Stack.Stack.TCP.close flow
  in
  Lwt.async (fun () -> start_server ~f server);
  start_client client >>= fun flow -> read_one flow >>= fun buf ->
  Alcotest.(check int) "received size matches sent size" (Cstruct.length response) (Cstruct.length buf);
  Stack.Stack.TCP.close flow

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
