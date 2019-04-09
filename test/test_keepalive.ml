(* Test the functional part *)

(* Linux default *)
let default = Mirage_protocols.Keepalive.({
  after = Duration.of_sec 7200; (* 2 hours *)
  interval = Duration.of_sec 75; (* 75 seconds *)
  probes = 9;
})

let simulate configuration iterations nprobes ns state =
  let rec loop iterations nprobes ns state =
    if iterations > 3 * configuration.Mirage_protocols.Keepalive.probes
    then Alcotest.fail (Printf.sprintf "too many iteractions: loop in keep-alive test? iterations = %d nprobes = %d ns=%Ld" iterations nprobes ns);
    let action, state' = Tcp.Keepalive.next ~configuration ~ns state in
    match action with
    | `SendProbe ->
      Logs.info (fun f -> f "iteration %d, ns %Ld: SendProbe" iterations ns);
      loop (iterations + 1) (nprobes + 1) ns state'
    | `Wait ns' ->
      Logs.info (fun f -> f "iteration %d, ns %Ld: Wait %Ld" iterations ns ns');
      loop (iterations + 1) nprobes (Int64.add ns ns') state'
    | `Close ->
      Logs.info (fun f -> f "iteration %d, ns %Ld: Close" iterations ns);
      nprobes in
  loop iterations nprobes ns state

(* check we send the expected number of probes if everything does as expected *)
let test_keepalive_sequence () =
  let configuration = default in
  let state = Tcp.Keepalive.alive in
  let nprobes = simulate configuration 0 0 0L state in
  Alcotest.(check int) "number of probes" (configuration.probes) nprobes

(* check what happens if we miss a probe *)
let test_keepalive_miss_probes () =
  let configuration = default in
  let state = Tcp.Keepalive.alive in
  (* skip sending the first 1 or 2 probes *)
  let ns = Int64.(add configuration.Mirage_protocols.Keepalive.after (mul 2L configuration.Mirage_protocols.Keepalive.interval)) in
  let nprobes = simulate configuration 0 0 ns state in
  if nprobes >= configuration.Mirage_protocols.Keepalive.probes
  then Alcotest.fail (Printf.sprintf "too many probes: max was %d but we sent %d and we should have skipped the first 1 or 2" configuration.probes nprobes)

(* check what happens if we exceed the maximum timeout *)
let test_keepalive_miss_everything () =
  let configuration = default in
  let state = Tcp.Keepalive.alive in
  (* massive delay *)
  let ns = Int64.(add configuration.Mirage_protocols.Keepalive.after (mul 2L (mul (of_int configuration.Mirage_protocols.Keepalive.probes) configuration.Mirage_protocols.Keepalive.interval))) in
  let nprobes = simulate configuration 0 0 ns state in
  if nprobes <> 0
  then Alcotest.fail (Printf.sprintf "too many probes: max was %d but we sent %d and we should have skipped all" configuration.probes nprobes)

let suite_1 = [
  "correct number of keepalives", `Quick, test_keepalive_sequence;
  "we don't try to send old keepalives", `Quick, test_keepalive_miss_probes;
  "check we close if we miss all probes", `Slow, test_keepalive_miss_everything;
]

let suite_1 =
  List.map (fun (n, s, f) -> n, s, (fun () -> Lwt.return (f ()))) suite_1

(* Test the end-to-end protocol behaviour *)
open Common
open Vnetif_common

let (>>=) = Lwt.(>>=)

let src = Logs.Src.create "test_keepalive" ~doc:"keepalive tests"
module Log = (val Logs.src_log src : Logs.LOG)

(* Establish a TCP connection, enable keepalives on the connection, tell the network
   to drop all packets and check that the keep-alives detect the failure. *)
module Test_connect = struct
  module V = VNETIF_STACK (Vnetif_backends.On_off_switch)

  let netmask = 24
  let gw = Some (Ipaddr.V4.of_string_exn "10.0.0.1")
  let client_ip = Ipaddr.V4.of_string_exn "10.0.0.101"
  let server_ip = Ipaddr.V4.of_string_exn "10.0.0.100"
  let backend = V.create_backend ()

  let err_read_eof () = failf "accept got EOF while reading"
  let err_write_eof () = failf "client tried to write, got EOF"

  let err_read e =
    let err = Format.asprintf "%a" V.Stackv4.TCPV4.pp_error e in
    failf "Error while reading: %s" err

  let accept flow =
    let ip, port = V.Stackv4.TCPV4.dst flow in
    Logs.debug (fun f -> f "Accepted connection from %s:%d" (Ipaddr.V4.to_string ip) port);
    V.Stackv4.TCPV4.read flow >>= function
    | Error e      -> err_read e
    | Ok `Eof      -> Lwt.return_unit
    | Ok (`Data _) -> failf "accept: expected to get EOF in read, but got data"

  let test_tcp_keepalive_timeout () =
    let timeout = 15.0 in
    Lwt.pick [
      (Lwt_unix.sleep timeout >>= fun () ->
        failf "connect test timedout after %f seconds" timeout) ;

      (V.create_stack backend server_ip netmask gw >>= fun s1 ->
        V.Stackv4.listen_tcpv4 s1 ~port:80 (fun f -> accept f);
        V.Stackv4.listen s1) ;

      (Lwt_unix.sleep 0.1 >>= fun () ->
        V.create_stack backend client_ip netmask gw >>= fun s2 ->
        Lwt.pick [
        V.Stackv4.listen s2;
        let keepalive = { Mirage_protocols.Keepalive.after = 0L; interval = Duration.of_sec 1; probes = 3 } in
        (let conn = V.Stackv4.TCPV4.create_connection ~keepalive (V.Stackv4.tcpv4 s2) in
        or_error "connect" conn (server_ip, 80) >>= fun flow ->
        Logs.debug (fun f -> f "Connected to other end...");
        Vnetif_backends.On_off_switch.send_packets := false;
        V.Stackv4.TCPV4.read flow  >>= function
        | Error e      -> err_read e
        | Ok (`Data _) -> failf "read: expected to get EOF, but got data"
        | Ok `Eof ->
          Logs.debug (fun f -> f "connection read EOF as expected");
          V.Stackv4.TCPV4.close flow >>= fun () ->
          Lwt_unix.sleep 1.0 >>= fun () -> (* record some traffic after close *)
          Lwt.return_unit)]) ] >>= fun () ->

    Lwt.return_unit

  let record_pcap =
    V.record_pcap backend

end

let test_tcp_keepalive_timeout () =
  Test_connect.record_pcap
    "test_tcp_keepalive_timeout.pcap"
    Test_connect.test_tcp_keepalive_timeout

let suite_2 = [
  "check that TCP keepalives detect a network failure", `Slow,
  test_tcp_keepalive_timeout;
]

let suite = suite_1 @ suite_2
