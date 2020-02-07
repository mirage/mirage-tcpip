
let src =
  let src = Logs.Src.create "ping" ~doc:"Mirage ping" in
  Logs.Src.set_level src (Some Logs.Info);
  src

module Log = (val Logs.src_log src : Logs.LOG)

(* Construct a payload buffer of a given size *)
let make_payload ~size () =
  let buf = Cstruct.create size in
  let pattern = "plz reply i'm so lonely" in
  for i = 0 to Cstruct.len buf - 1 do
    Cstruct.set_char buf i pattern.[i mod (String.length pattern)]
  done;
  buf

let seq_no_to_send_time = Hashtbl.create 7
let nr_transmitted = ref 0
let nr_received = ref 0

let min_ms = ref max_float
let max_ms = ref 0.
(* to compute the standard deviation, we store the sum and the sum of squares *)
let sum_ms = ref 0.
let sum_ms_2 = ref 0.

(* Send ICMP ECHO_REQUEST packets forever *)
let send_echo_requests ~stack ~payload ~dst () =
  let rec send seq_no =
    let open Lwt.Infix in
    let id_no = 0x1234 in
    let req = Icmpv4_packet.({code = 0x00; ty = Icmpv4_wire.Echo_request;
                              subheader = Id_and_seq (id_no, seq_no)}) in
    let header = Icmpv4_packet.Marshal.make_cstruct req ~payload in
    let echo_request = Cstruct.concat [ header; payload ] in
    Log.debug (fun f -> f "Sending ECHO_REQUEST id_no=%d seq_no=%d to %s" id_no seq_no (Ipaddr.V4.to_string dst));
    Icmpv4_socket.write stack ~dst echo_request
    >>= function
    | Ok () ->
      Hashtbl.replace seq_no_to_send_time seq_no (Unix.gettimeofday ());
      incr nr_transmitted;
      Lwt_unix.sleep 1.
      >>= fun () ->
      send (seq_no + 1)
    | Error e ->
      Log.err (fun f -> f "Error sending ICMP to %s: %a" (Ipaddr.V4.to_string dst) Icmpv4_socket.pp_error e);
      Lwt.return_unit in
  send 0

(* Return a thread and a receiver callback. The thread is woken up when we have
   received [count] packets *)
let make_receiver ~count ~payload () =
  let finished_t, finished_u = Lwt.task () in
  let callback buf =
    Log.debug (fun f -> f "Received IP %a" Cstruct.hexdump_pp buf);
    match Ipv4_packet.Unmarshal.of_cstruct buf with
    | Error msg ->
      Log.err (fun f -> f "Error unmarshalling IP datagram: %s" msg);
      Lwt.return_unit
    | Ok (ip, ip_payload) ->
      match Icmpv4_packet.Unmarshal.of_cstruct ip_payload with
      | Error msg ->
        Log.err (fun f -> f "Error unmarshalling ICMP message: %s" msg);
        Lwt.return_unit
      | Ok (reply, received_payload) ->
        let open Icmpv4_packet in
        begin match reply.subheader with
          | Next_hop_mtu _ | Pointer _ | Address _ | Unused ->
            Log.err (fun f -> f "received an ICMP message which wasn't an echo-request or reply");
            Lwt.return_unit
          | Id_and_seq (_id, seq) ->
            if reply.code <> 0
            then Log.err (fun f -> f "received an ICMP ECHO_REQUEST with reply.code=%d" reply.code);
            if not(Cstruct.equal payload received_payload)
            then Log.err (fun f -> f "received an ICMP ECHO_REQUEST with an unexpected payload");
            if not(Hashtbl.mem seq_no_to_send_time seq)
            then Log.err (fun f -> f "received an ICMP ECHO_REQUEST with an unexpected sequence number")
            else begin
              let secs = Unix.gettimeofday () -. (Hashtbl.find seq_no_to_send_time seq) in
              Hashtbl.remove seq_no_to_send_time seq;
              let ms = secs *. 1000.0 in
              Printf.printf "%d bytes from %s: icmp_seq=%d ttl=%d time=%f ms\n%!"
                (Cstruct.len payload) (Ipaddr.V4.to_string ip.Ipv4_packet.src) seq ip.Ipv4_packet.ttl ms;
              incr nr_received;
              min_ms := min !min_ms ms;
              max_ms := max !max_ms ms;
              sum_ms := !sum_ms +. ms;
              sum_ms_2 := !sum_ms_2 +. (ms *. ms);
              if Some !nr_received = count then begin
                Log.debug (fun f -> f "Finished after %d packets received" !nr_received);
                Lwt.wakeup_later finished_u ();
              end
            end;
            Lwt.return_unit
          end in
        finished_t, callback

let ping (count:int option) (size:int) (timeout:int option) dst =
  let dst = Ipaddr.V4.of_string_exn dst in
  Lwt_main.run begin
    let open Lwt.Infix in
    let payload = make_payload ~size () in
    Icmpv4_socket.connect ()
    >>= fun stack ->
    let finished, on_icmp_receive = make_receiver ~count ~payload () in
    let me = Ipaddr.V4.any in
    let listener = Icmpv4_socket.listen stack me on_icmp_receive in
    let timeout = match timeout with
      | None ->
        let forever, _ = Lwt.task () in
        forever
      | Some t ->
        Lwt_unix.sleep (float_of_int t)
        >>= fun () ->
        Log.debug (fun f -> f "Timed-out");
        Lwt.return_unit in
    let sender = send_echo_requests ~stack ~payload ~dst () in
    let interrupted, interrupted_u = Lwt.task () in
    ignore(Lwt_unix.on_signal Sys.sigint (fun _ -> Lwt.wakeup_later interrupted_u ()));
    Lwt.pick [
      finished;
      timeout;
      interrupted;
      listener;
      sender;
    ]
    >>= fun () ->
    Printf.printf "--- %s ping statistics ---\n" (Ipaddr.V4.to_string dst);
    let n = float_of_int (!nr_received) in
    let percent_loss = 100. *. (float_of_int (!nr_transmitted) -. n) /. (float_of_int (!nr_transmitted)) in
    Printf.printf "%d packets transmitted, %d packets received, %0.0f%% packet loss\n"
      !nr_transmitted !nr_received percent_loss;
    let avg_ms = !sum_ms /. n in
    let variance_ms = 1. /. (n -. 1.) *. (!sum_ms_2) -. 1. /. (n *. (n -. 1.)) *. (!sum_ms) *. (!sum_ms) in
    let stddev_ms = sqrt variance_ms in
    Printf.printf "round-trip min/avg/max/stddev = %.03f/%.03f/%.03f/%.03f ms\n"
      !min_ms avg_ms !max_ms stddev_ms;
    Lwt.return (`Ok ())
  end

open Cmdliner

let exit_after_success =
  let doc = "Exit successfully after receiving one reply packet." in
  Arg.(value & flag & info [ "o" ] ~doc)

let count =
  let doc = "Stop after sending (and receiving) count ECHO_RESPONSE packets. If not specified, ping will continue until interrupted." in
  Arg.(value & opt (some int) None & info [ "c" ] ~doc)

let size =
  let doc = "Specify the number of data bytes to be sent." in
  Arg.(value & opt int 56 & info [ "s" ] ~doc)

let timeout =
  let doc = "Specify a timeout, before ping exits regardless of how many packets have been received." in
  Arg.(value & opt (some int) None & info [ "t" ] ~doc)

let destination =
  let doc ="Hostname or IP address of destination host" in
  Arg.(value & pos 0 string "" & info [] ~doc)

let cmd =
  let doc = "Send ICMP ECHO_REQUEST packets and listen for ECHO_RESPONSES" in
  let man = [
    `S "DESCRIPTION";
    `P "Send a sequence of ICMP ECHO_REQUEST packets to a network host and count the responses. When the program exits, display some statistics.";
  ] in
  Term.(ret(pure ping $ count $ size $ timeout $ destination)),
  Term.info "ping" ~doc ~man

let _ =
  Logs.set_reporter (Logs_fmt.reporter ());
  match Term.eval cmd with
  | `Error _ -> exit 1
  | _ -> exit 0
