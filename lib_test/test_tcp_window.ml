open Lwt.Infix

module Clock = struct
  type error = string
  type t = { time: int64 }
  type 'a io = 'a Lwt.t
  let tick {time} = {time = Int64.add time 1L}
  let disconnect _ = Lwt.return_unit
  let connect () = Lwt.return { time = 0L }
  let period_ns _ = None
  let elapsed_ns {time} = time
end

module Timed_window = Tcp.Window.Make(Clock)

let default_window () =
  Tcp.Window.t ~tx_wnd_scale:2 ~rx_wnd_scale:2 ~rx_wnd:65535 ~tx_wnd:65535 ~rx_isn:Tcp.Sequence.zero ~tx_mss:(Some 1460) ~tx_isn:Tcp.Sequence.zero

let fresh_window () =
  let window = default_window () in
  Alcotest.(check bool) "should be no data in flight" false @@ Tcp.Window.tx_inflight window;
  Alcotest.(check bool) "no rexmits yet" false @@ Tcp.Window.max_rexmits_done window;
  Alcotest.(check int) "no traffic transferred yet" 0 @@ Tcp.Window.tx_totalbytes window;
  Alcotest.(check int) "no traffic received yet" 0 @@ Tcp.Window.rx_totalbytes window;
  Alcotest.(check int32) "should be able to send 65535 <<= 2 bytes" Int32.(mul 65535l 4l) @@ Tcp.Window.tx_wnd window;
  Alcotest.(check int32) "should be able to receive 65535 <<= 2 bytes" Int32.(mul 65535l 4l) @@ Tcp.Window.rx_wnd window;
  Alcotest.(check int64) "initial rto is 2/3 second" (Duration.of_ms 667) @@ Tcp.Window.rto window;
  Lwt.return_unit

let increase_congestion_window clock window goal =
  (* simulate a successful slow start, which primes the congestion window to be relatively large *)
  let receive_window = Tcp.Window.ack_win window in
  let rec successful_transmission goal =
    let max_send = Tcp.Window.tx_available window |> Tcp.Sequence.of_int32 in
    match Tcp.Sequence.geq max_send goal with
    | true -> max_send
    | false ->
      let sz = Tcp.Sequence.add max_send @@ Tcp.Window.tx_nxt window in
      let clock = Clock.tick clock in
      Timed_window.tx_advance clock window @@ Tcp.Window.tx_nxt window;
      let clock = Clock.tick clock in
      (* need to acknowledge the full size of the data *)
      Timed_window.tx_ack clock window sz receive_window;
      successful_transmission goal
  in
  (clock, successful_transmission goal)

let n_segments window n =
  Int32.mul n @@ Int32.of_int @@ Tcp.Window.tx_mss window |> Tcp.Sequence.of_int32

(* attempt to ensure that fast recovery is working as described in rfc5681 *)
let recover_fast () =
  let window = default_window () in
  Clock.connect () >>= fun clock ->
  let receive_window = Tcp.Window.ack_win window in
  Alcotest.(check bool) "don't start in fast recovery" false @@ Tcp.Window.fast_rec window;

  (* get a large congestion window to avoid confounding factors *)
  let cwnd_goal = 262140l in
  let clock, _ = increase_congestion_window clock window (Tcp.Sequence.of_int32 cwnd_goal) in
  let available_to_send = Tcp.Window.tx_available window in
  let big_enough x = Int32.compare x cwnd_goal > 0 in
  Alcotest.(check bool) "congestion window is big enough" true @@ big_enough available_to_send;

  (* get ready to send another burst of data *)
  let seq = Tcp.Window.tx_nxt window in
  let clock = Clock.tick clock in
  (* say that we sent the full amount of data *)
  let sz = Tcp.Sequence.(add (of_int32 available_to_send) seq) in
  Timed_window.tx_advance clock window @@ sz;
  (* but receive an ack indicating that we missed a segment *)
  let nonfull_ack = Tcp.Sequence.add seq @@ n_segments window 4l in
  (* 1st ack *)
  let clock = Clock.tick clock in
  Timed_window.tx_ack clock window nonfull_ack receive_window;
  (* 1st duplicate ack *)
  let clock = Clock.tick clock in
  Timed_window.tx_ack clock window nonfull_ack receive_window;
  (* 2nd duplicate ack *)
  let clock = Clock.tick clock in
  Timed_window.tx_ack clock window nonfull_ack receive_window;
  (* 3rd duplicate ack *)
  let clock = Clock.tick clock in
  Timed_window.tx_ack clock window nonfull_ack receive_window;
  (* request that we go into fast retransmission *)
  Tcp.Window.alert_fast_rexmit window @@ n_segments window 4l;

  Alcotest.(check bool) "fast retransmit when we wanted it" true @@ Tcp.Window.fast_rec window;

  Alcotest.(check bool) "once entering fast recovery, we can send >0 packets" true ((Int32.compare (Tcp.Window.tx_available window) 0l) > 0);

  Lwt.return_unit
  
let suite = [
  "fresh window is sensible", `Quick, fresh_window;
  "fast recovery recovers fast", `Quick, recover_fast;
]
