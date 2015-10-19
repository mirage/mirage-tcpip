module No_time : sig
  include V1_LWT.TIME
end = struct
  type 'a io = 'a Lwt.t
  let sleep _ = Lwt.return_unit
end
module Tricky_time : sig
  include V1_LWT.TIME
  val wake : unit -> unit
end = struct
  type 'a io = 'a Lwt.t
  let u = ref None
  let rec sleep time =
    let open Lwt.Infix in
    let (sleeper, wakener) = Lwt.wait () in
    u := Some wakener;
    sleeper >>= fun _ -> Lwt.return_unit
  let wake () =
    match !u with
    | Some wakener -> Lwt.wakeup wakener ()
    | None -> ()
end

module Timeless_state = Tcp.State.Make(No_time)
module Tricky_state = Tcp.State.Make(Tricky_time)
open Tcp.State

let get_closed () = start ~on_close:(fun _ -> ())
let seq n = Tcp.Sequence.of_int n
let random_item l =
  Random.self_init ();
  let i = Random.int (List.length l) in
  List.nth l i

(* disregarding sequence numbers, is this a valid transition? *)
let valid left right =
  match left, right with
  | Closed, Syn_sent _ -> true
  | Closed, Listen -> true
  | Syn_sent _, Closed -> true
  | Syn_sent _, Syn_rcvd _-> true
  | Syn_sent _, Established -> true
  | Syn_rcvd _, Listen -> true
  | Syn_rcvd _, Established -> true
  | Syn_rcvd _, Fin_wait_1 _ -> true
  | Established, Fin_wait_1 _ -> true
  | Established, Close_wait -> true
  | Fin_wait_1 _, Closing _ -> true
  | Fin_wait_1 _, Time_wait -> true
  | Fin_wait_1 _, Fin_wait_2 -> true
  | Fin_wait_2 , Time_wait -> true
  | Closing _, Time_wait -> true
  | Time_wait, Closed -> true
  | Close_wait, Last_ack _ -> true
  | Last_ack _, Closed -> true
  | left, right when left = right -> true (* maintaining state is always valid *)
  | _, _ -> false

(* given a sequence number, generate a list of possible actions (with that
   sequence number if sequence numbers are applicable) *)
let actions s = [
  Passive_open
; Recv_rst
; Recv_synack s
; Recv_ack s
; Recv_fin
; Send_syn s
; Send_synack s
; Send_rst
; Send_fin s
; Timeout
]

let states s = [
    Closed
  ; Listen
  ; Syn_rcvd s
  ; Syn_sent s
  ; Established
  ; Close_wait
  ; Last_ack s
  ; Fin_wait_1 s
  ; Fin_wait_2
  ; Closing s
  ; Time_wait
]

let state_diff formatter (expected, actual) =
  Format.pp_print_string formatter "expected state:";
  pp_tcpstate formatter expected;
  Format.print_newline ();
  Format.pp_print_string formatter "actual state:";
  pp_tcpstate formatter actual

let state_is t s =
  let actual_state = state t in
  OUnit.assert_equal ~pp_diff:state_diff s actual_state

let rec get_to = function
  | Closed -> get_closed ()
  | Listen ->
    let t = get_closed () in
    Timeless_state.tick t Passive_open;
    state_is t Listen;
    t
  | Syn_sent s ->
    let t = get_closed () in
    Timeless_state.tick t (Send_syn s);
    state_is t (Syn_sent s);
    t
  | Syn_rcvd s ->
    let t = get_closed () in
    Timeless_state.tick t Passive_open;
    Timeless_state.tick t (Send_synack s);
    state_is t (Syn_rcvd s);
    t
  | Established ->
    let s = 0xabad1dea in
    let sa = s + 1 in
    let t = get_closed () in
    Timeless_state.tick t (Send_syn (seq s));
    Timeless_state.tick t (Recv_synack (seq sa));
    state_is t Established;
    t
  | Fin_wait_1 s ->
    let t = get_to Established in
    Tricky_state.tick t (Send_fin s);
    state_is t (Fin_wait_1 s);
    t
  | Fin_wait_2 ->
    let t = get_to (Fin_wait_1 (seq 0xabad1dea)) in
    Timeless_state.tick t (Recv_ack (seq (0xabad1dea + 1)));
    state_is t Fin_wait_2;
    t
  | Closing s ->
    let t = get_to (Fin_wait_1 s) in
    Tricky_state.tick t Recv_fin;
    state_is t (Closing s);
    t
  | Time_wait ->
    let t = get_to Fin_wait_2 in
    Tricky_state.tick t Recv_fin;
    state_is t Time_wait;
    t
  | Close_wait ->
    let t = get_to Established in
    Tricky_state.tick t Recv_fin;
    state_is t Close_wait;
    t
  | Last_ack s ->
    let t = get_to Close_wait in
    Tricky_state.tick t (Send_fin s);
    state_is t (Last_ack s);
    t

let get_to_states () =
  let _ = List.map get_to (states (seq 0xbadd00d5)) in
  Lwt.return_unit

let initial_listen () =
  let t = start ~on_close:(fun _ -> ()) in
  state_is t Closed;
  Lwt.return_unit

let stay_closed () =
  (* Closed connections ignore all but outgoing SYN *)
  let still_closed t = function
    | Passive_open | Send_syn _ -> ()
    | action ->
      Timeless_state.tick t action;
      state_is t Closed
  in
  let closed = get_closed () in
  List.iter (still_closed closed) (actions (seq 0xabad1dea));
  Lwt.return_unit

let initial_open () =
  let t = get_closed () in
  Timeless_state.tick t Passive_open;
  state_is t Listen;
  let t = get_closed () in
  let seq_no = 0xabad1dea in
  Timeless_state.tick t (Send_syn (seq seq_no));
  state_is t (Syn_sent (seq seq_no));
  Lwt.return_unit

let finwait2_resolves_normally () =
  let t = get_closed () in
  Tricky_state.tick t (Send_syn (seq 1));
  Tricky_state.tick t (Recv_synack (seq 2));
  Tricky_state.tick t (Send_fin (seq 3));
  state_is t (Fin_wait_1 (seq 3));
  Tricky_state.tick t (Recv_ack (seq 4));
  (* finwait2timer should have launched there *)
  state_is t Fin_wait_2;
  Tricky_time.wake ();
  (* finwait2timer should now have finished *)
  state_is t Closed;
  Lwt.return_unit

let finwait2_resolves_multiple_acks () =
  let t = get_closed () in
  Tricky_state.tick t (Send_syn (seq 1));
  Tricky_state.tick t (Recv_synack (seq 2));
  (* should be Established now *)
  state_is t Established;
  Tricky_state.tick t (Send_fin (seq 3));
  state_is t (Fin_wait_1 (seq 3));
  Tricky_state.tick t (Recv_ack (seq 4));
  (* finwait2timer should have launched there *)
  (* because we're using Tricky_state, we can fire as many acks as we like and
     observe the behavior until we call Tricky_timer.wake *)
  state_is t Fin_wait_2;
  Tricky_state.tick t (Recv_ack (seq 4));
  state_is t Fin_wait_2;
  Tricky_time.wake ();
  (* finwait2timer should now have finished *)
  state_is t Closed;
  Lwt.return_unit

let rst_closes t =
  Timeless_state.tick t Recv_rst;
  state_is t Closed

let rst_listen () =
  let t = get_to Listen in
  Timeless_state.tick t Recv_rst;
  state_is t Listen;
  Lwt.return_unit

let rst_syn_rcvd () =
  let t = get_to (Syn_rcvd (seq 2)) in
  Timeless_state.tick t Recv_rst;
  state_is t Listen;
  Lwt.return_unit

let rstack_syn_sent () =
  let t = get_to (Syn_sent (seq 1)) in
  Timeless_state.tick t (Recv_rstack (seq 2));
  state_is t Closed;
  Lwt.return_unit

let rst_established () =
  let t = get_to Established in
  rst_closes t;
  Lwt.return_unit

let rst_sent_fin () =
  let t = get_to Established in
  (* data exchange in ESTABLISHED happens for a while *)
  Timeless_state.tick t (Send_fin (seq 100));
  rst_closes t;
  Lwt.return_unit

let rst_fin_wait_2 () =
  let t = get_to Fin_wait_2 in
  (* get an RST before time-wait expires *)
  Tricky_state.tick t Recv_rst;
  state_is t Closed;
  Lwt.return_unit

let rst_rcvd_fin () =
  let t = get_to Established in
  (* other side closes *)
  Timeless_state.tick t Recv_fin;
  (* normally we wouldn't close until we get action Send_fin *)
  rst_closes t;
  Lwt.return_unit

let rstack_other_states () =
  let get_to_not_syn_sent = function
    | Syn_sent _ -> get_to Closed
    | x -> get_to x
  in
  let eq t s = OUnit.assert_equal ~pp_diff:state_diff (state t) (state s) in
  let rst_ack t = Timeless_state.tick t (Recv_rstack (seq 0xabad1deb)) in
  let states = (states (seq 0xabad1dea)) in
  let connections = List.map get_to_not_syn_sent states in
  List.iter rst_ack connections;
  let fresh_connections = List.map get_to_not_syn_sent states in
  List.iter2 eq fresh_connections connections;
  Lwt.return_unit

let rst_teardown =
  (* Quoth RFC 793,
       Reset Processing

       In all states except SYN-SENT, all reset (RST) segments are validated
       by checking their SEQ-fields.  A reset is valid if its sequence number
       is in the window.  In the SYN-SENT state (a RST received in response
  to an initial SYN), the RST is acceptable if the ACK field
       acknowledges the SYN.

       The receiver of a RST first validates it, then changes state.  If the
       receiver was in the LISTEN state, it ignores it.  If the receiver was
       in SYN-RECEIVED state and had previously been in the LISTEN state,
  then the receiver returns to the LISTEN state, otherwise the receiver
       aborts the connection and goes to the CLOSED state.  If the receiver
       was in any other state, it aborts the connection and advises the user
       and goes to the CLOSED state.
  *)

  (* Clearly we can't do the right thing because we don't support
     reflecting the sequence number of the RST in the types currently. *)
  [ "RSTs do not tear down connections in LISTEN", `Quick, rst_listen;
    "RSTACKs tear down connections in SYN_SENT", `Quick, rstack_syn_sent;
    "RSTACKs do not tear down connections in non-SYN_SENT states", `Quick, rstack_other_states;
    "RSTs send connections in SYN_RCVD to LISTEN", `Quick, rst_syn_rcvd;
    "RSTs tear down connections in ESTABLISHED", `Quick, rst_established;
    "RSTs tear down connections when a FIN has been sent", `Quick, rst_sent_fin;
    "RSTs tear down connections in FIN_WAIT_2", `Quick, rst_fin_wait_2;
    "RSTs tear down connections when a FIN has been received", `Quick, rst_rcvd_fin;
  ]

let out_of_sequence_ack () =
  let t = get_closed () in
  Timeless_state.tick t Passive_open;
  Timeless_state.tick t (Send_synack (seq 1));  (* this must be our seq #? *)
  state_is t (Syn_rcvd (seq 1));
  Timeless_state.tick t (Recv_ack (seq 504803));
  state_is t (Syn_rcvd (seq 1));
  Timeless_state.tick t (Recv_ack (seq 2));
  state_is t Established;
  Lwt.return_unit

let out_of_sequence_rstack () =
  let t = get_to (Syn_sent (seq 4)) in
  Timeless_state.tick t (Recv_rstack (seq 0xabad1dea));
  state_is t (Syn_sent (seq 4));
  Lwt.return_unit

let suite = List.append [
  "states are reachable as expected", `Quick, get_to_states;
  "initial state is Closed", `Quick, initial_listen;
  "valid transitions from Closed occur", `Quick, initial_open;
  "invalid transitions from Closed are ignored", `Quick, stay_closed;
  "connections in fin_wait_2 resolve with one ACK", `Quick, finwait2_resolves_normally;
  "connections in fin_wait_2 resolve even with multiple ACKs", `Quick, finwait2_resolves_multiple_acks;
  "out-of-sequence ACKs don't complete 3-way handshake", `Quick, out_of_sequence_ack;
  "out-of-sequence RST/ACKs are ignored", `Quick, out_of_sequence_rstack;
] rst_teardown
