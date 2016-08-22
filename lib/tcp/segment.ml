(*
 * Copyright (c) 2010-2011 Anil Madhavapeddy <anil@recoil.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

open Lwt.Infix

let src = Logs.Src.create "segment" ~doc:"Mirage TCP Segment module"
module Log = (val Logs.src_log src : Logs.LOG)

let lwt_sequence_add_l s seq =
  let (_:'a Lwt_sequence.node) = Lwt_sequence.add_l s seq in
  ()

let lwt_sequence_add_r s seq =
  let (_:'a Lwt_sequence.node) = Lwt_sequence.add_r s seq in
  ()

let peek_opt_l seq =
  match Lwt_sequence.take_opt_l seq with
  | None -> None
  | Some s ->
    lwt_sequence_add_l s seq;
    Some s

let peek_l seq =
  match Lwt_sequence.take_opt_l seq with
  | None -> assert false
  | Some s ->
    let _ = Lwt_sequence.add_l s seq in
    s

let rec reset_seq segs =
  match Lwt_sequence.take_opt_l segs with
  | None -> ()
  | Some _ -> reset_seq segs

(* The receive queue stores out-of-order segments, and can
   coalesece them on input and pass on an ordered list up the
   stack to the application.

   It also looks for control messages and dispatches them to
   the Rtx queue to ack messages or close channels.
*)
module Rx(Time:V1_LWT.TIME) = struct
  open Tcp_packet
  module StateTick = State.Make(Time)

  (* Individual received TCP segment
     TODO: this will change when IP fragments work *)
  type segment = { header: Tcp_packet.t; payload: Cstruct.t }

  let pp_segment fmt {header; payload} =
    Format.fprintf fmt
      "RX seg seq=%a acknum=%a ack=%b rst=%b syn=%b fin=%b win=%d len=%d"
      Sequence.pp header.sequence Sequence.pp header.ack_number
      header.ack header.rst header.syn header.fin
      header.window (Cstruct.len payload)

  let len seg =
    Sequence.of_int ((Cstruct.len seg.payload) +
    (if seg.header.fin then 1 else 0) +
    (if seg.header.syn then 1 else 0))

  (* Set of segments, ordered by sequence number *)
  module S = Set.Make(struct
      type t = segment
      let compare a b = (Sequence.compare a.header.sequence b.header.sequence)
    end)

  type t = {
    mutable segs: S.t;
    rx_data: (Cstruct.t list option * Sequence.t option) Lwt_mvar.t; (* User receive channel *)
    tx_ack: (Sequence.t * int) Lwt_mvar.t; (* Acks of our transmitted segs *)
    wnd: Window.t;
    state: State.t;
  }

  let create ~rx_data ~wnd ~state ~tx_ack =
    let segs = S.empty in
    { segs; rx_data; tx_ack; wnd; state }

  let pp fmt t =
    let pp_v fmt seg =
      Format.fprintf fmt "%a[%a]" Sequence.pp seg.header.sequence Sequence.pp (len seg)
    in
    Format.pp_print_list pp_v fmt (S.elements t.segs)

  (* If there is a FIN flag at the end of this segment set.  TODO:
     should look for a FIN and chop off the rest of the set as they
     may be orphan segments *)
  let fin q =
    try (S.max_elt q).header.fin
    with Not_found -> false

  let is_empty q = S.is_empty q.segs

  let check_valid_segment q seg =
    if seg.header.rst then
      if Sequence.compare seg.header.sequence (Window.rx_nxt q.wnd) = 0 then
        `Reset
      else if Window.valid q.wnd seg.header.sequence then
        `ChallengeAck
      else
        `Drop
    else if seg.header.syn then
      `ChallengeAck
    else if Window.valid q.wnd seg.header.sequence then
      let min = Sequence.(sub (Window.tx_una q.wnd) (of_int32 (Window.max_tx_wnd q.wnd))) in
      if Sequence.between seg.header.ack_number min (Window.tx_nxt q.wnd) then
        `Ok
      else
        (* rfc5961 5.2 *)
        `ChallengeAck
    else
      `Drop

  let send_challenge_ack q =
    (* TODO:  rfc5961 ACK Throttling *)
    (* Is this the correct way trigger an ack? *)
    Lwt_mvar.put q.rx_data (Some [], Some Sequence.zero)

  (* Given an input segment, the window information, and a receive
     queue, update the window, extract any ready segments into the
     user receive queue, and signal any acks to the Tx queue *)
  let input (q:t) seg =
    match check_valid_segment q seg with
    | `Ok ->
      let force_ack = ref false in
      (* Insert the latest segment *)
      let segs = S.add seg q.segs in
      (* Walk through the set and get a list of contiguous segments *)
      let ready, waiting = S.fold (fun seg acc ->
          match Sequence.compare seg.header.sequence (Window.rx_nxt_inseq q.wnd) with
          | (-1) ->
            (* Sequence number is in the past, probably an overlapping
               segment. Drop it for now, but TODO segment
               coalescing *)
            force_ack := true;
            acc
          | 0 ->
            (* This is the next segment, so put it into the ready set
               and update the receive ack number *)
            let (ready,waiting) = acc in
            Window.rx_advance_inseq q.wnd (len seg);
            (S.add seg ready), waiting
          | 1 ->
            (* Sequence is in the future, so can't use it yet *)
            force_ack := true;
            let (ready,waiting) = acc in
            ready, (S.add seg waiting)
          | _ -> assert false
        ) segs (S.empty, S.empty) in
      q.segs <- waiting;
      (* If the segment has an ACK, tell the transmit side *)
      let tx_ack =
        if seg.header.ack && (Sequence.geq seg.header.ack_number (Window.ack_seq q.wnd)) then begin
          StateTick.tick q.state (State.Recv_ack seg.header.ack_number);
          let data_in_flight = Window.tx_inflight q.wnd in
          let ack_has_advanced = (Window.ack_seq q.wnd) <> seg.header.ack_number in
          let win_has_changed = (Window.ack_win q.wnd) <> seg.header.window in
          if ((data_in_flight && (Window.ack_serviced q.wnd || not ack_has_advanced)) ||
              (not data_in_flight && win_has_changed)) then begin
            Window.set_ack_serviced q.wnd false;
            Window.set_ack_seq_win q.wnd seg.header.ack_number seg.header.window;
            Lwt_mvar.put q.tx_ack ((Window.ack_seq q.wnd), (Window.ack_win q.wnd))
          end else begin
            Window.set_ack_seq_win q.wnd seg.header.ack_number seg.header.window;
            Lwt.return_unit
          end
        end else Lwt.return_unit
      in
      (* Inform the user application of new data *)
      let urx_inform =
        (* TODO: deal with overlapping fragments *)
        let elems_r, winadv = S.fold (fun seg (acc_l, acc_w) ->
            (if Cstruct.len seg.payload > 0 then seg.payload :: acc_l else acc_l),
            (Sequence.add (len seg) acc_w)
          ) ready ([], Sequence.zero) in
        let elems = List.rev elems_r in
        let w = if !force_ack || Sequence.(gt winadv zero)
          then Some winadv else None in
        Lwt_mvar.put q.rx_data (Some elems, w) >>= fun () ->
        (* If the last ready segment has a FIN, then mark the receive
           window as closed and tell the application *)
        (if fin ready then begin
            if S.cardinal waiting != 0 then
              Log.info (fun f -> f "application receive queue closed, but there are waiting segments.");
            Lwt_mvar.put q.rx_data (None, Some Sequence.zero)
          end else Lwt.return_unit)
      in
      tx_ack <&> urx_inform
    | `ChallengeAck ->
      send_challenge_ack q
    | `Drop ->
      Lwt.return_unit
    | `Reset ->
      StateTick.tick q.state State.Recv_rst;
      (* Abandon our current segments *)
      q.segs <- S.empty;
      (* Signal TX side *)
      let txalert ack_svcd =
        if not ack_svcd then Lwt.return_unit
        else Lwt_mvar.put q.tx_ack (Window.ack_seq q.wnd, Window.ack_win q.wnd)
      in
      txalert (Window.ack_serviced q.wnd) >>= fun () ->
      (* Use the fin path to inform the application of end of stream *)
      Lwt_mvar.put q.rx_data (None, Some Sequence.zero)
end

(* Transmitted segments are sent in-order, and may also be marked
   with control flags (such as urgent, or fin to mark the end).
*)

type tx_flags = (* At most one of Syn/Fin/Rst/Psh allowed *)
  | No_flags
  | Syn
  | Fin
  | Rst
  | Psh

module Tx (Time:V1_LWT.TIME) (Clock:V1.MCLOCK) = struct

  module StateTick = State.Make(Time)
  module TT = Tcptimer.Make(Time)
  module TX = Window.Make(Clock)

  type xmit = flags:tx_flags -> wnd:Window.t -> options:Options.t list ->
    seq:Sequence.t -> Cstruct.t -> unit Lwt.t

  type seg = {
    data: Cstruct.t;
    flags: tx_flags;
    seq: Sequence.t;
  }

  (* Sequence length of the segment *)
  let len seg =
    Sequence.of_int
    ((match seg.flags with
     | No_flags | Psh | Rst -> 0
     | Syn | Fin -> 1) +
    (Cstruct.len seg.data))

  (* Queue of pre-transmission segments *)
  type t = {
    segs: seg Lwt_sequence.t;      (* Retransmitted segment queue *)
    xmit: xmit;                    (* Transmit packet to the wire *)
    rx_ack: Sequence.t Lwt_mvar.t; (* RX Ack thread that we've sent one *)
    wnd: Window.t;                 (* TCP Window information *)
    state: State.t;                (* state of the TCP connection associated
                                      with this queue *)
    tx_wnd_update: int Lwt_mvar.t; (* Received updates to the transmit window *)
    rexmit_timer: Tcptimer.t;      (* Retransmission timer for this connection *)
    clock: Clock.t;                (* whom to ask for the time *)
    mutable dup_acks: int;         (* dup ack count for re-xmits *)
  }

  let ack_segment _ _ = ()
  (* Take any action to the user transmit queue due to this being
     successfully ACKed *)

  (* URG_TODO: Add sequence number to the Syn_rcvd rexmit to only
     rexmit most recent *)
  let ontimer xmit st segs wnd seq =
    match State.state st with
    | State.Syn_rcvd _ | State.Established | State.Fin_wait_1 _
    | State.Close_wait | State.Last_ack _ ->
      begin match peek_opt_l segs with
        | None -> Lwt.return Tcptimer.Stoptimer
        | Some rexmit_seg ->
          match rexmit_seg.seq = seq with
          | false ->
            Log.debug (fun fmt ->
                fmt "PUSHING TIMER - new time=%Lu, new seq=%a"
                  (Window.rto wnd) Sequence.pp rexmit_seg.seq);
            let ret =
              Tcptimer.ContinueSetPeriod (Window.rto wnd, rexmit_seg.seq)
            in
            Lwt.return ret
          | true ->
            if (Window.max_rexmits_done wnd) then (
              (* TODO - include more in log msg like ipaddrs *)
              Log.debug (fun f -> f "Max retransmits reached: %a" Window.pp wnd);
              Log.info (fun fmt -> fmt "Max retransmits reached for connection - terminating");
              StateTick.tick st State.Timeout;
              Lwt.return Tcptimer.Stoptimer
            ) else (
              let flags = rexmit_seg.flags in
              let options = [] in (* TODO: put the right options *)
              Log.debug (fun fmt ->
                  fmt "TCP retransmission triggered by timer! seq = %d"
                    (Sequence.to_int rexmit_seg.seq));
              Lwt.async
                (fun () -> xmit ~flags ~wnd ~options ~seq rexmit_seg.data);
              Window.backoff_rto wnd;
              Log.debug (fun fmt -> fmt "Backed off! %a" Window.pp wnd);
              Log.debug (fun fmt ->
                  fmt "PUSHING TIMER - new time = %Lu, new seq = %a"
                    (Window.rto wnd) Sequence.pp rexmit_seg.seq);
              let ret =
                Tcptimer.ContinueSetPeriod (Window.rto wnd, rexmit_seg.seq)
              in
              Lwt.return ret
            )
      end
    | _ -> Lwt.return Tcptimer.Stoptimer

  let rec clearsegs q ack_remaining segs =
    match Sequence.(gt ack_remaining zero) with
    | false -> Sequence.zero (* here we return 0l instead of ack_remaining in case
                     the ack was an old packet in the network *)
    | true ->
      match Lwt_sequence.take_opt_l segs with
      | None ->
        Log.debug (fun f -> f "Dubious ACK received");
        ack_remaining
      | Some s ->
        let seg_len = (len s) in
        match Sequence.lt ack_remaining seg_len with
        | true ->
          Log.debug (fun f -> f "Partial ACK received");
          (* return uncleared segment to the sequence *)
          lwt_sequence_add_l s segs;
          ack_remaining
        | false ->
          ack_segment q s;
          clearsegs q (Sequence.sub ack_remaining seg_len) segs

  let rto_t q tx_ack =
    (* Listen for incoming TX acks from the receive queue and ACK
       segments in our retransmission queue *)
    let rec tx_ack_t () =
      let serviceack dupack ack_len seq win =
        let partleft = clearsegs q ack_len q.segs in
        TX.tx_ack q.clock q.wnd (Sequence.sub seq partleft) win;
        match dupack || Window.fast_rec q.wnd with
        | true ->
          q.dup_acks <- q.dup_acks + 1;
          if q.dup_acks = 3 ||
             (q.dup_acks > 3 && Sequence.to_int32 ack_len > 0l) then begin
            (* alert window module to fall into fast recovery *)
            Window.alert_fast_rexmit q.wnd seq;
            (* retransmit the bottom of the unacked list of packets *)
            let rexmit_seg = peek_l q.segs in
            Log.debug (fun fmt ->
                fmt "TCP fast retransmission seq=%a, dupack=%a"
                  Sequence.pp rexmit_seg.seq Sequence.pp seq);
            let { wnd; _ } = q in
            let flags=rexmit_seg.flags in
            let options=[] in (* TODO: put the right options *)
            Lwt.async
              (fun () -> q.xmit ~flags ~wnd ~options ~seq rexmit_seg.data);
            Lwt.return_unit
          end else
            Lwt.return_unit
        | false ->
          q.dup_acks <- 0;
          Lwt.return_unit
      in
      Lwt_mvar.take tx_ack >>= fun _ ->
      Window.set_ack_serviced q.wnd true;
      let seq = Window.ack_seq q.wnd in
      let win = Window.ack_win q.wnd in
      begin match State.state q.state with
        | State.Reset ->
          (* Note: This is not stricly necessary, as the PCB will be
             GCed later on.  However, it helps removing pressure on
             the GC. *)
          reset_seq q.segs;
          Lwt.return_unit
        | _ ->
          let ack_len = Sequence.sub seq (Window.tx_una q.wnd) in
          let dupacktest () =
            0l = Sequence.to_int32 ack_len &&
            Window.tx_wnd_unscaled q.wnd = Int32.of_int win &&
            not (Lwt_sequence.is_empty q.segs)
          in
          serviceack (dupacktest ()) ack_len seq win
      end >>= fun () ->
      (* Inform the window thread of updates to the transmit window *)
      Lwt_mvar.put q.tx_wnd_update win >>= fun () ->
      tx_ack_t ()
    in
    tx_ack_t ()

  let create ~clock ~xmit ~wnd ~state ~rx_ack ~tx_ack ~tx_wnd_update =
    let segs = Lwt_sequence.create () in
    let dup_acks = 0 in
    let expire = ontimer xmit state segs wnd in
    let period_ns = Window.rto wnd in
    let rexmit_timer = TT.t ~period_ns ~expire in
    let q =
      { clock; xmit; wnd; state; rx_ack; segs; tx_wnd_update; rexmit_timer; dup_acks }
    in
    let t = rto_t q tx_ack in
    q, t

  (* Queue a segment for transmission. May block if:
       - There is no transmit window available.
       - The wire transmit function blocks.
     The transmitter should check that the segment size will
     will not be greater than the transmit window.
  *)
  let output ?(flags=No_flags) ?(options=[]) q data =
    (* Transmit the packet to the wire
         TODO: deal with transmission soft/hard errors here RFC5461 *)
    let { wnd; _ } = q in
    let ack = Window.rx_nxt wnd in
    let seq = Window.tx_nxt wnd in
    let seg = { data; flags; seq } in
    let seq_len = len seg in
    TX.tx_advance q.clock q.wnd seq_len;
    (* Queue up segment just sent for retransmission if needed *)
    let q_rexmit () =
      match Sequence.(gt seq_len zero) with
      | false -> Lwt.return_unit
      | true ->
        lwt_sequence_add_r seg q.segs;
        let p = Window.rto q.wnd in
        TT.start q.rexmit_timer ~p seg.seq
    in
    q_rexmit () >>= fun () ->
    q.xmit ~flags ~wnd ~options ~seq data >>= fun _ ->
    (* Inform the RX ack thread that we've just sent one *)
    Lwt_mvar.put q.rx_ack ack
end
