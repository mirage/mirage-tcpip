(*
 * Copyright (c) 2010 Anil Madhavapeddy <anil@recoil.org>
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

let src = Logs.Src.create "window" ~doc:"Mirage TCP Window module"
module Log = (val Logs.src_log src : Logs.LOG)

type time = int64

type t = {
  tx_mss: int;
  tx_isn: Sequence.t;
  rx_isn: Sequence.t;
  max_rx_wnd: int32;               (* Max RX Window size after scaling *)
  tx_wnd_scale: int;               (* TX Window scaling option     *)
  rx_wnd_scale: int;               (* RX Window scaling option     *)

  mutable ack_serviced: bool;
  mutable ack_seq: Sequence.t;
  mutable ack_win: int;

  mutable snd_una: Sequence.t;
  mutable tx_nxt: Sequence.t;
  mutable rx_nxt: Sequence.t;
  mutable rx_nxt_inseq: Sequence.t;
  mutable fast_rec_th: Sequence.t;
  mutable max_tx_wnd : int32;      (* Max seen TX window after scaling *)
  mutable tx_wnd: int32;           (* TX Window size after scaling *)
  mutable rx_wnd: int32;           (* RX Window size after scaling *)
  mutable ssthresh: int32;         (* threshold to switch from exponential
                                      slow start to linear congestion
                                      avoidance *)
  mutable cwnd: int32;             (* congestion window *)
  mutable fast_recovery: bool;     (* flag to mark if this tcp is in
                                      fast recovery *)

  mutable rtt_timer_on: bool;
  mutable rtt_timer_reset: bool;
  mutable rtt_timer_seq: Sequence.t;
  mutable rtt_timer_starttime: time;
  mutable srtt: time;
  mutable rttvar: time;
  mutable rto: int64;
  mutable backoff_count: int;
}

let count_ackd_segs = MProf.Counter.make ~name:"tcp-ackd-segs"

(* To string for debugging *)
let pp fmt t =
  Format.fprintf fmt
    "Window: rx_nxt=%a rx_nxt_inseq=%a tx_nxt=%a rx_wnd=%lu tx_wnd=%lu snd_una=%a backoffs=%d rto=%Lu"
    Sequence.pp t.rx_nxt
    Sequence.pp t.rx_nxt_inseq
    Sequence.pp t.tx_nxt
    t.rx_wnd t.tx_wnd
    Sequence.pp t.snd_una
    t.backoff_count t.rto

(* Initialise the sequence space *)
let t ~rx_wnd_scale ~tx_wnd_scale ~rx_wnd ~tx_wnd ~rx_isn ~tx_mss ~tx_isn =
  let tx_nxt = tx_isn in
  let rx_nxt = Sequence.incr rx_isn in
  let rx_nxt_inseq = Sequence.incr rx_isn in
  let snd_una = tx_nxt in
  let fast_rec_th = tx_nxt in
  let ack_serviced = true in
  let ack_seq = tx_nxt in
  let ack_win = rx_wnd in
  let rx_wnd = Int32.(shift_left (of_int rx_wnd) rx_wnd_scale) in
  let max_rx_wnd = rx_wnd in
  let tx_wnd = Int32.(shift_left (of_int tx_wnd) tx_wnd_scale) in
  let max_tx_wnd = tx_wnd in
  (* ssthresh is initialized per RFC 2581 to a large value so slow-start
     can be used all the way till first loss *)
  let ssthresh = tx_wnd in
  let cwnd = Int32.of_int (tx_mss * 2) in
  let fast_recovery = false in
  let rtt_timer_on = false in
  let rtt_timer_reset = true in
  let rtt_timer_seq = tx_nxt in
  let rtt_timer_starttime = 0L in
  let srtt = (Duration.of_ms 667) in
  let rttvar = 0L in
  let rto = (Duration.of_ms 667) in
  let backoff_count = 0 in
  { tx_isn; rx_isn; max_rx_wnd; max_tx_wnd;
    ack_serviced; ack_seq; ack_win;
    snd_una; tx_nxt; tx_wnd; rx_nxt; rx_nxt_inseq;
    fast_rec_th; rx_wnd; tx_wnd_scale; rx_wnd_scale;
    ssthresh; cwnd; tx_mss; fast_recovery;
    rtt_timer_on; rtt_timer_reset;
    rtt_timer_seq; rtt_timer_starttime; srtt; rttvar; rto; backoff_count }

(* Check if a sequence number is in the right range *)
let valid t seq =
  let redge = Sequence.(add t.rx_nxt (of_int32 t.rx_wnd)) in
  let ledge = Sequence.(sub t.rx_nxt (of_int32 t.max_rx_wnd)) in
  let r = Sequence.between seq ledge redge in
  Log.debug (fun f -> f "sequence validation: seq=%a range=%a[%lu] res=%b"
    Sequence.pp seq Sequence.pp t.rx_nxt t.rx_wnd r);
  r

(* Advance received packet sequence number *)
let rx_advance t b =
  t.rx_nxt <- Sequence.add t.rx_nxt b

(* Early advance received packet sequence number for packet ordering *)
let rx_advance_inseq t b =
  t.rx_nxt_inseq <- Sequence.add t.rx_nxt_inseq b

(* Next expected receive sequence number *)
let rx_nxt t = t.rx_nxt
let rx_nxt_inseq t = t.rx_nxt_inseq
let rx_wnd t = t.rx_wnd
let rx_wnd_unscaled t = Int32.shift_right t.rx_wnd t.rx_wnd_scale

let ack_serviced t = t.ack_serviced
let ack_seq t = t.ack_seq
let ack_win t = t.ack_win

let set_ack_serviced t v = t.ack_serviced <- v
let set_ack_seq_win t s w =
  MProf.Counter.increase count_ackd_segs (Sequence.(sub s t.ack_seq |> to_int));
  t.ack_seq <- s;
  t.ack_win <- w

(* TODO: scale the window down so we can advertise it correctly with
   window scaling on the wire *)
let set_rx_wnd t sz =
  t.rx_wnd <- sz

(* Take an unscaled value and scale it up *)
let set_tx_wnd t sz =
  let wnd = Int32.(shift_left (of_int sz) t.tx_wnd_scale) in
  t.tx_wnd <- wnd;
  if wnd > t.max_tx_wnd then
      t.max_tx_wnd <- wnd

(* transmit MSS of current connection *)
let tx_mss t =
  t.tx_mss

module Make(Clock:Mirage_clock.MCLOCK) = struct
  (* Advance transmitted packet sequence number *)
  let tx_advance clock t b =
    if not t.rtt_timer_on && not t.fast_recovery then begin
      t.rtt_timer_on <- true;
      t.rtt_timer_seq <- t.tx_nxt;
      t.rtt_timer_starttime <- Clock.elapsed_ns clock;
    end;
    t.tx_nxt <- Sequence.add t.tx_nxt b

  (* An ACK was received - use it to adjust cwnd *)
  let tx_ack clock t r win =
    set_tx_wnd t win;
    if t.fast_recovery then begin
      if Sequence.gt r t.snd_una then
        t.snd_una <- r;
      if Sequence.geq r t.fast_rec_th then begin
        Log.debug (fun f -> f "EXITING fast recovery");
        t.cwnd <- t.ssthresh;
        t.fast_recovery <- false;
      end else begin
        t.cwnd <- (Int32.add t.cwnd (Int32.of_int t.tx_mss));
      end
    end else begin
      if Sequence.gt r t.snd_una then begin
        t.backoff_count <- 0;
        t.snd_una <- r;
        if t.rtt_timer_on && Sequence.gt r t.rtt_timer_seq then begin
          t.rtt_timer_on <- false;
          let rtt_m = Int64.sub (Clock.elapsed_ns clock) t.rtt_timer_starttime in
          if t.rtt_timer_reset then begin
            t.rtt_timer_reset <- false;
            t.rttvar <- Int64.div rtt_m 2L;
            t.srtt <- rtt_m;
          end else begin
            let (/) = Int64.div
            and ( * ) = Int64.mul
            and (-) = Int64.sub
            and (+) = Int64.add
            in
            (* RFC2988 2.3 *)
            t.rttvar <- (3L * t.rttvar / 4L) + (Int64.abs (t.srtt - rtt_m) / 4L);
            t.srtt <- (7L * t.srtt / 8L) + (rtt_m / 8L)
          end;
          t.rto <- max (Duration.of_ms 667) Int64.(add t.srtt (mul t.rttvar 4L));
        end;
      end;
      let cwnd_incr = match t.cwnd < t.ssthresh with
        | true -> Int32.of_int t.tx_mss
        | false -> max (Int32.div (Int32.of_int (t.tx_mss * t.tx_mss)) t.cwnd) 1l
      in
      t.cwnd <- Int32.add t.cwnd cwnd_incr
    end
end

let tx_nxt t = t.tx_nxt
let tx_wnd t = t.tx_wnd
let tx_wnd_unscaled t = Int32.shift_right t.tx_wnd t.tx_wnd_scale
let max_tx_wnd t = t.max_tx_wnd
let tx_una t = t.snd_una
let fast_rec t = t.fast_recovery
let tx_available t =
  let inflight = Sequence.to_int32 (Sequence.sub t.tx_nxt t.snd_una) in
  let win = min t.cwnd t.tx_wnd in
  let avail_win = Int32.sub win inflight in
  match avail_win < Int32.of_int t.tx_mss with
  | true -> 0l
  | false -> avail_win

let tx_inflight t =
  t.tx_nxt <> t.snd_una


let alert_fast_rexmit t _ =
  if not t.fast_recovery then begin
    let inflight = Sequence.to_int32 (Sequence.sub t.tx_nxt t.snd_una) in
    let newssthresh = max (Int32.div inflight 2l) (Int32.of_int (t.tx_mss * 2)) in
    let newcwnd = Int32.add inflight (Int32.of_int (t.tx_mss * 2)) in
    Log.debug (fun fmt ->
        fmt "ENTERING fast recovery inflight=%ld, ssthresh=%ld -> %ld, \
                    cwnd=%ld -> %ld"
          inflight t.ssthresh newssthresh t.cwnd newcwnd);
    t.fast_recovery <- true;
    t.fast_rec_th <- t.tx_nxt;
    t.ssthresh <- newssthresh;
    t.rtt_timer_on <- false;
    t.cwnd <- newcwnd
  end

let rto t =
  match t.backoff_count with
  | 0 -> t.rto
  | _ -> Int64.(mul t.rto (shift_left 2L t.backoff_count))

let backoff_rto t =
  t.backoff_count <- t.backoff_count + 1;
  t.rtt_timer_on <- false;
  t.rtt_timer_reset <- true

let max_rexmits_done t =
  (t.backoff_count > 5)

let tx_totalbytes t =
  Sequence.(to_int (sub t.tx_nxt t.tx_isn))

let rx_totalbytes t =
  (-) Sequence.(to_int (sub t.rx_nxt t.rx_isn)) 1
