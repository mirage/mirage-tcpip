(*
 * Copyright (c) 2010-2012 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (c) 2012 Balraj Singh <bs375@cl.cam.ac.uk>
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

let src = Logs.Src.create "pcb" ~doc:"Mirage TCP PCB module"
module Log = (val Logs.src_log src : Logs.LOG)

module Make(Ip:Mirage_protocols.IP)(Time:Mirage_time.S)(Clock:Mirage_clock.MCLOCK)(Random:Mirage_random.S) =
struct

  module RXS = Segment.Rx(Time)
  module TXS = Segment.Tx(Time)(Clock)
  module ACK = Ack.Immediate
  module UTX = User_buffer.Tx(Time)(Clock)
  module WIRE = Wire.Make(Ip)
  module STATE = State.Make(Time)
  module KEEPALIVE = Keepalive.Make(Time)(Clock)

  type error = [ Mirage_protocols.Tcp.error | WIRE.error]

  let pp_error ppf = function
    | #Mirage_protocols.Tcp.error as e -> Mirage_protocols.Tcp.pp_error ppf e
    | #WIRE.error as e -> WIRE.pp_error ppf e

  type write_error = [Mirage_protocols.Tcp.write_error | `Not_ready]

  let pp_write_error ppf = function
    | `Not_ready ->
      Fmt.string ppf "attempted to send data before connection was ready"
    | #Mirage_protocols.Tcp.write_error as e -> Mirage_protocols.Tcp.pp_write_error ppf e

  type ipaddr = Ip.ipaddr
  type buffer = Cstruct.t
  type +'a io = 'a Lwt.t
  type ipinput = src:ipaddr -> dst:ipaddr -> buffer -> unit io

  type pcb = {
    id: WIRE.t;
    wnd: Window.t;            (* Window information *)
    rxq: RXS.t;               (* Received segments queue for out-of-order data *)
    txq: TXS.t;               (* Transmit segments queue *)
    ack: ACK.t;               (* Ack state *)
    state: State.t;           (* Connection state *)
    urx: User_buffer.Rx.t;    (* App rx buffer *)
    utx: UTX.t;               (* App tx buffer *)
    keepalive: KEEPALIVE.t option; (* Optional TCP keepalive state *)
  }

  type flow = pcb
  type connection = flow * unit Lwt.t

  type listener = {
    process: flow -> unit io;
    keepalive: Mirage_protocols.Keepalive.t option;
  }

  type t = {
    ip : Ip.t;
    mutable localport : int;
    channels: (WIRE.t, connection) Hashtbl.t;
    (* server connections the process of connecting - SYN-ACK sent
       waiting for ACK *)
    listens: (WIRE.t, (Sequence.t * ((flow -> unit Lwt.t) * connection)))
        Hashtbl.t;
    (* clients in the process of connecting *)
    connects: (WIRE.t, ((connection, error) result Lwt.u * Sequence.t * Mirage_protocols.Keepalive.t option)) Hashtbl.t;
  }

  let _pp_pcb fmt pcb =
    Format.fprintf fmt "id=[%a] state=[%a]" WIRE.pp pcb.id State.pp pcb.state

  let pp_stats fmt t =
    Format.fprintf fmt "[channels=%d listens=%d connects=%d]"
      (Hashtbl.length t.channels)
      (Hashtbl.length t.listens)
      (Hashtbl.length t.connects)

  let log_with_stats name t = Log.debug (fun fmt -> fmt "%s: %a" name pp_stats t)

  let wscale_default = 2

  module Tx = struct

    (* Output a TCP packet, and calculate some settings from a state descriptor *)
    let xmit_pcb ip id ~flags ~wnd ~options ~seq (datav : Cstruct.t) =
      let window = Int32.to_int (Window.rx_wnd_unscaled wnd) in
      let rx_ack = Some (Window.rx_nxt wnd) in
      let syn = match flags with Segment.Syn -> true | _ -> false in
      let fin = match flags with Segment.Fin -> true | _ -> false in
      let rst = match flags with Segment.Rst -> true | _ -> false in
      let psh = match flags with Segment.Psh -> true | _ -> false in
      WIRE.xmit ~ip id ~syn ~fin ~rst ~psh ~rx_ack ~seq ~window ~options datav

    (* Output an RST response when we dont have a PCB *)
    let send_rst { ip; _ } id ~sequence ~ack_number ~syn ~fin =
      let datalen = Int32.add (if syn then 1l else 0l) (if fin then 1l else 0l) in
      let window = 0 in
      let options = [] in
      let seq = ack_number in
      let rx_ack = Some Sequence.(add sequence (of_int32 datalen)) in
      WIRE.xmit ~ip id ~rst:true ~rx_ack ~seq ~window ~options (Cstruct.create 0)

    (* Output a SYN packet *)
    let send_syn { ip; _ } id ~tx_isn ~options ~window =
      WIRE.xmit ~ip id ~syn:true ~rx_ack:None ~seq:tx_isn ~window ~options
        (Cstruct.create 0)

    (* Queue up an immediate close segment *)
    let close pcb =
      Log.debug (fun f -> f "Closing connection %a" WIRE.pp pcb.id);
      match State.state pcb.state with
      | State.Established | State.Close_wait ->
        UTX.wait_for_flushed pcb.utx >>= fun () ->
        (let { wnd; _ } = pcb in
         STATE.tick pcb.state (State.Send_fin (Window.tx_nxt wnd));
         TXS.output ~flags:Segment.Fin pcb.txq (Cstruct.create 0)
        )
      | _ ->
        Log.debug (fun fmt ->
            fmt "TX.close: close requested but no action needed, state=%a" State.pp pcb.state);
        Lwt.return_unit

    (* Thread that transmits ACKs in response to received packets,
       thus telling the other side that more can be sent, and
       also data from the user transmit queue *)
    let thread t pcb ~send_ack ~rx_ack  =
      let { wnd; ack; _ } = pcb in

      (* Transmit an empty ack when prompted by the Ack thread *)
      let rec send_empty_ack () =
        Lwt_mvar.take send_ack >>= fun _ ->
        let ack_number = Window.rx_nxt wnd in
        let flags = Segment.No_flags in
        let options = [] in
        let seq = Window.tx_nxt wnd in
        ACK.transmit ack ack_number >>= fun () ->
        xmit_pcb t.ip pcb.id ~flags ~wnd ~options ~seq (Cstruct.create 0) >>=
        fun _ -> (* TODO: what to do if sending failed.  Ignoring
                  * errors gives us the same behavior as if the packet
                  * was lost in transit *)
        send_empty_ack () in
      (* When something transmits an ACK, tell the delayed ACK thread *)
      let rec notify () =
        Lwt_mvar.take rx_ack >>= fun ack_number ->
        ACK.transmit ack ack_number >>= fun () ->
        notify () in
      send_empty_ack () <&> (notify ())
  end

  module Rx = struct

    (* Process an incoming TCP packet that has an active PCB *)
    let input _t parsed (pcb,_) =
      let { rxq; _ } = pcb in
      (* The connection is alive! *)
      begin match pcb.keepalive with
      | None -> ()
      | Some keepalive -> KEEPALIVE.refresh keepalive
      end;
      (* Coalesce any outstanding segments and retrieve ready segments *)
      RXS.input rxq parsed

    (* Thread that spools the data into an application receive buffer,
       and notifies the ACK subsystem that new data is here *)
    let thread pcb ~rx_data =
      let { wnd; ack; urx; _ } = pcb in
      (* Thread to monitor application receive and pass it up *)
      let rec rx_application_t () =
        Lwt_mvar.take rx_data >>= fun (data, winadv) ->
        let signal_ack = function
          | None        -> Lwt.return_unit
          | Some winadv when Sequence.(gt winadv zero) ->
              Window.rx_advance wnd winadv;
              ACK.receive ack (Window.rx_nxt wnd)
          | Some winadv ->
              Window.rx_advance wnd winadv;
              ACK.pushack ack (Window.rx_nxt wnd)
        in
        begin match data with
          | None ->
            (* don't send an ACK in this case; this already happened *)
            STATE.tick pcb.state State.Recv_fin;
            User_buffer.Rx.add_r urx None >>= fun () ->
            Lwt.return_unit
          | Some data ->
            signal_ack winadv >>= fun () ->
            let rec queue = function
              | []     -> Lwt.return_unit
              | hd::tl ->
                User_buffer.Rx.add_r urx (Some hd) >>= fun () ->
                queue tl
            in
            queue data >>= fun _ ->
            rx_application_t ()
        end
      in
      rx_application_t ()
  end

  module Wnd = struct

    let thread ~urx:_ ~utx ~wnd:_ ~state ~tx_wnd_update =
      (* Monitor our transmit window when updates are received
         remotely, and tell the application that new space is
         available when it is blocked *)
      let rec tx_window_t () =
        Lwt_mvar.take tx_wnd_update >>= fun tx_wnd ->
        begin match State.state state with
          | State.Reset -> UTX.reset utx
          | _ -> UTX.free utx tx_wnd
        end >>= fun () ->
        tx_window_t ()
      in
      tx_window_t ()

  end

  (* Helper function to apply function with contents of hashtbl, or
     take default action *)
  let with_hashtbl h k fn default =
    try fn (Hashtbl.find h k) with Not_found -> default k

  let hashtbl_find h k =
    try Some (Hashtbl.find h k) with Not_found -> None

  let clearpcb t id tx_isn =
    log_with_stats "removing pcb from connection tables" t;
    match hashtbl_find t.channels id with
    | Some _ ->
      Hashtbl.remove t.channels id;
      Stats.decr_channel ();
      Log.debug (fun f -> f "removed %a from active channels" WIRE.pp id);
    | None ->
      match hashtbl_find t.listens id with
      | Some (isn, _) ->
        if isn = tx_isn then (
          Hashtbl.remove t.listens id;
          Stats.decr_listen ();
          Log.debug (fun f -> f "removed %a from incomplete listen pcbs" WIRE.pp id);
        )
      | None ->
        Log.debug (fun f -> f "error in removing %a - no such connection" WIRE.pp id)

  let pcb_allocs = ref 0
  let th_allocs = ref 0
  let pcb_frees = ref 0
  let th_frees = ref 0

  let resolve_wnd_scaling options rx_wnd_scaleoffer =
    let tx_wnd_scale = List.fold_left (fun a ->
        function Options.Window_size_shift m -> Some m | _ -> a
      ) None options in
    match tx_wnd_scale with
    | None -> (0, 0), []
    | Some tx_f ->
      (rx_wnd_scaleoffer, tx_f),
      (Options.Window_size_shift rx_wnd_scaleoffer :: [])

  type pcb_params =
    { tx_wnd: int;
      sequence: Sequence.t;
      options: Options.t list;
      tx_isn: Sequence.t;
      rx_wnd: int;
      rx_wnd_scaleoffer: int }


  let keepalive_cb t id wnd state urx = function
  | `SendProbe ->
    Log.debug (fun f -> f "Sending keepalive on connection %a" WIRE.pp id);
    (* From https://tools.ietf.org/html/rfc1122#page-101

      > 4.2.3.6  TCP Keep-Alives
      ...
      > Such a segment generally contains SEG.SEQ =
      > SND.NXT-1 and may or may not contain one garbage octet
      > of data.  Note that on a quiet connection SND.NXT =
      > RCV.NXT, so that this SEG.SEQ will be outside the
      > window.  Therefore, the probe causes the receiver to
      > return an acknowledgment segment, confirming that the
      > connection is still live.  If the peer has dropped the
      > connection due to a network partition or a crash, it
      > will respond with a RST instead of an acknowledgment
      > segment.
    *)
    let flags = Segment.No_flags in
    let options = [] in
    let seq = Sequence.pred @@ Window.tx_nxt wnd in
    (* if the sending fails this behaves like a packet drop which will cause
        the connection to be eventually closed after the probes are sent *)
    Tx.xmit_pcb t.ip id ~flags ~wnd ~options ~seq (Cstruct.create 0) >>= fun _ ->
    Lwt.return_unit
  | `Close ->
    Log.debug (fun f -> f "Keepalive timer expired, resetting connection %a" WIRE.pp id);
    STATE.tick state State.Recv_rst;
    (* Close the read direction *)
    User_buffer.Rx.add_r urx None >>= fun () ->
    Lwt.return_unit

  let emitted_keepalive_warning = ref false

  let new_pcb t params id keepalive =
    let mtu_mss = Ip.mtu t.ip - Tcp_wire.sizeof_tcp in
    let { tx_wnd; sequence; options; tx_isn; rx_wnd; rx_wnd_scaleoffer } =
      params
    in
    let tx_mss = List.fold_left (fun a ->
      function
      | Options.MSS m -> min m mtu_mss
      | _ -> a
    ) mtu_mss options
    in
    let (rx_wnd_scale, tx_wnd_scale), opts =
      resolve_wnd_scaling options rx_wnd_scaleoffer
    in
    (* Set up the windowing variables *)
    let rx_isn = sequence in
    (* Initialise the window handler *)
    let wnd =
      Window.t ~rx_wnd_scale ~tx_wnd_scale ~rx_wnd ~tx_wnd ~rx_isn ~tx_mss
        ~tx_isn
    in
    (* When we transmit an ACK for a received segment, rx_ack is written to *)
    let rx_ack = MProf.Trace.named_mvar_empty "rx_ack" in
    (* When we receive an ACK for a transmitted segment, tx_ack is written to *)
    let tx_ack = MProf.Trace.named_mvar_empty "tx_ack" in
    (* When new data is received, rx_data is written to *)
    let rx_data = MProf.Trace.named_mvar_empty "rx_data" in
    (* Write to this mvar to transmit an empty ACK to the remote side *)
    let send_ack = MProf.Trace.named_mvar_empty "send_ack" in
    (* The user application receive buffer and close notification *)
    let rx_buf_size = Window.rx_wnd wnd in
    let urx = User_buffer.Rx.create ~max_size:rx_buf_size ~wnd in
    (* The window handling thread *)
    let tx_wnd_update = MProf.Trace.named_mvar_empty "tx_wnd_update" in
    (* Set up transmit and receive queues *)
    let on_close () = clearpcb t id tx_isn in
    let state = State.t ~on_close in
    let txq, _tx_t =
      TXS.create ~xmit:(Tx.xmit_pcb t.ip id) ~wnd ~state ~rx_ack ~tx_ack ~tx_wnd_update
    in
    (* The user application transmit buffer *)
    let utx = UTX.create ~wnd ~txq ~max_size:16384l in
    let rxq = RXS.create ~rx_data ~wnd ~state ~tx_ack in
    (* Set up ACK module *)
    let ack = ACK.t ~send_ack ~last:(Sequence.succ rx_isn) in
    (* Set up the keepalive state if requested *)
    let keepalive = match keepalive with
      | None -> None
      | Some config ->
        (* Only omit the warning once to avoid spamming the logs *)
	if not !emitted_keepalive_warning then begin
          Log.warn (fun f -> f "using keep-alives can cause excessive memory consumption: https://github.com/mirage/mirage-tcpip/issues/367");
          emitted_keepalive_warning := true
        end;
        Some (KEEPALIVE.create config (keepalive_cb t id wnd state urx)) in
    (* Construct basic PCB in Syn_received state *)
    let pcb = { state; rxq; txq; wnd; id; ack; urx; utx; keepalive } in
    (* Compose the overall thread from the various tx/rx threads
       and the main listener function *)
    let tx_thread = (Tx.thread t pcb ~send_ack ~rx_ack) in
    let rx_thread = (Rx.thread pcb ~rx_data) in
    let wnd_thread = (Wnd.thread ~utx ~urx ~wnd ~state ~tx_wnd_update) in
    let threads = [ tx_thread; rx_thread; wnd_thread ] in
    let catch_and_cancel = function
      | Lwt.Canceled -> ()
      | ex ->
        (* cancel the other threads *)
        List.iter Lwt.cancel threads;
        Log.err (fun f -> f "thread failure: [%s]. Terminating threads and closing connection"
                    (Printexc.to_string ex));
        on_close ();
        !Lwt.async_exception_hook ex
    in
    List.iter (fun t -> Lwt.on_failure t catch_and_cancel) threads;
    let th = Lwt.join threads in
    pcb_allocs := !pcb_allocs + 1;
    th_allocs := !th_allocs + 1;
    let fnpcb = fun _ -> pcb_frees := !pcb_frees + 1 in
    let fnth = fun _ -> th_frees := !th_frees + 1 in
    Gc.finalise fnpcb pcb;
    Gc.finalise fnth th;
    Lwt.return (pcb, th, opts)

  let new_server_connection t params id pushf keepalive =
    log_with_stats "new-server-connection" t;
    new_pcb t params id keepalive >>= fun (pcb, th, opts) ->
    STATE.tick pcb.state State.Passive_open;
    STATE.tick pcb.state (State.Send_synack params.tx_isn);
    (* Add the PCB to our listens table *)
    if Hashtbl.mem t.listens id then (
      Log.debug (fun f -> f "duplicate attempt to make a connection: %a .\
      Removing the old state and replacing with new attempt" WIRE.pp id);
      Hashtbl.remove t.listens id;
      Stats.decr_listen ();
    );
    Hashtbl.add t.listens id (params.tx_isn, (pushf, (pcb, th)));
    Stats.incr_listen ();
    (* Queue a SYN ACK for transmission *)
    let options = Options.MSS (Ip.mtu t.ip - Tcp_wire.sizeof_tcp) :: opts in
    TXS.output ~flags:Segment.Syn ~options pcb.txq (Cstruct.create 0) >>= fun () ->
    Lwt.return (pcb, th)

  let new_client_connection t params id ack_number keepalive =
    log_with_stats "new-client-connection" t;
    let tx_isn = params.tx_isn in
    let params = { params with tx_isn = Sequence.succ tx_isn } in
    new_pcb t params id keepalive >>= fun (pcb, th, _) ->
    (* A hack here because we create the pcb only after the SYN-ACK is rx-ed*)
    STATE.tick pcb.state (State.Send_syn tx_isn);
    (* Add the PCB to our connection table *)
    Hashtbl.add t.channels id (pcb, th);
    Stats.incr_channel ();
    STATE.tick pcb.state (State.Recv_synack ack_number);
    (* xmit ACK *)
    TXS.output pcb.txq (Cstruct.create 0) >>= fun () ->
    Lwt.return (pcb, th)

  let is_correct_ack ~tx_isn ~ack_number =
   (Sequence.compare (Sequence.succ tx_isn) ack_number) = 0

  let process_reset t id ~ack ~ack_number =
    log_with_stats "process-reset" t;
    if ack then
        match hashtbl_find t.connects id with
        | Some (wakener, tx_isn, _) ->
          (* We don't send data in the syn request, so the expected ack is tx_isn + 1 *)
          if is_correct_ack ~tx_isn ~ack_number then begin
            Hashtbl.remove t.connects id;
            Stats.decr_connect ();
            Lwt.wakeup wakener (Error `Refused);
            Lwt.return_unit
          end else
            Lwt.return_unit
        | None ->
          match hashtbl_find t.listens id with
          | Some (_, (_, (pcb, th))) ->
            Hashtbl.remove t.listens id;
            Stats.decr_listen ();
            STATE.tick pcb.state State.Recv_rst;
            Lwt.cancel th;
            Lwt.return_unit
          | None ->
            (* Incoming RST possibly to listen port - ignore per RFC793 pg65 *)
            Lwt.return_unit
    else
        (* rst without ack, drop it *)
        Lwt.return_unit

  let process_synack t id ~tx_wnd ~ack_number ~sequence ~options ~syn ~fin =
    log_with_stats "process-synack" t;
    match hashtbl_find t.connects id with
    | Some (wakener, tx_isn, keepalive) ->
      if is_correct_ack ~tx_isn ~ack_number then (
        Hashtbl.remove t.connects id;
        Stats.decr_connect ();
        let rx_wnd = 65535 in
        (* TODO: fix hardcoded value - it assumes that this value was
           sent in the SYN *)
        let rx_wnd_scaleoffer = wscale_default in
        new_client_connection t
          { tx_wnd; sequence; options; tx_isn; rx_wnd; rx_wnd_scaleoffer }
          id ack_number keepalive
        >>= fun (pcb, th) ->
        Lwt.wakeup wakener (Ok (pcb, th));
        Lwt.return_unit
      ) else
        (* Normally sending a RST reply to a random pkt would be in
           order but here we stay quiet since we are actively trying
           to connect this id *)
        Lwt.return_unit
    | None ->
      (* Incoming SYN-ACK with no pending connect and no matching pcb
         - send RST *)
      Tx.send_rst t id ~sequence ~ack_number ~syn ~fin
      >>= fun _ -> Lwt.return_unit (* discard errors; we won't retry *)

  let process_syn t id ~listeners ~tx_wnd ~ack_number ~sequence ~options ~syn ~fin =
    log_with_stats "process-syn" t;
    match listeners @@ WIRE.src_port id with
    | Some { process; keepalive } ->
      let tx_isn = Sequence.of_int32 (Randomconv.int32 Random.generate) in
      (* TODO: make this configurable per listener *)
      let rx_wnd = 65535 in
      let rx_wnd_scaleoffer = wscale_default in
      new_server_connection t
        { tx_wnd; sequence; options; tx_isn; rx_wnd; rx_wnd_scaleoffer }
        id process keepalive
      >>= fun _ ->
      Lwt.return_unit
    | None ->
      Tx.send_rst t id ~sequence ~ack_number ~syn ~fin
      >>= fun _ -> Lwt.return_unit (* discard errors; we won't retry *)

  let process_ack t id ~pkt =
    let open RXS in
    log_with_stats "process-ack" t;
    match hashtbl_find t.listens id with
    | Some (tx_isn, (pushf, newconn)) ->
      if Tcp_packet.(is_correct_ack ~tx_isn ~ack_number:pkt.header.ack_number) then begin
        (* Established connection - promote to active channels *)
        Hashtbl.remove t.listens id;
        Stats.decr_listen ();
        Hashtbl.add t.channels id newconn;
        Stats.incr_channel ();
        (* Finish processing ACK, so pcb.state is correct *)
        Rx.input t pkt newconn >>= fun () ->
        (* send new connection up to listener *)
        pushf (fst newconn)
      end else
        (* No RST because we are trying to connect on this id *)
        Lwt.return_unit
    | None ->
      match hashtbl_find t.connects id with
      | Some _ ->
        (* No RST because we are trying to connect on this id *)
        Lwt.return_unit
      | None ->
        let { sequence; Tcp_packet.ack_number; syn; fin; _ } = pkt.header in
        (* ACK but no matching pcb and no listen - send RST *)
        Tx.send_rst t id ~sequence ~ack_number ~syn ~fin
        >>= fun _ -> Lwt.return_unit (* if send fails, who cares *)

  let input_no_pcb t listeners (parsed, payload) id =
    let { sequence; Tcp_packet.ack_number; window; options; syn; fin; rst; ack; _ } = parsed in
    match rst, syn, ack with
    | true, _, _ -> process_reset t id ~ack ~ack_number
    | false, true, true ->
      process_synack t id ~ack_number ~sequence ~tx_wnd:window ~options ~syn ~fin
    | false, true , false -> process_syn t id ~listeners ~tx_wnd:window
			       ~ack_number ~sequence ~options ~syn ~fin
    | false, false, true  ->
      let open RXS in
      process_ack t id ~pkt:{ header = parsed; payload}
    | false, false, false ->
      Log.debug (fun f -> f "incoming packet matches no connection table entry and has no useful flags set; dropping it");
      Lwt.return_unit

  (* Main input function for TCP packets *)
  let input t ~listeners ~src ~dst data =
    let open Tcp_packet in
    match Unmarshal.of_cstruct data with
    | Error s -> Log.debug (fun f -> f "parsing TCP header failed: %s" s);
      Lwt.return_unit
    | Ok (pkt, payload) ->
      let id =
        WIRE.v ~src_port:pkt.dst_port ~dst_port:pkt.src_port ~dst:src ~src:dst
      in
      (* Lookup connection from the active PCB hash *)
      with_hashtbl t.channels id
        (* PCB exists, so continue the connection state machine in tcp_input *)
        (Rx.input t RXS.({header = pkt; payload}))
        (* No existing PCB, so check if it is a SYN for a listening function *)
        (input_no_pcb t listeners (pkt, payload))

  (* Blocking read on a PCB *)
  let read pcb =
    User_buffer.Rx.take_l pcb.urx
    >>= function
    | None   -> Lwt.return @@ Ok `Eof
    | Some t -> Lwt.return @@ Ok (`Data t)

  (* Maximum allowed write *)
  let write_available pcb =
    (* Our effective outgoing MTU is what can fit in a page *)
    min 4000 (min (Window.tx_mss pcb.wnd)
                (Int32.to_int (UTX.available pcb.utx)))

  (* Wait for more write space *)
  let write_wait_for pcb sz =
    UTX.wait_for pcb.utx (Int32.of_int sz)

  let rec writefn pcb wfn data =
    match State.state pcb.state with
    (* but it's only appropriate to send data if the connection is ready for it *)
    | State.Established | State.Close_wait -> begin
      let len = Cstruct.len data in
      match write_available pcb with
      | 0 -> (* no room at all; we must wait *)
        write_wait_for pcb 1 >>= fun () ->
        writefn pcb wfn data
      | av_len when av_len >= len -> (* we have enough room for the whole packet *)
        wfn [data] >>= fun n -> Lwt.return (Ok n)
      | av_len -> (* partial send is possible *)
        let sendable = Cstruct.sub data 0 av_len in
        writefn pcb wfn sendable >>= function
        | Ok () -> writefn pcb wfn @@ Cstruct.sub data av_len (len - av_len)
        | Error _ as e -> Lwt.return e
      end
    | _ -> Lwt.return (Error `Not_ready)

  let rec iter_s f = function
    | [] -> Lwt.return (Ok ())
    | h :: t -> f h >>= function
      | Ok () -> iter_s f t
      | e -> Lwt.return e

  (* Blocking write on a PCB *)
  let cast x = (x :> (unit, write_error) result Lwt.t)

  let write pcb data = writefn pcb (UTX.write pcb.utx) data |> cast
  let writev pcb data = iter_s (write pcb) data |> cast

  let write_nodelay pcb data = writefn pcb (UTX.write_nodelay pcb.utx) data |> cast
  let writev_nodelay pcb data = iter_s (write_nodelay pcb) data |> cast

  (* Close - no more will be written *)
  let close pcb = Tx.close pcb

  let dst pcb = WIRE.dst pcb.id, WIRE.dst_port pcb.id

  let getid t dst dst_port =
    (* TODO: make this more robust and recognise when all ports are gone *)
    let islistener _t _port =
      (* TODO keep a list of active listen ports *)
      false in
    let idinuse t id =
      Hashtbl.mem t.channels id ||
      Hashtbl.mem t.connects id ||
      Hashtbl.mem t.listens id
    in
    let inuse t id = islistener t (WIRE.src_port id) || idinuse t id in
    let rec bumpport t =
      (match t.localport with
       | 65535 -> t.localport <- 10000
       | _ -> t.localport <- t.localport + 1);
      let id =
        WIRE.v ~src:(Ip.src t.ip ~dst) ~src_port:t.localport ~dst ~dst_port
      in
      if inuse t id then bumpport t else id
    in
    bumpport t

  (* SYN retransmission timer *)
  let rec connecttimer t id tx_isn options window count =
    let rxtime = match count with
      | 0 -> 3 | 1 -> 6 | 2 -> 12 | 3 -> 24 | _ -> 48
    in
    Time.sleep_ns (Duration.of_sec rxtime) >>= fun () ->
    match hashtbl_find t.connects id with
    | None                -> Lwt.return_unit
    | Some (wakener, isn, _) ->
      if isn = tx_isn then
        if count > 3 then (
          Hashtbl.remove t.connects id;
          Stats.decr_connect ();
          Lwt.wakeup wakener (Error `Timeout);
          Lwt.return_unit
        ) else (
          Tx.send_syn t id ~tx_isn ~options ~window >>= function
          | Ok () -> connecttimer t id tx_isn options window (count + 1)
          | Error (`No_route _s) ->
            (* normal mechanism for recovery is fine *)
            connecttimer t id tx_isn options window (count + 1)
          | Error `Would_fragment ->
            (* this should not happen, if we've a transport that fragments syn.. *)
            Log.err (fun m -> m "syn retransmission timer returned would fragment");
            Lwt.return_unit
        )
      else Lwt.return_unit

  let connect ?keepalive t ~dst ~dst_port =
    let id = getid t dst dst_port in
    let tx_isn = Sequence.of_int32 (Randomconv.int32 Random.generate) in
    (* TODO: This is hardcoded for now - make it configurable *)
    let rx_wnd_scaleoffer = wscale_default in
    let options =
      Options.MSS (Ip.mtu t.ip - Tcp_wire.sizeof_tcp) :: Options.Window_size_shift rx_wnd_scaleoffer :: []
    in
    let window = 5840 in
    let th, wakener = MProf.Trace.named_task "TCP connect" in
    if Hashtbl.mem t.connects id then (
      Log.debug (fun f ->
          f "duplicate attempt to make a connection: [%a]. \
             Removing the old state and replacing with new attempt"
            WIRE.pp id);
      Hashtbl.remove t.connects id;
      Stats.decr_connect ();
    );
    Hashtbl.add t.connects id (wakener, tx_isn, keepalive);
    Stats.incr_connect ();
    Tx.send_syn t id ~tx_isn ~options ~window >>= function
    | Ok () | Error _ (* keep trying *) ->
      Lwt.async (fun () -> connecttimer t id tx_isn options window 0);
      th

  let log_failure daddr dport = function
  | `Timeout ->
    Log.debug (fun fmt ->
      fmt "Timeout attempting to connect to %a:%d\n%!"
        Ip.pp_ipaddr daddr dport)
  | `Refused ->
    Log.debug (fun fmt ->
      fmt "Refused connection to %a:%d\n%!"
        Ip.pp_ipaddr daddr dport)
  | e ->
    Log.debug (fun fmt ->
      fmt "%a error connecting to %a:%d\n%!"
        pp_error e Ip.pp_ipaddr daddr dport)

  let create_connection ?keepalive tcp (daddr, dport) =
    connect ?keepalive tcp ~dst:daddr ~dst_port:dport >>= function
    | Error e -> log_failure daddr dport e; Lwt.return @@ Error e
    | Ok (fl, _) -> Lwt.return (Ok fl)

  (* Construct the main TCP thread *)
  let connect ip =
    let localport =
      1024 + (Randomconv.int ~bound:(0xFFFF - 1024) Random.generate)
    in
    let listens = Hashtbl.create 1 in
    let connects = Hashtbl.create 1 in
    let channels = Hashtbl.create 7 in
    Lwt.return { ip; localport; channels; listens; connects }

  let disconnect _ = Lwt.return_unit
end
