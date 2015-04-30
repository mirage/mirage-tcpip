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

open Lwt
open Printf

let () = Random.self_init ()

module Tcp_wire = Wire_structs.Tcp_wire

cstruct pseudo_header {
    uint32_t src;
    uint32_t dst;
    uint8_t res;
    uint8_t proto;
    uint16_t len
  } as big_endian

type mode = [ `Synjitsu | `Synjitsu_app | `Normal ]

let mode_: mode ref = ref `Normal
let set_mode x = mode_ := x
let mode () = !mode_

module Make
    (KV: KV.S)(Ip:V1_LWT.IP)(Time:V1_LWT.TIME)(Clock:V1.CLOCK)(Random:V1.RANDOM) =
struct

  module RXS = Segment.Rx(Time)
  module TXS = Segment.Tx(Time)(Clock)
  module ACK = Ack.Immediate
  module UTX = User_buffer.Tx(Time)(Clock)
  module WIRE = Wire.Make(Ip)
  module STATE = State.Make(Time)

  type pcb = {
    id: WIRE.id;
    wnd: Window.t;            (* Window information *)
    rxq: RXS.t;               (* Received segments queue for out-of-order data *)
    txq: TXS.t;               (* Transmit segments queue *)
    ack: ACK.t;               (* Ack state *)
    state: State.t;           (* Connection state *)
    urx: User_buffer.Rx.t;    (* App rx buffer *)
    urx_close_t: unit Lwt.t;  (* App rx close thread *)
    urx_close_u: unit Lwt.u;  (* App rx connection close wakener *)
    utx: UTX.t;               (* App tx buffer *)
  }

  type connection = pcb * unit Lwt.t

  type connection_result = [ `Ok of connection | `Rst | `Timeout ]

  type t = {
    ip : Ip.t;
    listeners: int -> (pcb -> unit Lwt.t) option;
    mutable localport : int;
    channels: (WIRE.id, connection) Hashtbl.t;
    (* server connections the process of connecting - SYN-ACK sent
       waiting for ACK *)
    listens: (WIRE.id, (Sequence.t * ((pcb -> unit Lwt.t) * connection)))
        Hashtbl.t;
    (* clients in the process of connecting *)
    connects: (WIRE.id, (connection_result Lwt.u * Sequence.t)) Hashtbl.t;
  }

  let with_listeners listeners t = { t with listeners }

  let ip { ip; _ } = ip

  let verify_checksum _ _ _ = true

  let wscale_default = 2

  module Tx = struct

    (* Output a TCP packet, and calculate some settings from a state descriptor *)
    let xmit_pcb ip id ~flags ~wnd ~options ~seq datav =
      let window = Int32.to_int (Window.rx_wnd_unscaled wnd) in
      let rx_ack = Some (Window.rx_nxt wnd) in
      let syn = match flags with Segment.Syn -> true | _ -> false in
      let fin = match flags with Segment.Fin -> true | _ -> false in
      let rst = match flags with Segment.Rst -> true | _ -> false in
      let psh = match flags with Segment.Psh -> true | _ -> false in
      WIRE.xmit ~ip ~id ~syn ~fin ~rst ~psh ~rx_ack ~seq ~window ~options datav

    (* Output an RST response when we dont have a PCB *)
    let send_rst { ip; _ } id ~sequence ~ack_number ~syn ~fin =
      let datalen = Int32.add (if syn then 1l else 0l) (if fin then 1l else 0l) in
      let window = 0 in
      let options = [] in
      let seq = Sequence.of_int32 ack_number in
      let rx_ack = Some (Sequence.of_int32 (Int32.add sequence datalen)) in
      WIRE.xmit ~ip ~id ~rst:true ~rx_ack ~seq ~window ~options []

    (* Output a SYN packet *)
    let send_syn { ip; _ } id ~tx_isn ~options ~window =
      WIRE.xmit ~ip ~id ~syn:true ~rx_ack:None ~seq:tx_isn ~window ~options []

    (* Queue up an immediate close segment *)
    let close pcb =
      match State.state pcb.state with
      | State.Established | State.Close_wait ->
        UTX.wait_for_flushed pcb.utx >>= fun () ->
        (let { wnd; _ } = pcb in
         STATE.tick pcb.state (State.Send_fin (Window.tx_nxt wnd));
         TXS.output ~flags:Segment.Fin pcb.txq []
        )
      | _ -> return_unit

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
        xmit_pcb t.ip pcb.id ~flags ~wnd ~options ~seq [] >>= fun () ->
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
    let input _t pkt (pcb,_) =
      (* URG_TODO: Deal correctly with incomming RST segment *)
      let sequence = Sequence.of_int32 (Tcp_wire.get_tcp_sequence pkt) in
      let ack_number =
        Sequence.of_int32 (Tcp_wire.get_tcp_ack_number pkt)
      in
      let fin = Tcp_wire.get_fin pkt in
      let syn = Tcp_wire.get_syn pkt in
      let ack = Tcp_wire.get_ack pkt in
      let window = Tcp_wire.get_tcp_window pkt in
      let data = Wire.get_payload pkt in
      let seg =
        RXS.segment ~sequence ~fin ~syn ~ack ~ack_number ~window ~data
      in
      let { rxq; _ } = pcb in
      (* Coalesce any outstanding segments and retrieve ready segments *)
      RXS.input rxq seg

    (* Thread that spools the data into an application receive buffer,
       and notifies the ACK subsystem that new data is here *)
    let thread (pcb:pcb) ~rx_data =
      let { wnd; ack; urx; urx_close_u; _ } = pcb in
      (* Thread to monitor application receive and pass it up *)
      let rec rx_application_t () =
        Lwt_mvar.take rx_data >>= fun (data, winadv) ->
        begin match winadv with
          | None -> return_unit
          | Some winadv ->
            if (winadv > 0) then (
              Window.rx_advance wnd winadv;
              ACK.receive ack (Window.rx_nxt wnd)
            ) else (
              Window.rx_advance wnd winadv;
              ACK.pushack ack (Window.rx_nxt wnd)
            )
        end >>= fun _ ->
        begin match data with
          | None ->
            STATE.tick pcb.state State.Recv_fin;
            Lwt.wakeup urx_close_u ();
            User_buffer.Rx.add_r urx None >>= fun () ->
            rx_application_t ()
          | Some data ->
            let rec queue = function
              | hd::tl ->
                User_buffer.Rx.add_r urx (Some hd) >>= fun () ->
                queue tl
              | [] -> return_unit in
            queue data >>= fun _ ->
            rx_application_t ()
        end
      in
      rx_application_t ()
  end

  module Wnd = struct

    let thread ~urx:_ ~utx ~wnd:_ ~tx_wnd_update =
      (* Monitor our transmit window when updates are received
         remotely, and tell the application that new space is
         available when it is blocked *)
      let rec tx_window_t () =
        Lwt_mvar.take tx_wnd_update >>= fun tx_wnd ->
        UTX.free utx tx_wnd >>= fun () ->
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
    (* TODO: add more info to log msgs *)
    match hashtbl_find t.channels id with
    | Some _ ->
      (* printf "TCP: removing pcb from tables\n%!";*)
      Hashtbl.remove t.channels id
    | None ->
      match hashtbl_find t.listens id with
      | Some (isn, _) ->
        if isn = tx_isn then (
          printf "TCP: removing incomplete listen pcb\n%!";
          Hashtbl.remove t.listens id
        )
      | None ->
        printf "TCP: error in removing pcb - no such connection\n%!"

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

  module Syn = struct

    type t =
      { tx_wnd: int;
        sequence: int32;
        options: Options.t list;
        tx_isn: Sequence.t;
        rx_wnd: int;
        rx_wnd_scaleoffer: int }

    let short_path_of_id id = WIRE.path_of_id id
    let path_of_id id = short_path_of_id id @ ["syn"]

    let read t id =
      let path = path_of_id id in
      KV.read path >>= function
      | None   -> return_none
      | Some _ ->
        (* XXX: use a transaction *)
        let read k = KV.read (path @ [k]) in
        let (>>|) x f =
          x >>= function
          | None   -> return_none
          | Some x -> f x in
        read "tx_wnd"   >>| fun tx_wnd ->
        read "sequence" >>| fun sequence ->
        read "options"  >>| fun options ->
        read "tx_isn"   >>| fun tx_isn ->
        read "rx_wnd"   >>| fun rx_wnd ->
        read "rx_wnd_scaleoffer" >>| fun rx_wnd_scaleoffer ->
        KV.remove (short_path_of_id id) >>= fun () ->
        try
          let tx_wnd = int_of_string tx_wnd in
          let sequence = Int32.of_string sequence in
          let options = Options.of_string options in
          let tx_isn = Sequence.of_string tx_isn in
          let rx_wnd = int_of_string rx_wnd in
          let rx_wnd_scaleoffer = int_of_string rx_wnd_scaleoffer in
          return
            (Some { tx_wnd; sequence; options; tx_isn; rx_wnd; rx_wnd_scaleoffer })
        with Failure _ ->
          KV.remove path >>= fun () ->
          return_none

    let write t id params =
      let { tx_wnd; sequence; options; tx_isn; rx_wnd; rx_wnd_scaleoffer } =
        params
      in
      let path = path_of_id id in
      let key k = path @ [k] in
      KV.writev [
        key "tx_wnd"           , string_of_int tx_wnd;
        key "sequence"         , Int32.to_string sequence;
        key "options"          , Options.to_string options;
        key "tx_isn"           , Sequence.to_string tx_isn;
        key "rx_wnd"           , string_of_int rx_wnd;
        key "rx_wnd_scaleoffer", string_of_int rx_wnd_scaleoffer
      ]

  end

  let new_pcb t params id =
    let { Syn.tx_wnd; sequence; options; tx_isn; rx_wnd; rx_wnd_scaleoffer } =
      params
    in
    let tx_mss = List.fold_left (fun a ->
        function Options.MSS m -> Some m | _ -> a
      ) None options
    in
    let (rx_wnd_scale, tx_wnd_scale), opts =
      resolve_wnd_scaling options rx_wnd_scaleoffer
    in
    (* Set up the windowing variables *)
    let rx_isn = Sequence.of_int32 sequence in
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
    let urx_close_t, urx_close_u = MProf.Trace.named_task "urx_close" in
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
    let ack = ACK.t ~send_ack ~last:(Sequence.incr rx_isn) in
    (* Construct basic PCB in Syn_received state *)
    let pcb = { state; rxq; txq; wnd; id; ack; urx; urx_close_t; urx_close_u; utx } in
    (* Compose the overall thread from the various tx/rx threads
       and the main listener function *)
    let th =
      (Tx.thread t pcb ~send_ack ~rx_ack) <?>
      (Rx.thread pcb ~rx_data) <?>
      (Wnd.thread ~utx ~urx ~wnd ~tx_wnd_update)
    in
    pcb_allocs := !pcb_allocs + 1;
    th_allocs := !th_allocs + 1;
    let fnpcb = fun _ -> pcb_frees := !pcb_frees + 1 in
    let fnth = fun _ -> th_frees := !th_frees + 1 in
    Gc.finalise fnpcb pcb;
    Gc.finalise fnth th;
    return (pcb, th, opts)

  let is_not_for_me t id =
    not (List.mem id.WIRE.local_ip (Ip.get_ip t.ip))

  let string_of_ip ip = Ipaddr.to_string (Ip.to_uipaddr ip)

  let is_managed t id =
    let ip = [string_of_ip id.WIRE.local_ip] in
    KV.read ip >>= function
    | Some "managed" -> return true
    | _ -> return false

  let new_server_connection t params id pushf = match pushf with
    | Some pushf ->
      new_pcb t params id >>= fun (pcb, th, opts) ->
      STATE.tick pcb.state State.Passive_open;
      STATE.tick pcb.state (State.Send_synack params.Syn.tx_isn);
      (* Add the PCB to our listens table *)
      Hashtbl.replace t.listens id (params.Syn.tx_isn, (pushf, (pcb, th)));
      (* Queue a SYN ACK for transmission *)
      let options = Options.MSS 1460 :: opts in
      TXS.output ~flags:Segment.Syn ~options pcb.txq []
    | None ->
      if not (!mode_ = `Synjitsu && is_not_for_me t id) then return_unit
      else is_managed t id >>= function
        | true  -> return_unit
        | false ->
          printf "Synjitsu: writing the SYN parameters to xenstore ...\n";
          Syn.write t id params

  let new_client_connection t params id ack_number =
    let tx_isn = params.Syn.tx_isn in
    let params = { params with Syn.tx_isn = Sequence.incr tx_isn } in
    new_pcb t params id >>= fun (pcb, th, _) ->
    (* A hack here because we create the pcb only after the SYN-ACK is rx-ed*)
    STATE.tick pcb.state (State.Send_syn tx_isn);
    (* Add the PCB to our connection table *)
    Hashtbl.add t.channels id (pcb, th);
    STATE.tick pcb.state (State.Recv_synack (Sequence.of_int32 ack_number));
    (* xmit ACK *)
    TXS.output pcb.txq [] >>= fun () ->
    return (pcb, th)

  let process_reset t id =
    if is_not_for_me t id then return_unit
    else match hashtbl_find t.connects id with
      | Some (wakener, _) ->
        (* URG_TODO: check if RST ack num is valid before it is accepted *)
        Hashtbl.remove t.connects id;
        Lwt.wakeup wakener `Rst;
        return_unit
      | None ->
        match hashtbl_find t.listens id with
        | Some (_, (_, (pcb, th))) ->
          Hashtbl.remove t.listens id;
          STATE.tick pcb.state State.Recv_rst;
          Lwt.cancel th;
          return_unit
        | None ->
          (* Incoming RST possibly to listen port - ignore per RFC793 pg65 *)
          return_unit

  let process_synack t id ~pkt ~ack_number ~sequence ~options ~syn ~fin =
    if is_not_for_me t id then return_unit
    else match hashtbl_find t.connects id with
      | Some (wakener, tx_isn) ->
        if Sequence.(to_int32 (incr tx_isn)) = ack_number then (
          Hashtbl.remove t.connects id;
          let tx_wnd = Tcp_wire.get_tcp_window pkt in
          let rx_wnd = 65535 in
          (* TODO: fix hardcoded value - it assumes that this value was
             sent in the SYN *)
          let rx_wnd_scaleoffer = wscale_default in
          new_client_connection t
            { Syn.tx_wnd; sequence; options; tx_isn; rx_wnd; rx_wnd_scaleoffer }
            id ack_number
          >>= fun (pcb, th) ->
          Lwt.wakeup wakener (`Ok (pcb, th));
          return_unit
        ) else
          (* Normally sending a RST reply to a random pkt would be in
             order but here we stay quiet since we are actively trying
             to connect this id *)
          return_unit
      | None ->
        (* Incomming SYN-ACK with no pending connect and no matching pcb
           - send RST *)
        Tx.send_rst t id ~sequence ~ack_number ~syn ~fin

  let process_syn t id ~pkt ~ack_number ~sequence ~options ~syn ~fin =
    if !mode_ <> `Synjitsu && is_not_for_me t id then return_unit
    else
      let send_syn pushf =
        let tx_isn = Sequence.of_int ((Random.int 65535) + 0x1AFE0000) in
        let tx_wnd = Tcp_wire.get_tcp_window pkt in
        (* TODO: make this configurable per listener *)
        let rx_wnd = 65535 in
        let rx_wnd_scaleoffer = wscale_default in
        let params =
          { Syn.tx_wnd; sequence; options; tx_isn; rx_wnd; rx_wnd_scaleoffer }
        in
        new_server_connection t params id pushf
      in
      if !mode_ = `Synjitsu && is_not_for_me t id then send_syn None
      else match t.listeners id.WIRE.local_port with
        | Some pushf -> send_syn (Some pushf)
        | None       -> Tx.send_rst t id ~sequence ~ack_number ~syn ~fin

  let process_syn_cookies t id =
    match t.listeners id.WIRE.local_port with
    | None       -> return_unit
    | Some pushf ->
      Syn.read t id >>= function
      | Some params ->
        printf "Found SYN cookies.\n";
        new_server_connection t params id (Some pushf)
      | None ->
        printf "No SYN cookies.\n";
        return_unit

  let process_ack t id ~pkt ~ack_number ~sequence ~syn ~fin =
    if is_not_for_me t id then return_unit
    else match hashtbl_find t.listens id with
      | Some (tx_isn, (pushf, newconn)) ->
        if Sequence.(to_int32 (incr tx_isn)) = ack_number then (
          (* Established connection - promote to active channels *)
          Hashtbl.remove t.listens id;
          Hashtbl.add t.channels id newconn;
          (* Finish processing ACK, so pcb.state is correct *)
          Rx.input t pkt newconn >>= fun () ->
          (* send new connection up to listener *)
          pushf (fst newconn)
        ) else
          (* No RST because we are trying to connect on this id *)
          return_unit
      | None ->
        match hashtbl_find t.connects id with
        | Some _ ->
          (* No RST because we are trying to connect on this id *)
          return_unit
        | None ->
          (* ACK but no matching pcb and no listen - send RST *)
          Tx.send_rst t id ~sequence ~ack_number ~syn ~fin

  let input_no_pcb t pkt id =
    match Tcp_wire.get_rst pkt with
    | true -> process_reset t id
    | false ->
      let sequence = Tcp_wire.get_tcp_sequence pkt in
      let options = Wire.get_options pkt in
      let ack_number = Tcp_wire.get_tcp_ack_number pkt in
      let syn = Tcp_wire.get_syn pkt in
      let ack = Tcp_wire.get_ack pkt in
      let fin = Tcp_wire.get_fin pkt in
      match syn, ack with
      | true , true  -> process_synack t id ~pkt ~ack_number ~sequence
                          ~options ~syn ~fin
      | true , false -> process_syn t id ~pkt ~ack_number ~sequence
                          ~options ~syn ~fin
      | false, true  -> process_ack t id ~pkt ~ack_number ~sequence ~syn ~fin
      | false, false ->
        (* What the hell is this packet? No SYN,ACK,RST *)
        return_unit

  (* Main input function for TCP packets *)
  let input t ~src ~dst data =
    match verify_checksum src dst data with
    | false -> printf "RX.input: checksum error\n%!"; return_unit
    | true ->
      let source_port = Tcp_wire.get_tcp_src_port data in
      let dest_port = Tcp_wire.get_tcp_dst_port data in
      let id =
        { WIRE.local_port = dest_port;
          dest_ip         = src;
          local_ip        = dst;
          dest_port       = source_port }
      in
      (* Lookup connection from the active PCB hash *)
      with_hashtbl t.channels id
        (* PCB exists, so continue the connection state machine in tcp_input *)
        (Rx.input t data)
        (* No existing PCB, so check if it is a SYN for a listening function *)
        (input_no_pcb t data)

  (* Blocking read on a PCB *)
  let read pcb =
    User_buffer.Rx.take_l pcb.urx

  (* Maximum allowed write *)
  let write_available pcb =
    (* Our effective outgoing MTU is what can fit in a page *)
    min 4000 (min (Window.tx_mss pcb.wnd)
                (Int32.to_int (UTX.available pcb.utx)))

  (* URG_TODO: raise exception if not in Established or Close_wait state *)
  (* Wait for more write space *)
  let write_wait_for pcb sz =
    UTX.wait_for pcb.utx (Int32.of_int sz)

  let rec writefn pcb wfn data =
    let len = Cstruct.len data in
    match write_available pcb with
    | 0 ->
      write_wait_for pcb 1 >>= fun () ->
      writefn pcb wfn data
    | av_len when av_len < len ->
      let first_bit = Cstruct.sub data 0 av_len in
      let remaing_bit = Cstruct.sub data av_len (len - av_len) in
      writefn pcb wfn first_bit  >>= fun () ->
      writefn pcb wfn remaing_bit
    | _ -> wfn [data]

  (* URG_TODO: raise exception when trying to write to closed connection
               instead of quietly returning *)
  (* Blocking write on a PCB *)
  let write pcb data = writefn pcb (UTX.write pcb.utx) data
  let writev pcb data = Lwt_list.iter_s (fun d -> write pcb d) data

  let write_nodelay pcb data = writefn pcb (UTX.write_nodelay pcb.utx) data
  let writev_nodelay pcb data =
    Lwt_list.iter_s (fun d -> write_nodelay pcb d) data

  (* Close - no more will be written *)
  let close pcb =
    Tx.close pcb

  let get_dest pcb =
    pcb.id.WIRE.dest_ip, pcb.id.WIRE.dest_port

  let getid t dest_ip dest_port =
    (* TODO: make this more robust and recognise when all ports are gone *)
    let islistener _t _port =
      (* TODO keep a list of active listen ports *)
      false in
    let idinuse t id =
      Hashtbl.mem t.channels id ||
      Hashtbl.mem t.connects id ||
      Hashtbl.mem t.listens id
    in
    let inuse t id = islistener t id.WIRE.local_port || idinuse t id in
    let rec bumpport t =
      (match t.localport with
       | 65535 -> t.localport <- 10000
       | _ -> t.localport <- t.localport + 1);
      let id =
        { WIRE.local_port = t.localport;
          dest_ip         = dest_ip;
          local_ip        = Ip.get_source t.ip dest_ip;
          dest_port       = dest_port }
      in
      if inuse t id then bumpport t else id
    in
    bumpport t

  (* SYN retransmission timer *)
  let rec connecttimer t id tx_isn options window count =
    let rxtime = match count with
      | 0 -> 3. | 1 -> 6. | 2 -> 12. | 3 -> 24. | _ -> 48.
    in
    Time.sleep rxtime >>= fun () ->
    match hashtbl_find t.connects id with
    | Some (wakener, isn) ->
      if isn = tx_isn then
        if count > 3 then (
          Hashtbl.remove t.connects id;
          Lwt.wakeup wakener `Timeout;
          return_unit
        ) else (
          Tx.send_syn t id ~tx_isn ~options ~window >>= fun () ->
          connecttimer t id tx_isn options window (count + 1)
        )
      else
        return_unit
    | None ->
      return_unit

  let connect t ~dest_ip ~dest_port =
    let id = getid t dest_ip dest_port in
    let tx_isn = Sequence.of_int ((Random.int 65535) + 0x1BCD0000) in
    (* TODO: This is hardcoded for now - make it configurable *)
    let rx_wnd_scaleoffer = wscale_default in
    let options =
      Options.MSS 1460 :: Options.Window_size_shift rx_wnd_scaleoffer :: []
    in
    let window = 5840 in
    let th, wakener = MProf.Trace.named_task "TCP connect" in
    if Hashtbl.mem t.connects id then
      printf "WARNING: connection already being attempted\n%!";
    Hashtbl.replace t.connects id (wakener, tx_isn);
    Tx.send_syn t id ~tx_isn ~options ~window >>= fun () ->
    let _ = connecttimer t id tx_isn options window 0 in
    th

  let watchers = Hashtbl.create 4

  let watch ~log t =
    log "Pcb.watch" >>= fun () ->
    let log fmt = Printf.ksprintf log fmt in
    let ips = List.map string_of_ip (Ip.get_ip t.ip) in
    let read_xs ip =
      KV.dirs [ip] >>= fun ports ->
      log "Ports: %s" (String.concat " " ports) >>= fun () ->
      Lwt_list.fold_left_s (fun acc port ->
          KV.dirs [ip; port] >>= fun dest_ips ->
          log "Dest-ip: %s" (String.concat " " dest_ips) >>= fun () ->
          Lwt_list.fold_left_s (fun acc dest_ip ->
              KV.dirs [ip; port; dest_ip] >>= fun dest_ports ->
              log "Dest-ports: %s" (String.concat " " dest_ports) >>= fun () ->
              Lwt_list.fold_left_s (fun acc dest_port ->
                  let id = WIRE.id_of_path [ip; port; dest_ip; dest_port] in
                  return (id :: acc)
                ) acc dest_ports
            ) acc dest_ips
        ) [] ports
      >>= fun ids ->
      printf "Found %d started connections.\n" (List.length ids);
      Lwt_list.iter_p (fun id ->
          Lwt.catch
            (fun () -> process_syn_cookies t id)
            (fun e -> printf "Error: %s" (Printexc.to_string e); return_unit)
        ) ids >>= fun () ->
      return_unit
    in
    if !mode_ = `Synjitsu_app && not (Hashtbl.mem watchers t.ip) then (
      printf "Synjitsu-app mode. Watching xenstore for incoming SYN!\n";
      Hashtbl.add watchers t.ip ();
      Lwt_list.iter_p (fun ip ->
          KV.writev [ [ip], "managed" ] >>= fun () ->
          read_xs ip
        ) ips
    ) else return_unit

  (* Construct the main TCP thread *)
  let create ip =
    let localport = 10000 + (Random.int 10000) in
    let listens = Hashtbl.create 1 in
    let connects = Hashtbl.create 1 in
    let channels = Hashtbl.create 7 in
    let listeners = fun _ -> None in
    Lwt.return { ip; localport; channels; listens; connects; listeners }

end
