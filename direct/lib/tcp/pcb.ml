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
open Nettypes
open Printf
open State
open Wire

type pcb = {
  id: id;
  wnd: Window.t;            (* Window information *)
  rxq: Segment.Rx.q;        (* Received segments queue for out-of-order data *)
  txq: Segment.Tx.q;        (* Transmit segments queue *)
  ack: Ack.Delayed.t;       (* Ack state *)
  state: State.t;           (* Connection state *)
  urx: User_buffer.Rx.t;    (* App rx buffer *)
  urx_close_t: unit Lwt.t;  (* App rx close thread *)
  urx_close_u: unit Lwt.u;  (* App rx connection close wakener *)
  utx: User_buffer.Tx.t;    (* App tx buffer *)
}

type connection = (pcb * unit Lwt.t) 

type t = {
  ip : Ipv4.t;
  channels: (id, connection) Hashtbl.t;
  listeners: (int, (connection Lwt_stream.t * (connection option -> unit))) Hashtbl.t;
  (* server connections the process of connecting - SYN-ACK sent waiting for ACK *)
  listens: (id, (Sequence.t * ((connection option -> unit) * connection))) Hashtbl.t;
  (* clients in the process of connecting *)
  connects: (id, (connection option Lwt.u * Sequence.t)) Hashtbl.t;
}

type listener = {
  t: t;
  port: int;
}

(* TODO: implement *)
let verify_checksum pkt = true

let wscale_default = 2

module Tx = struct

  (* Output a TCP packet, and calculate some settings from a state descriptor *)
  let xmit_pcb ip id ~flags ~wnd ~options ~seq datav =
    let window = Int32.to_int (Window.rx_wnd_unscaled wnd) in
    let rx_ack = Some (Window.rx_nxt wnd) in
    let syn = match flags with Segment.Tx.Syn -> true |_ -> false in
    let fin = match flags with Segment.Tx.Fin -> true |_ -> false in
    let rst = match flags with Segment.Tx.Rst -> true |_ -> false in
    let psh = match flags with Segment.Tx.Psh -> true |_ -> false in
    xmit ~ip ~id ~syn ~fin ~rst ~psh ~rx_ack ~seq ~window ~options datav

  (* Output an RST response when we dont have a PCB *)
  let send_rst {ip} id ~sequence ~ack_number ~syn ~fin (* ~data *) =
    (* XXX XXX what is data for here? -avsm *)
    let datalen = Int32.add (if syn then 1l else 0l) (if fin then 1l else 0l) in
    let window = 0 in
    let options = [] in
    let seq = Sequence.of_int32 ack_number in
    let rx_ack = Some (Sequence.of_int32 (Int32.add sequence datalen)) in
    xmit ~ip ~id ~rst:true ~rx_ack ~seq ~window ~options []

  (* Output a SYN packet *)
  let send_syn {ip} id ~tx_isn ~options ~window = 
    xmit ~ip ~id ~syn:true ~rx_ack:None ~seq:tx_isn ~window ~options []

  (* Queue up an immediate close segment *)
  let close pcb =
    match state pcb.state with
    | Established | Close_wait ->
      User_buffer.Tx.wait_for_flushed pcb.utx >>
      Segment.Tx.output ~flags:Segment.Tx.Fin pcb.txq []
    |_ -> return ()
     
  (* Thread that transmits ACKs in response to received packets,
     thus telling the other side that more can be sent, and
     also data from the user transmit queue *)
  let rec thread t pcb ~send_ack ~rx_ack  =
    let {wnd; ack} = pcb in

    (* Transmit an empty ack when prompted by the Ack thread *)
    let rec send_empty_ack () =
      lwt _ = Lwt_mvar.take send_ack in
      let ack_number = Window.rx_nxt wnd in
      let flags = Segment.Tx.No_flags in
      let options = [] in
      let seq = Window.tx_nxt wnd in
      Ack.Delayed.transmit ack ack_number >>
      xmit_pcb t.ip pcb.id ~flags ~wnd ~options ~seq [] >>
      send_empty_ack () in
    (* When something transmits an ACK, tell the delayed ACK thread *)
    let rec notify () =
      lwt ack_number = Lwt_mvar.take rx_ack in
      Ack.Delayed.transmit ack ack_number >>
      notify () in
    send_empty_ack () <&> (notify ())
end

module Rx = struct

  (* Process an incoming TCP packet that has an active PCB *)
  let input t pkt (pcb,_) =
    (* TODO: implement verify checksum *)
    match verify_checksum pkt with
    | false -> return (printf "RX.input: checksum error\n%!")
    | true ->
	(* URG_TODO: Deal correctly with incomming RST segment *)
        let sequence = Sequence.of_int32 (Wire.get_tcpv4_sequence pkt) in
        let ack_number = Sequence.of_int32 (Wire.get_tcpv4_ack_number pkt) in
        let fin = Wire.get_fin pkt in
        let syn = Wire.get_syn pkt in
        let ack = Wire.get_ack pkt in
        let window = Wire.get_tcpv4_window pkt in
        let data = Wire.get_payload pkt in
        let seg = Segment.Rx.make ~sequence ~fin ~syn ~ack ~ack_number ~window ~data in
        let {rxq} = pcb in
        (* Coalesce any outstanding segments and retrieve ready segments *)
        Segment.Rx.input rxq seg
   
  (* Thread that spools the data into an application receive buffer,
     and notifies the ACK subsystem that new data is here *)
  let thread pcb ~rx_data =
    let {wnd; ack; urx; urx_close_u} = pcb in
    (* Thread to monitor application receive and pass it up *)
    let rec rx_application_t () =
      lwt data, winadv = Lwt_mvar.take rx_data in
      lwt _ = match winadv with
      | None -> return ()
      | Some winadv -> begin
          if (winadv > 0) then begin
            Window.rx_advance wnd winadv;
            Ack.Delayed.receive ack (Window.rx_nxt wnd)
          end else begin
            Window.rx_advance wnd winadv;
            Ack.Delayed.pushack ack (Window.rx_nxt wnd)
          end
      end in
      match data with
      |None ->
        (* lwt _ = Ack.Delayed.pushack ack (Window.rx_nxt wnd) in *)
        State.tick pcb.state State.Recv_fin;
        Lwt.wakeup urx_close_u ();
        User_buffer.Rx.add_r urx None >>
        rx_application_t ()
      |Some data ->
        let rec queue = function
        |hd::tl ->
           User_buffer.Rx.add_r urx (Some hd) >>
           queue tl
        |[] -> return () in
      lwt _ = queue data in
      rx_application_t ()
    in   
    rx_application_t ()
end

module Wnd = struct

  let thread ~urx ~utx ~wnd ~tx_wnd_update =
    (* Monitor our transmit window when updates are received remotely,
       and tell the application that new space is available when it is blocked *)
    let rec tx_window_t () =
      lwt tx_wnd = Lwt_mvar.take tx_wnd_update in
      User_buffer.Tx.free utx tx_wnd >>
      tx_window_t ()
    in
    tx_window_t ()
    
end

(* Helper function to apply function with contents of hashtbl, or take default action *)
let with_hashtbl h k fn default =
  try fn (Hashtbl.find h k) with Not_found -> default k

let hashtbl_find h k =
  try Some (Hashtbl.find h k) with Not_found -> None


let clearpcb t id tx_isn =
  (* TODO: add more info to log msgs *)
  match (hashtbl_find t.channels id) with
  | Some _ ->
      (* printf "TCP: removing pcb from tables\n%!";*)
      Hashtbl.remove t.channels id
  | None ->
      match (hashtbl_find t.listens id) with
      | Some (isn, _) -> 
	  if isn = tx_isn then begin
	    printf "TCP: removing incomplete listen pcb\n%!";
	    Hashtbl.remove t.listens id
	  end
      | None ->
	  printf "TCP: error in removing pcb - no such connection\n%!"


let pcb_allocs = ref 0
let th_allocs = ref 0
let pcb_frees = ref 0
let th_frees = ref 0


let new_pcb t ~rx_wnd ~rx_wnd_scale ~tx_wnd ~tx_wnd_scale ~sequence ~tx_mss ~tx_isn id =
  (* Set up the windowing variables *)
  let rx_isn = Sequence.of_int32 sequence in
  (* Initialise the window handler *)
  let wnd = Window.t ~rx_wnd_scale ~tx_wnd_scale ~rx_wnd ~tx_wnd ~rx_isn ~tx_mss ~tx_isn in
  (* When we transmit an ACK for a received segment, rx_ack is written to *)
  let rx_ack = Lwt_mvar.create_empty () in
  (* When we receive an ACK for a transmitted segment, tx_ack is written to *)
  let tx_ack = Lwt_mvar.create_empty () in
  (* When new data is received, rx_data is written to *)
  let rx_data = Lwt_mvar.create_empty () in
  (* Write to this mvar to transmit an empty ACK to the remote side *) 
  let send_ack = Lwt_mvar.create_empty () in
  (* The user application receive buffer and close notification *)
  let rx_buf_size = Window.rx_wnd wnd in
  let urx = User_buffer.Rx.create ~max_size:rx_buf_size ~wnd in 
  let urx_close_t, urx_close_u = Lwt.task () in
  (* The window handling thread *)
  let tx_wnd_update = Lwt_mvar.create_empty () in
  (* Set up transmit and receive queues *)
  let on_close () = clearpcb t id tx_isn in
  let state = State.t ~on_close in
  let txq, tx_t = Segment.Tx.q ~xmit:(Tx.xmit_pcb t.ip id) ~wnd ~state ~rx_ack ~tx_ack ~tx_wnd_update in
  (* The user application transmit buffer *)
  let utx = User_buffer.Tx.create ~wnd ~txq ~max_size:16384l in
  let rxq = Segment.Rx.q ~rx_data ~wnd ~state ~tx_ack in
  (* Set up ACK module *)
  let ack = Ack.Delayed.t ~send_ack ~last:(Sequence.incr rx_isn) in
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
  let fnpcb = fun x -> pcb_frees := !pcb_frees + 1 in
  let fnth = fun x -> th_frees := !th_frees + 1 in
  Gc.finalise fnpcb pcb;
  Gc.finalise fnth th;
  return (pcb, th)


let resolve_wnd_scaling options rx_wnd_scaleoffer = 
  let tx_wnd_scale = List.fold_left
      (fun a -> function Options.Window_size_shift m -> Some m |_ -> a) None options in
  match tx_wnd_scale with
  | None -> (0, 0), []
  | Some tx_f -> (rx_wnd_scaleoffer, tx_f), (Options.Window_size_shift rx_wnd_scaleoffer :: [])


let new_server_connection t ~tx_wnd ~sequence ~options ~tx_isn ~rx_wnd ~rx_wnd_scaleoffer ~pushf id =
  let tx_mss = List.fold_left (fun a -> function Options.MSS m -> Some m |_ -> a) None options in
  let (rx_wnd_scale, tx_wnd_scale), opts = resolve_wnd_scaling options rx_wnd_scaleoffer in
  lwt pcb, th = new_pcb t ~rx_wnd ~rx_wnd_scale ~tx_wnd ~tx_wnd_scale ~sequence ~tx_mss ~tx_isn id in
  State.tick pcb.state State.Passive_open;
  State.tick pcb.state (State.Send_synack tx_isn);
  (* Add the PCB to our listens table *)
  Hashtbl.replace t.listens id (tx_isn, (pushf, (pcb, th)));
  (* Queue a SYN ACK for transmission *)
  let options = Options.MSS 1460 :: opts in
  lwt () = Segment.Tx.output ~flags:Segment.Tx.Syn ~options pcb.txq [] in
  return (pcb, th)


let new_client_connection t ~tx_wnd ~sequence ~ack_number ~options ~tx_isn ~rx_wnd ~rx_wnd_scaleoffer id =
  let tx_mss = List.fold_left (fun a -> function Options.MSS m -> Some m |_ -> a) None options in
  let (rx_wnd_scale, tx_wnd_scale), _ = resolve_wnd_scaling options rx_wnd_scaleoffer in
  lwt pcb, th = new_pcb t ~rx_wnd ~rx_wnd_scale ~tx_wnd ~tx_wnd_scale ~sequence ~tx_mss ~tx_isn:(Sequence.incr tx_isn) id in
  (* A hack here because we create the pcb only after the SYN-ACK is rx-ed*)
  State.tick pcb.state (State.Send_syn tx_isn);
  (* Add the PCB to our connection table *)
  Hashtbl.add t.channels id (pcb, th);
  State.tick pcb.state (State.Recv_synack (Sequence.of_int32 ack_number));
  (* xmit ACK *)  
  lwt () = Segment.Tx.output pcb.txq [] in
  return (pcb, th)

let input_no_pcb t pkt id =
  (* TODO: implement verify checksum *)
  match verify_checksum pkt with
  |false -> return (printf "RX.input: checksum error\n%!")
  |true ->
      match Wire.get_rst pkt with
      |true -> begin
        match (hashtbl_find t.connects id) with
        | Some (wakener, _) -> begin
          (* URG_TODO: check if RST ack num is valid before it is accepted *)
          Hashtbl.remove t.connects id;
          Lwt.wakeup wakener None;
          return ()
        end
        | None -> 
          match (hashtbl_find t.listens id) with
          | Some (_, (_, (pcb, th))) -> begin
            Hashtbl.remove t.listens id;
	    tick pcb.state Recv_rst;
            Lwt.cancel th;
            return ()
	  end
          | None -> 
            (* Incoming RST possibly to listen port - ignore per RFC793 pg65 *)
            return ()
      end
      |false -> begin
        let sequence = Wire.get_tcpv4_sequence pkt in
        let options = Wire.get_options pkt in
        let ack_number = Wire.get_tcpv4_ack_number pkt in
        let syn = Wire.get_syn pkt in
        let fin = Wire.get_fin pkt in
        match syn with
        | true -> begin
          match Wire.get_ack pkt with
          | true -> begin
            match (hashtbl_find t.connects id) with
            | Some (wakener, tx_isn) -> begin
              if Sequence.(to_int32 (incr tx_isn)) = ack_number then begin
                Hashtbl.remove t.connects id;
		let tx_wnd = Wire.get_tcpv4_window pkt in
		let rx_wnd = 65535 in
		(* TODO: fix hardcoded value - it assumes that this value was sent in the SYN *)
		let rx_wnd_scaleoffer = wscale_default in
                lwt (pcb, th) = new_client_connection
                  t ~tx_wnd ~sequence ~ack_number ~options ~tx_isn ~rx_wnd ~rx_wnd_scaleoffer id in
                Lwt.wakeup wakener (Some (pcb, th));
                return ()
              end else begin
                (* Normally sending a RST reply to a random pkt would be in order but 
                   here we stay quiet since we are actively trying to connect this id *)
                return ()
              end
            end
            | None -> 
              (* Incomming SYN-ACK with no pending connect
                 and no matching pcb - send RST *)
              Tx.send_rst t id ~sequence ~ack_number ~syn ~fin
          end
          | false -> begin
            match (hashtbl_find t.listeners id.local_port) with
            | Some (_, pushf) -> begin
              let tx_isn = Sequence.of_int ((Random.int 65535) + 0x1AFE0000) in
	      let tx_wnd = Wire.get_tcpv4_window pkt in
	      (* TODO: make this configurable per listener *)
	      let rx_wnd = 65535 in
	      let rx_wnd_scaleoffer = wscale_default in
              lwt newconn = new_server_connection
		t ~tx_wnd ~sequence ~options ~tx_isn ~rx_wnd ~rx_wnd_scaleoffer ~pushf id in
              return ()
            end
            | None -> begin
              Tx.send_rst t id ~sequence ~ack_number ~syn ~fin
            end
          end
        end
        | false -> begin
          match Wire.get_ack pkt with
          | true -> begin
            match (hashtbl_find t.listens id) with
            | Some (tx_isn, (pushf, newconn)) -> begin
              if Sequence.(to_int32 (incr tx_isn)) = ack_number then begin
                (* Established connection - promote to active channels *)
                Hashtbl.remove t.listens id;
                Hashtbl.add t.channels id newconn;
                (* send new connection up to listener *)
                pushf (Some newconn);
                Rx.input t pkt newconn
              end else begin
                (* No RST because we are trying to connect on this id *)
                return ()
              end
	    end
            | None -> 
              match (hashtbl_find t.connects id) with
              | Some _ ->
                (* No RST because we are trying to connect on this id *)
                return ()
              | None ->
                (* ACK but no matching pcb and no listen - send RST *)
                Tx.send_rst t id ~sequence ~ack_number ~syn ~fin
          end
          | false ->
            (* What the hell is this packet? No SYN,ACK,RST *)
            return ()
        end
      end


(* Main input function for TCP packets *)
let input t ~src ~dst data =
  let source_port = Wire.get_tcpv4_src_port data in
  let dest_port = Wire.get_tcpv4_dst_port data in
  let id = { local_port=dest_port; dest_ip=src; local_ip=dst; dest_port=source_port } in
  (* Lookup connection from the active PCB hash *)
  with_hashtbl t.channels id
    (* PCB exists, so continue the connection state machine in tcp_input *)
    (Rx.input t data)
    (* No existing PCB, so check if it is a SYN for a listening function *)
    (input_no_pcb t data)

(* Blocking read on a PCB *)
let rec read pcb =
  lwt d = User_buffer.Rx.take_l pcb.urx in 
  return d

(* Maximum allowed write *)
let write_available pcb =
  (* Our effective outgoing MTU is what can fit in a page *)
  min 4000 (min (Window.tx_mss pcb.wnd)
              (Int32.to_int (User_buffer.Tx.available pcb.utx)))

(* URG_TODO: raise exception if not in Established or Close_wait state *)
(* Wait for more write space *)
let write_wait_for pcb sz =
  User_buffer.Tx.wait_for pcb.utx (Int32.of_int sz)

(* URG_TODO: raise exception when trying to write to closed connection
             instead of quietly returning *)
(* Write a segment *)
let writev pcb data = User_buffer.Tx.write pcb.utx data
let write pcb data = User_buffer.Tx.write pcb.utx [data]

(* Close - no more will be written *)
let close pcb =
  Tx.close pcb
     
let closelistener l = 
  printf "TCP: Closing listener on port %d\n%!" l.port;
  match (hashtbl_find l.t.listeners l.port) with
  | Some (st, pushf) ->
      pushf None;
      Hashtbl.remove l.t.listeners l.port
  | None -> ()


let get_dest pcb =
  (pcb.id.dest_ip, pcb.id.dest_port)

(* URG_TODO: move this elsewhere! *)
let _ = Random.self_init ()

let localport = ref (10000 + (Random.int 10000))

let getid t dest_ip dest_port =
  (* TODO: make this more robust and recognise when all ports are gone *)
  let islistener t port = Hashtbl.mem t.listeners port in
  let idinuse t id = (Hashtbl.mem t.channels id) ||
                     (Hashtbl.mem t.connects id) || (Hashtbl.mem t.listens id) in
  let inuse t id = (islistener t id.local_port) || (idinuse t id) in
  let rec bumpport t =
    if !localport = 65535 then localport := 10000 else localport := !localport + 1;
    let id = { local_port = !localport; dest_ip = dest_ip;
               local_ip = (Ipv4.get_ip t.ip); dest_port = dest_port } in
    if inuse t id then bumpport t else id
  in
  bumpport t


(* SYN retransmission timer *)
let rec connecttimer t id tx_isn options window count =
  let rxtime = match count with | 0 -> 3. | 1 -> 6. | 2 -> 12. | 3 -> 24. | _ -> 48. in
  OS.Time.sleep rxtime >>
  match (hashtbl_find t.connects id) with
  | Some (wakener, isn) -> begin
      if isn = tx_isn then begin
	if count > 3 then begin
          Hashtbl.remove t.connects id;
          Lwt.wakeup wakener None;
          return ()
	end else begin
	  Tx.send_syn t id ~tx_isn ~options ~window >>
	  connecttimer t id tx_isn options window (count + 1)
	end
      end else 
	return ()
  end
  | None ->
      return ()

let connect t ~dest_ip ~dest_port = 
  let id = getid t dest_ip dest_port in
  let tx_isn = Sequence.of_int ((Random.int 65535) + 0x1BCD0000) in
  (* TODO: This is hardcoded for now - make it configurable *)
  let rx_wnd_scaleoffer = wscale_default in
  let options = Options.MSS 1460 :: Options.Window_size_shift rx_wnd_scaleoffer :: [] in
  let window = 5840 in
  let th, wakener = Lwt.task () in
  if Hashtbl.mem t.connects id then begin
    printf "WARNING: connection already being attempted\n%!";
  end;
  Hashtbl.replace t.connects id (wakener, tx_isn);
  Tx.send_syn t id ~tx_isn ~options ~window >>
  let _ = connecttimer t id tx_isn options window 0 in
  lwt c = th in
  return c


(* Register a TCP listener on a port *)
let listen t port =
  let st, pushfn = Lwt_stream.create () in
  if Hashtbl.mem t.listeners port then begin
    printf "WARNING: TCP listen port %d in use - replacing current listener\n%!" port;
    closelistener {t; port}
  end;
  Hashtbl.replace t.listeners port (st, pushfn);
  (st, {t; port})

(*
let print_onestat ~src ~sp ~dst ~dp ~st sent rxed =
  printf "%s\t%s\t%s\t%s\t%10d\t%10d\t%s\n%!" src sp dst dp sent rxed st

let listeners_stats t port _ =
  let src = ipv4_addr_to_string (Ipv4.get_ip t.ip) in
  let sp = string_of_int port in
  let dst = "*\t" in
  let dp = "*" in
  let st = tcpstates_to_string Listen in
  print_onestat ~src ~sp ~dst ~dp ~st 0 0

let connects_stats id (_, tx_isn) =
  let src = ipv4_addr_to_string id.local_ip in
  let sp = string_of_int id.local_port in
  let dst = ipv4_addr_to_string id.dest_ip in
  let dp = string_of_int id.dest_port in
  let st = tcpstates_to_string (Syn_sent tx_isn) in
  print_onestat ~src ~sp ~dst ~dp ~st 0 0

let pcb_stat pcb =
  let src = ipv4_addr_to_string pcb.id.local_ip in
  let sp = string_of_int pcb.id.local_port in
  let dst = ipv4_addr_to_string pcb.id.dest_ip in
  let dp = string_of_int pcb.id.dest_port in
  let st = tcpstates_to_string (state pcb.state) in
  print_onestat ~src ~sp ~dst ~dp ~st (Window.tx_totalbytes pcb.wnd) (Window.rx_totalbytes pcb.wnd)

let listens_stats _ (_, (_, (pcb, _))) =
  pcb_stat pcb

let channels_stats _ (pcb, _) =
  pcb_stat pcb

let tcpstats t =
  printf "\nSrc \t\tSrc_P \tDst \t\tDst_P \tSent_bytes \tRxed_bytes \tState \n%!";
  Hashtbl.iter (listeners_stats t) t.listeners;
  Hashtbl.iter listens_stats t.listens;
  Hashtbl.iter connects_stats t.connects;
  Hashtbl.iter channels_stats t.channels


let get_onestat ~src ~sp ~dst ~dp ~st sent rxed =
  (sprintf "%s\t%s\t%s\t%s\t%10d\t%10d\t%s\n" src sp dst dp sent rxed st)

let get_listeners_stats t port _ s =
  let src = ipv4_addr_to_string (Ipv4.get_ip t.ip) in
  let sp = string_of_int port in
  let dst = "*\t" in
  let dp = "*" in
  let st = tcpstates_to_string Listen in
  s ^ (get_onestat ~src ~sp ~dst ~dp ~st 0 0)

let get_connects_stats id (_, tx_isn) s =
  let src = ipv4_addr_to_string id.local_ip in
  let sp = string_of_int id.local_port in
  let dst = ipv4_addr_to_string id.dest_ip in
  let dp = string_of_int id.dest_port in
  let st = tcpstates_to_string (Syn_sent tx_isn) in
  s ^ (get_onestat ~src ~sp ~dst ~dp ~st 0 0)

let get_pcb_stat pcb =
  let src = ipv4_addr_to_string pcb.id.local_ip in
  let sp = string_of_int pcb.id.local_port in
  let dst = ipv4_addr_to_string pcb.id.dest_ip in
  let dp = string_of_int pcb.id.dest_port in
  let st = tcpstates_to_string (state pcb.state) in
  get_onestat ~src ~sp ~dst ~dp ~st (Window.tx_totalbytes pcb.wnd) (Window.rx_totalbytes pcb.wnd)

let get_listens_stats _ (_, (_, (pcb, _))) s =
  s ^ (get_pcb_stat pcb)

let get_channels_stats _ (pcb, _) s =
  s ^ (get_pcb_stat pcb)

let get_tcpstats t =
  let s = sprintf "GC Stats\nlive_words = %d\npcb: \tallocs=%d\tfrees=%d\tdiff=%d\nth: \tallocs=%d\tfrees=%d\tdiff=%d\n\n"
      Gc.((stat()).live_words) !pcb_allocs !pcb_frees (!pcb_allocs - !pcb_frees) !th_allocs !th_frees (!th_allocs - !th_frees) in
  let s = s ^ "\nSrc \t\tSrc_P \tDst \t\tDst_P \tSent_bytes \tRxed_bytes \tState \n" in
  let s = Hashtbl.fold (get_listeners_stats t) t.listeners s in
  let s = Hashtbl.fold get_listens_stats t.listens s in
  let s =  Hashtbl.fold get_connects_stats t.connects s in
  let s =  Hashtbl.fold get_channels_stats t.channels s in
  s


let httphdr =
  "HTTP/1.1 200 OK\nContent-Type: text/html\n\n"
let htmltitle = 
  "<html>\n<head>\n<title>Stats</title>\n</head>\n<body>\n"^
  "<h1>Stats</h1>\n"^
  "<p><h2>Status of current run: </h2><xmp>\n"
let htmlend = 
  "\n</xmp> End of data.</p>\n</body>\n</html>"


let write_stat ch s =
  let rec w_one start len ch s =
    if (String.length s - start) > len then begin
      let subs = String.sub s start len in
      let bs = Bitstring.bitstring_of_string subs in
      write ch bs >>
      w_one (start + len) len ch s
    end else begin
      let subs = String.sub s start (String.length s - start) in
      let bs = Bitstring.bitstring_of_string subs in
      write ch bs
    end
  in
  w_one 0 1460 ch s

let statsprint t (ch, _) =
  Gc.compact ();
  let s = get_tcpstats t in
  let rec onetxn ch = 
    match_lwt read ch with
    | None -> close ch 
    | Some _ ->
	write_stat ch httphdr >>
	write_stat ch htmltitle >>
	write_stat ch s >>
	write_stat ch htmlend >>
	close ch 
  in
  onetxn ch


let startTcpStatsServer t ~port =
  let st, l = listen t port in
  Lwt_stream.iter_s (fun f -> statsprint t f) st

*)
(* Construct the main TCP thread *)
let create ip =
  let thread, _ = Lwt.task () in
  let listeners = Hashtbl.create 1 in
  let listens = Hashtbl.create 1 in
  let connects = Hashtbl.create 1 in
  let channels = Hashtbl.create 7 in
  let t = { ip; channels; listeners; listens; connects } in
  Ipv4.attach ip (`TCP (input t));
  Lwt.on_cancel thread (fun () ->
    printf "TCP: shutting down\n%!";
    Ipv4.detach ip `TCP;
  );
 (*
  let statsport = 81 in
  let _ = startTcpStatsServer t statsport in 
  *)
  (t, thread)

