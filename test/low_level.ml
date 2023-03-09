open Lwt.Infix

(*
 * Connects two stacks to the same backend.
 * One is a complete v4 stack (the system under test, referred to as [sut]).
 * The other gives us low level access to inject crafted TCP packets,
 * and sends and receives crafted packets to check the [sut] behavior.
 *)
module VNETIF_STACK = Vnetif_common.VNETIF_STACK(Vnetif_backends.Basic)

module Time = Vnetif_common.Time
module V = Vnetif.Make(Vnetif_backends.Basic)
module E = Ethernet.Make(V)
module A = Arp.Make(E)(Time)
module I = Static_ipv4.Make(Mirage_random_test)(Vnetif_common.Clock)(E)(A)
module Wire = Tcp.Wire
module WIRE = Wire.Make(I)
module Tcp_wire = Tcp.Tcp_wire
module Tcp_unmarshal = Tcp.Tcp_packet.Unmarshal
module Sequence = Tcp.Sequence

let sut_cidr = Ipaddr.V4.Prefix.of_string_exn "10.0.0.101/24"
let server_ip = Ipaddr.V4.of_string_exn "10.0.0.100"
let server_cidr = Ipaddr.V4.Prefix.make 24 server_ip
let gateway = Ipaddr.V4.of_string_exn "10.0.0.1"

let header_size = Ethernet.Packet.sizeof_ethernet



(* defaults when injecting packets *)
let options = []
let window = 5120

(* Helper functions *)
let reply_id_from ~src ~dst data =
  let sport = Tcp_wire.get_src_port data in
  let dport = Tcp_wire.get_dst_port data in
  WIRE.v ~dst_port:sport ~dst:src ~src_port:dport ~src:dst

let ack_for data =
  match Tcp_unmarshal.of_cstruct data with
  | Error s -> Alcotest.fail ("attempting to ack data: " ^ s)
  | Ok (packet, data) ->
    let open Tcp.Tcp_packet in
    let data_len =
      Sequence.of_int ((Cstruct.length data) +
		       (if packet.fin then 1 else 0) +
		       (if packet.syn then 1 else 0)) in
    let sequence = packet.sequence in
    let ack_n = Sequence.(add sequence data_len) in
    ack_n

let ack data =
  Some(ack_for data)

let ack_in_future data off =
  Some Sequence.(add (ack_for data) (of_int off))

let ack_from_past data off =
  Some Sequence.(sub (ack_for data) (of_int off))

let fail_result_not_expected fail = function
  | Error _err ->
    fail "error not expected"
  | Ok `Eof ->
    fail "eof"
  | Ok (`Data data) ->
    Alcotest.fail (Format.asprintf "data not expected but received: %a"
		     Cstruct.hexdump_pp data)



let create_sut_stack backend =
  VNETIF_STACK.create_stack ~cidr:sut_cidr ~gateway backend

let create_raw_stack backend =
  V.connect backend >>= fun netif ->
  E.connect netif >>= fun ethif ->
  A.connect ethif >>= fun arpv4 ->
  I.connect ~cidr:server_cidr ~gateway ethif arpv4 >>= fun ip ->
  Lwt.return (netif, ethif, arpv4, ip)

type 'state fsm_result =
  | Fsm_next of 'state
  | Fsm_done
  | Fsm_error of string

(*  This could be moved to a common module and reused for other low level tcp tests *)

(* setups network and run a given sut and raw fsm *)
let run backend fsm sut () =
  let initial_state, fsm_handler = fsm in
  create_sut_stack backend >>= fun stack ->
  create_raw_stack backend >>= fun (netif, ethif, arp, rawip) ->
  let error_mbox = Lwt_mvar.create_empty () in
  let stream, pushf = Lwt_stream.create () in
  Lwt.pick [
  VNETIF_STACK.Stack.listen stack;

  (* Consume TCP packets one by one, in sequence *)
  let rec fsm_thread state =
    Lwt_stream.next stream >>= fun (src, dst, data) ->
    fsm_handler rawip state ~src ~dst data >>= function
    | Fsm_next s ->
      fsm_thread s
    | Fsm_done ->
      Lwt.return_unit
    | Fsm_error err ->
      Lwt_mvar.put error_mbox err >>= fun () ->
      (* it will be terminated anyway when the error is picked up *)
      fsm_thread state in

  Lwt.async (fun () ->
      (V.listen netif ~header_size
         (E.input
            ~arpv4:(A.input arp)
            ~ipv4:(I.input
                     ~tcp: (fun ~src ~dst data -> pushf (Some(src,dst,data)); Lwt.return_unit)
                     ~udp:(fun ~src:_ ~dst:_ _data -> Lwt.return_unit)
                     ~default:(fun ~proto ~src ~dst _data ->
                        Logs.debug (fun f -> f "default handler invoked for packet from %a to %a, protocol %d -- dropping" Ipaddr.V4.pp src Ipaddr.V4.pp dst proto); Lwt.return_unit)
                     rawip
                  )
            ~ipv6:(fun _buf ->
              Logs.debug (fun f -> f "IPv6 packet -- dropping");
              Lwt.return_unit)
            ethif) ) >|= fun _ -> ());

  (* Either both fsm and the sut terminates, or a timeout occurs, or one of the sut/fsm informs an error *)
  Lwt.pick [
    (Time.sleep_ns (Duration.of_sec 5) >>= fun () ->
     Lwt.return_some "timed out");

    (Lwt.join [
        (fsm_thread initial_state);

        (* time to let the other end connects to the network and listen.
         * Otherwise initial syn might need to be repeated slowing down the test *)
        (Time.sleep_ns (Duration.of_ms 100) >>= fun () ->
         sut stack (Lwt_mvar.put error_mbox) >>= fun _ ->
         Time.sleep_ns (Duration.of_ms 100));
      ] >>= fun () -> Lwt.return_none);

    (Lwt_mvar.take error_mbox >>= fun cause ->
     Lwt.return_some cause);
  ] >|= function
  | None     -> ()
  | Some err -> Alcotest.fail err
  ]
