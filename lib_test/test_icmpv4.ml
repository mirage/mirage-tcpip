open Result

module B = Basic_backend.Make
module V = Vnetif.Make(B)
module E = Ethif.Make(V)
module A = Arpv4.Make(E)(Clock)(OS.Time)

open Lwt.Infix

module Static_arp : sig
  include V1_LWT.ARP
  val connect : E.t -> [> `Ok of t | `Error of error ] Lwt.t
  val add_entry : t -> Ipaddr.V4.t -> macaddr -> unit
end = struct
  (* generally repurpose A, but substitute input and query, and add functions
     for adding/deleting entries *)
  type error = A.error
  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t
  type macaddr = Macaddr.t
  type result = A.result
  type ipaddr = Ipaddr.V4.t
  type id = A.id
  type repr = string

  type t = {
    base : A.t;
    table : (Ipaddr.V4.t, macaddr) Hashtbl.t;
  }

  let add_ip t = A.add_ip t.base
  let remove_ip t = A.remove_ip t.base
  let set_ips t = A.set_ips t.base
  let get_ips t = A.get_ips t.base

  let to_repr t =
    let print ip entry acc =
      let key = Ipaddr.V4.to_string ip in
      let entry = Macaddr.to_string entry in
      Printf.sprintf "IP %s : MAC %s\n" key entry
    in
    Lwt.return (Hashtbl.fold print t.table "")

  let pp fmt repr =
    Format.fprintf fmt "%s" repr

  let connect e = A.connect e >>= function
    | `Ok base -> Lwt.return (`Ok { base; table = (Hashtbl.create 7) })
    | `Error e -> Lwt.return (`Error e)

  let disconnect t = A.disconnect t.base

  let query t ip =
    match Hashtbl.mem t.table ip with
    | false -> Lwt.return `Timeout
    | true -> Lwt.return (`Ok (Hashtbl.find t.table ip))

  let input t buffer =
    (* disregard responses, but reply to queries *)
    try
    match Arpv4_wire.get_arp_op buffer with
    | 1 -> A.input t.base buffer
    | 2 | _ -> Lwt.return_unit
    with
    | Invalid_argument s -> Printf.printf "Arpv4_wire failed on buffer: %s" s;
      Lwt.return_unit

  let add_entry t ip mac =
    Hashtbl.add t.table ip mac

end

module Ip = Ipv4.Make(E)(Static_arp)
module Icmp = Icmpv4.Make(Ip)

type stack = {
  backend : B.t;
  netif : V.t;
  ethif : E.t;
  arp : Static_arp.t;
  ip : Ip.t;
  icmp : Icmp.t;
}

let testbind x y =
  match x with
  | Result.Ok p -> y p
  | Result.Error s -> Alcotest.fail s
let (>>=?) = testbind

let slowly fn =
  OS.Time.sleep 0.1 >>= fun () -> fn >>= fun () -> OS.Time.sleep 0.1

let get_stack ?(backend = B.create ~use_async_readers:true 
                  ~yield:(fun() -> Lwt_main.yield ()) ()) () =
  let or_error = Common.or_error in
  or_error "backend" V.connect backend >>= fun netif ->
  or_error "ethif" E.connect netif >>= fun ethif ->
  or_error "arp" Static_arp.connect ethif >>= fun arp ->
  or_error "ipv4" (Ip.connect ethif) arp >>= fun ip ->
  or_error "icmpv4" Icmp.connect ip >>= fun icmp ->
  Lwt.return { backend; netif; ethif; arp; ip; icmp; }

(* assume a class C network with no default gateway *)
let configure ip stack =
  Ip.set_ip stack.ip ip >>= fun () ->
  Ip.set_ip_netmask stack.ip (Ipaddr.V4.of_string_exn "255.255.255.0") >>= fun
    () ->
  Lwt.return stack

let icmp_listen stack fn =
  let noop = fun ~src:_ ~dst:_ _buf -> Lwt.return_unit in
  V.listen stack.netif (* some buffer -> unit io *)
    ( E.input stack.ethif ~arpv4:(Static_arp.input stack.arp)
        ~ipv6:(fun _ -> Lwt.return_unit)
        ~ipv4:
          ( Ip.input stack.ip
              ~tcp:noop ~udp:noop
              ~default:(fun ~proto -> match proto with | 1 -> fn | _ -> noop)))

(* some default addresses which will be on the same class C *)
let listener_address = Ipaddr.V4.of_string_exn "192.168.222.1"
let speaker_address = Ipaddr.V4.of_string_exn "192.168.222.10"

let inform_arp stack = Static_arp.add_entry stack.arp
let mac_of_stack stack = E.mac stack.ethif

let short_read () =
  let too_short = Cstruct.create 4 in
  match Icmpv4_unmarshal.of_cstruct too_short with
  | Ok icmp -> Alcotest.fail "processed something too short to be real"
  | Error str -> Printf.printf "short packet rejected successfully! msg: %s\n" str;
    Lwt.return_unit

let echo_request () =
  let seq_no = 0x01 in
  let id_no = 0x1234 in
  get_stack () >>= configure speaker_address >>= fun speaker ->
  get_stack ~backend:speaker.backend () >>= configure listener_address >>= fun listener ->
  inform_arp speaker listener_address (mac_of_stack listener);
  inform_arp listener speaker_address (mac_of_stack speaker);
  let echo_request = Cstruct.create 4096 in
  Icmpv4_marshal.echo_request ~payload:Cstruct.(create 0) ~buf:echo_request ~id:id_no
    ~seq:seq_no >>=? fun () ->
  let check buf =
    let open Icmpv4_unmarshal in
    Printf.printf "Incoming ICMP message: ";
    Cstruct.hexdump buf;
    of_cstruct buf >>=? fun reply ->
    let (Icmpv4_unmarshal.Id_and_seq (id, seq)) = reply.subheader in
    Alcotest.(check int) "icmp response type" 0x00 (Icmpv4_wire.ty_to_int reply.ty); (* expect an icmp echo reply *)
    Alcotest.(check int) "icmp echo-reply code" 0x00 reply.code; (* should be code 0 *)
    Alcotest.(check int) "icmp echo-reply id" id_no id;
    Alcotest.(check int) "icmp echo-reply seq" seq_no seq;
    match (Cstruct.len reply.payload) with
    | 0 -> Alcotest.fail "icmp echo-reply had a payload but request didn't"
    | n -> Lwt.return_unit
  in
  Lwt.pick [
    icmp_listen speaker (fun ~src:_ ~dst:_ -> check); (* should get reply back *)
    icmp_listen listener (fun ~src ~dst buf -> Icmp.input listener.icmp ~src
                             ~dst buf);
    slowly (Icmp.write speaker.icmp ~dst:listener_address echo_request);
  ]

let echo_silent () =
  get_stack () >>= configure speaker_address >>= fun speaker ->
  get_stack ~backend:speaker.backend () >>= configure listener_address >>= fun listener ->
  let echo_request = Cstruct.create 4096 in
  Icmpv4_marshal.echo_request ~payload:(Cstruct.create 0) ~buf:echo_request ~id:0xff ~seq:0x4341 >>=? fun () ->
  let open Icmpv4_unmarshal in
  let check buf =
    of_cstruct buf >>=? fun message ->
    match message.ty with
    | Icmpv4_wire.Echo_reply -> Alcotest.fail "received an ICMP echo reply even though we shouldn't have"
    | Echo_request -> Printf.printf "received an ICMP echo request; ignoring it";
      Lwt.return_unit
    | _ -> Lwt.return_unit
  in
  let nobody_home = Ipaddr.V4.of_string_exn "192.168.222.90" in
  inform_arp speaker listener_address (mac_of_stack listener);
  inform_arp listener speaker_address (mac_of_stack speaker);
  (* set up an ARP mapping so the listener is more likely to see the echo-request *)
  inform_arp speaker nobody_home (mac_of_stack listener);
  Lwt.pick [
    icmp_listen listener (fun ~src ~dst buf -> Icmp.input listener.icmp ~src
                             ~dst buf);
    icmp_listen speaker (fun ~src ~dst -> check);
    slowly (Icmp.write speaker.icmp ~dst:nobody_home echo_request);
  ]

let suite = [
  "short read", `Quick, short_read;
  "echo requests elicit an echo reply", `Quick, echo_request;
  "echo requests for other ips don't elicit an echo reply", `Quick, echo_silent;
]
