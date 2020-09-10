open Common
module Time = Vnetif_common.Time
module B = Vnetif_backends.Basic
module V = Vnetif.Make(B)
module E = Ethernet.Make(V)

module Ipv6 = Ipv6.Make(V)(E)(Mirage_random_test)(Time)(Mclock)
module Udp = Udp.Make(Ipv6)(Mirage_random_test)
open Lwt.Infix

let ip =
  let module M = struct
    type t = Ipaddr.V6.t
    let pp = Ipaddr.V6.pp
    let equal p q = (Ipaddr.V6.compare p q) = 0
  end in
  (module M : Alcotest.TESTABLE with type t = M.t)

type stack = {
  backend : B.t;
  netif : V.t;
  ethif : E.t;
  ip : Ipv6.t;
  udp : Udp.t
}

let get_stack backend address =
  let ip = [address] in
  let netmask = [Ipaddr.V6.Prefix.make 24 address] in
  let gateways = [] in
  V.connect backend >>= fun netif ->
  E.connect netif >>= fun ethif ->
  Ipv6.connect ~ip ~netmask ~gateways netif ethif >>= fun ip ->
  Udp.connect ip >>= fun udp ->
  Lwt.return { backend; netif; ethif; ip; udp }

let noop = fun ~src:_ ~dst:_ _ -> Lwt.return_unit

let listen ?(tcp = noop) ?(udp = noop) ?(default = noop) stack =
  V.listen stack.netif ~header_size:Ethernet_wire.sizeof_ethernet
    ( E.input stack.ethif
      ~arpv4:(fun _ -> Lwt.return_unit)
      ~ipv4:(fun _ -> Lwt.return_unit)
      ~ipv6:(
        Ipv6.input stack.ip
          ~tcp:tcp
          ~udp:udp
          ~default:(fun ~proto:_ -> default))) >>= fun _ -> Lwt.return_unit

let udp_message = Cstruct.of_string "hello on UDP over IPv6"

let check_for_one_udp_packet on_received_one ~src ~dst buf =
  (match Udp_packet.Unmarshal.of_cstruct buf with
  | Ok (_, payload) ->
    Alcotest.(check ip) "sender address" (Ipaddr.V6.of_string_exn "fc00::23") src;
    Alcotest.(check ip) "receiver address" (Ipaddr.V6.of_string_exn "fc00::45") dst;
    Alcotest.(check cstruct) "payload is correct" udp_message payload
  | Error m -> Alcotest.fail m);
  (try Lwt.wakeup_later on_received_one () with _ -> () (* the first succeeds, the rest raise *));
  Lwt.return_unit

let send_forever sender receiver_address udp_message =
  let rec loop () =
    Udp.write sender.udp ~dst:receiver_address ~dst_port:1234 udp_message
    >|= Rresult.R.get_ok >>= fun () ->
    Time.sleep_ns (Duration.of_ms 50) >>= fun () ->
    loop () in
  loop ()

let pass_udp_traffic () =
  let sender_address = Ipaddr.V6.of_string_exn "fc00::23" in
  let receiver_address = Ipaddr.V6.of_string_exn "fc00::45" in
  let backend = B.create () in
  get_stack backend sender_address >>= fun sender ->
  get_stack backend receiver_address >>= fun receiver ->
  let received_one, on_received_one = Lwt.task () in
  Lwt.pick [
    listen receiver ~udp:(check_for_one_udp_packet on_received_one);
    listen sender;
    send_forever sender receiver_address udp_message;
    received_one; (* stop on the first packet *)
      Time.sleep_ns (Duration.of_ms 3000) >>= fun () ->
      Alcotest.fail "UDP packet should have been received";
  ]

let create_ethernet backend =
  V.connect backend >>= fun netif ->
  E.connect netif >|= fun ethif ->
  (fun ipv6 ->
     V.listen netif ~header_size:Ethernet_wire.sizeof_ethernet
       (E.input ethif
          ~arpv4:(fun _ -> Lwt.return_unit)
          ~ipv4:(fun _ -> Lwt.return_unit)
          ~ipv6) >|= fun _ -> ()),
  (fun dst ?size f -> E.write ethif dst `IPv6 ?size f)

let solicited_node_prefix =
  Ipaddr.V6.(Prefix.make 104 (of_int16 (0xff02, 0, 0, 0, 0, 1, 0xff00, 0)))

let dad_na_is_sent () =
  let address = Ipaddr.V6.of_string_exn "fc00::23" in
  let backend = B.create () in
  get_stack backend address >>= fun stack ->
  create_ethernet backend >>= fun (listen_raw, write_raw) ->
  let received_one, on_received_one = Lwt.task () in
  let nd_size = Ipv6_wire.sizeof_ipv6 + Ipv6_wire.sizeof_ns in
  let nd buf =
    Ipv6_wire.set_ipv6_version_flow buf 0x60000000l; (* IPv6 *)
    Ipv6_wire.set_ipv6_len buf Ipv6_wire.sizeof_ns;
    Ipaddr_cstruct.V6.write_cstruct_exn Ipaddr.V6.unspecified (Cstruct.shift buf 8);
    Ipaddr_cstruct.V6.write_cstruct_exn (Ipaddr.V6.Prefix.network_address solicited_node_prefix address) (Cstruct.shift buf 24);
    Ipv6_wire.set_ipv6_hlim buf 255;
    Ipv6_wire.set_ipv6_nhdr buf (Ipv6_wire.protocol_to_int `ICMP);
    let icmpbuf = Cstruct.shift buf Ipv6_wire.sizeof_ipv6 in
    Ipv6_wire.set_ns_ty icmpbuf 135; (* NS *)
    Ipv6_wire.set_ns_code icmpbuf 0;
    Ipv6_wire.set_ns_reserved icmpbuf 0l;
    Ipaddr_cstruct.V6.write_cstruct_exn address (Cstruct.shift icmpbuf 6);
    Ipv6_wire.set_icmpv6_csum icmpbuf 0;
    Ipv6_wire.set_icmpv6_csum icmpbuf @@ Ndpv6.checksum buf [];
    nd_size
  and is_na buf =
    let icmpbuf = Cstruct.shift buf Ipv6_wire.sizeof_ipv6 in
    Ipv6_wire.get_ipv6_version_flow buf = 0x60000000l && (* IPv6 *)
    Ipaddr.V6.compare
      (Ipaddr_cstruct.V6.of_cstruct_exn (Cstruct.shift buf 8))
      address = 0 &&
    Ipaddr.V6.compare
      (Ipaddr_cstruct.V6.of_cstruct_exn (Cstruct.shift buf 24))
      Ipaddr.V6.link_nodes = 0 &&
    Ipv6_wire.get_ipv6_hlim buf = 255 &&
    Ipv6_wire.get_ipv6_nhdr buf = Ipv6_wire.protocol_to_int `ICMP &&
    Ipv6_wire.get_ns_ty icmpbuf = 136 &&
    Ipv6_wire.get_ns_code icmpbuf = 0
  in
  Lwt.pick [
    listen stack;
    listen_raw (fun buf ->
        if is_na buf then
          Lwt.wakeup_later on_received_one ();
        Lwt.return_unit);
    (write_raw (E.mac stack.ethif) ~size:nd_size nd >|= fun _ -> ());
    received_one;
    (Time.sleep_ns (Duration.of_ms 1000) >>= fun () ->
     Alcotest.fail "NA packet should have been received")
  ]

let suite = [
  "Send a UDP packet from one IPV6 stack and check it is received by another", `Quick, pass_udp_traffic;
  "NA is sent when a ND is received", `Quick, dad_na_is_sent;
]
