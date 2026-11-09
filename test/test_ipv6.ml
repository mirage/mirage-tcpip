open Common
module B = Vnetif_backends.Basic
module V = Vnetif.Make(B)
module E = Ethernet.Make(V)

module Ipv6 = Ipv6.Make(V)(E)
module Udp = Udp.Make(Ipv6)
open Lwt.Infix

let ip =
  let module M = struct
    type t = Ipaddr.V6.t
    let pp = Ipaddr.V6.pp
    let equal p q = (Ipaddr.V6.compare p q) = 0
  end in
  (module M : Alcotest.TESTABLE with type t = M.t)

let prefix =
  Alcotest.testable Ipaddr.V6.Prefix.pp (fun a b -> Ipaddr.V6.Prefix.compare a b = 0)

type stack = {
  backend : B.t;
  netif : V.t;
  ethif : E.t;
  ip : Ipv6.t;
  udp : Udp.t
}

let get_stack backend address =
  let cidr = Ipaddr.V6.Prefix.make 64 address in
  V.connect backend >>= fun netif ->
  E.connect netif >>= fun ethif ->
  Ipv6.connect ~cidr netif ethif >>= fun ip ->
  Udp.connect ip >>= fun udp ->
  Lwt.return { backend; netif; ethif; ip; udp }

let noop = fun ~src:_ ~dst:_ _ -> Lwt.return_unit

let listen ?(tcp = noop) ?(udp = noop) ?(default = noop) stack =
  V.listen stack.netif ~header_size:Ethernet.Packet.sizeof_ethernet
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
    >|= Result.get_ok >>= fun () ->
    Mirage_sleep.ns (Duration.of_ms 50) >>= fun () ->
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
      Mirage_sleep.ns (Duration.of_ms 3000) >>= fun () ->
      Alcotest.fail "UDP packet should have been received";
  ]

let create_ethernet backend =
  V.connect backend >>= fun netif ->
  E.connect netif >|= fun ethif ->
  (fun ipv6 ->
     V.listen netif ~header_size:Ethernet.Packet.sizeof_ethernet
       (E.input ethif
          ~arpv4:(fun _ -> Lwt.return_unit)
          ~ipv4:(fun _ -> Lwt.return_unit)
          ~ipv6) >|= fun _ -> ()),
  (fun dst ?size f -> E.write ethif dst `IPv6 ?size f),
  E.mac ethif

let solicited_node_prefix =
  Ipaddr.V6.(Prefix.make 104 (of_int16 (0xff02, 0, 0, 0, 0, 1, 0xff00, 0)))

let dad_na_is_sent () =
  let address = Ipaddr.V6.of_string_exn "fc00::23" in
  let backend = B.create () in
  get_stack backend address >>= fun stack ->
  create_ethernet backend >>= fun (listen_raw, write_raw, _) ->
  let received_one, on_received_one = Lwt.task () in
  let nd_size = Ipv6_wire.sizeof_ipv6 + Ipv6_wire.Ns.sizeof_ns in
  let nd buf =
    Ipv6_wire.set_version_flow buf 0x60000000l; (* IPv6 *)
    Ipv6_wire.set_len buf Ipv6_wire.Ns.sizeof_ns;
    Ipaddr_cstruct.V6.write_cstruct_exn Ipaddr.V6.unspecified (Cstruct.shift buf 8);
    Ipaddr_cstruct.V6.write_cstruct_exn (Ipaddr.V6.Prefix.network_address solicited_node_prefix address) (Cstruct.shift buf 24);
    Ipv6_wire.set_hlim buf 255;
    Ipv6_wire.set_nhdr buf (Ipv6_wire.protocol_to_int `ICMP);
    let hdr, icmpbuf = Cstruct.split buf Ipv6_wire.sizeof_ipv6 in
    Ipv6_wire.set_ty icmpbuf 135; (* NS *)
    Ipv6_wire.set_code icmpbuf 0;
    Ipv6_wire.Ns.set_reserved icmpbuf 0l;
    Ipaddr_cstruct.V6.write_cstruct_exn address (Cstruct.shift icmpbuf 8);
    Ipv6_wire.Icmpv6.set_checksum icmpbuf 0;
    Ipv6_wire.Icmpv6.set_checksum icmpbuf @@ Ndpv6.checksum hdr [icmpbuf];
    nd_size
  and is_na buf =
    let icmpbuf = Cstruct.shift buf Ipv6_wire.sizeof_ipv6 in
    Ipv6_wire.get_version_flow buf = 0x60000000l && (* IPv6 *)
    Ipaddr.V6.compare
      (Ipaddr_cstruct.V6.of_cstruct_exn (Cstruct.shift buf 8))
      address = 0 &&
    Ipaddr.V6.compare
      (Ipaddr_cstruct.V6.of_cstruct_exn (Cstruct.shift buf 24))
      Ipaddr.V6.link_nodes = 0 &&
    Ipv6_wire.get_hlim buf = 255 &&
    Ipv6_wire.get_nhdr buf = Ipv6_wire.protocol_to_int `ICMP &&
    Ipv6_wire.get_ty icmpbuf = 136 &&
    Ipv6_wire.get_code icmpbuf = 0 &&
    Ipaddr.V6.compare
      (Ipaddr_cstruct.V6.of_cstruct_exn (Cstruct.shift icmpbuf 8))
      address = 0
  in
  Lwt.pick [
    listen stack;
    listen_raw (fun buf ->
        if is_na buf then
          Lwt.wakeup_later on_received_one ();
        Lwt.return_unit);
    (write_raw (E.mac stack.ethif) ~size:nd_size nd >|= fun _ -> ());
    received_one;
    (Mirage_sleep.ns (Duration.of_ms 1000) >>= fun () ->
     Alcotest.fail "NA packet should have been received")
  ]

let multicast_mac =
  let pbuf = Cstruct.create 6 in
  Cstruct.BE.set_uint16 pbuf 0 0x3333;
  fun ip ->
    let _, _, _, n = Ipaddr.V6.to_int32 ip in
    Cstruct.BE.set_uint32 pbuf 2 n;
    Macaddr_cstruct.of_cstruct_exn pbuf

let dad_na_is_received () =
  let address = Ipaddr.V6.of_string_exn "fc00::23" in
  let backend = B.create () in
  create_ethernet backend >>= fun (listen_raw, write_raw, mac) ->
  let na_size = Ipv6_wire.sizeof_ipv6 + Ipv6_wire.Na.sizeof_na + Ipv6_wire.Llopt.sizeof_llopt in
  let is_ns buf =
    let icmpbuf = Cstruct.shift buf Ipv6_wire.sizeof_ipv6 in
    if
      Ipv6_wire.get_version_flow buf = 0x60000000l && (* IPv6 *)
      Ipaddr.V6.compare
        (Ipaddr_cstruct.V6.of_cstruct_exn (Cstruct.shift buf 8))
        Ipaddr.V6.unspecified = 0 &&
      Ipaddr.V6.Prefix.mem
        (Ipaddr_cstruct.V6.of_cstruct_exn (Cstruct.shift buf 24))
        solicited_node_prefix &&
      Ipv6_wire.get_hlim buf = 255 &&
      Ipv6_wire.get_nhdr buf = Ipv6_wire.protocol_to_int `ICMP &&
      Ipv6_wire.get_ty icmpbuf = 135 &&
      Ipv6_wire.get_code icmpbuf = 0
    then
      Some (Ipaddr_cstruct.V6.of_cstruct_exn (Cstruct.shift icmpbuf 8))
    else
      None
  in
  let na addr buf =
    Ipv6_wire.set_version_flow buf 0x60000000l; (* IPv6 *)
    Ipv6_wire.set_len buf (Ipv6_wire.Na.sizeof_na + Ipv6_wire.Llopt.sizeof_llopt);
    Ipaddr_cstruct.V6.write_cstruct_exn addr (Cstruct.shift buf 8);
    Ipaddr_cstruct.V6.write_cstruct_exn Ipaddr.V6.link_nodes (Cstruct.shift buf 24);
    Ipv6_wire.set_hlim buf 255;
    Ipv6_wire.set_nhdr buf (Ipv6_wire.protocol_to_int `ICMP);
    let hdr, icmpbuf = Cstruct.split buf Ipv6_wire.sizeof_ipv6 in
    Ipv6_wire.set_ty icmpbuf 136; (* NA *)
    Ipv6_wire.set_code icmpbuf 0;
    Ipv6_wire.Na.set_reserved icmpbuf 0x20000000l;
    Ipaddr_cstruct.V6.write_cstruct_exn addr (Cstruct.shift icmpbuf 8);
    let optbuf = Cstruct.shift icmpbuf Ipv6_wire.Na.sizeof_na in
    Ipv6_wire.set_ty optbuf 2;
    Ipv6_wire.Llopt.set_len optbuf 1;
    Macaddr_cstruct.write_cstruct_exn mac (Cstruct.shift optbuf 2);
    Ipv6_wire.Icmpv6.set_checksum icmpbuf 0;
    Ipv6_wire.Icmpv6.set_checksum icmpbuf @@ Ndpv6.checksum hdr [icmpbuf];
    na_size
  in
  Lwt.pick [
    (listen_raw (fun buf ->
         match is_ns buf with
         | None -> Lwt.return_unit
         | Some addr ->
           let dst = multicast_mac Ipaddr.V6.link_nodes in
           write_raw dst ~size:na_size (na addr) >|= fun _ -> ()));
    (Lwt.catch
       (fun () -> get_stack backend address >|= fun _ -> Error ())
       (fun _ -> Lwt.return (Ok ())) >|= function
     | Ok () -> ()
     | Error () -> Alcotest.fail "Expected stack initialization failure");
    (Mirage_sleep.ns (Duration.of_ms 5000) >>= fun () ->
     Alcotest.fail "stack initialization should have failed")
  ]

let router_address = Ipaddr.V6.of_string_exn "fe80::1"
let ra_prefix = Ipaddr.V6.Prefix.of_string_exn "2001:db8::/64"

(* A Router Advertisement from [router_address] (Router Lifetime 1800 s) with
   a Prefix Information option for [ra_prefix] (on-link, autonomous, valid
   30 days, preferred 7 days). *)
let ra_packet () =
  let icmp_len = Ipv6_wire.Ra.sizeof_ra + Ipv6_wire.Opt_prefix.sizeof_opt_prefix in
  let buf = Cstruct.create (Ipv6_wire.sizeof_ipv6 + icmp_len) in
  Ipv6_wire.set_version_flow buf 0x60000000l; (* IPv6 *)
  Ipv6_wire.set_len buf icmp_len;
  Ipaddr_cstruct.V6.write_cstruct_exn router_address (Cstruct.shift buf 8);
  Ipaddr_cstruct.V6.write_cstruct_exn Ipaddr.V6.link_nodes (Cstruct.shift buf 24);
  Ipv6_wire.set_hlim buf 255;
  Ipv6_wire.set_nhdr buf (Ipv6_wire.protocol_to_int `ICMP);
  let hdr, icmpbuf = Cstruct.split buf Ipv6_wire.sizeof_ipv6 in
  Ipv6_wire.set_ty icmpbuf 134; (* RA *)
  Ipv6_wire.set_code icmpbuf 0;
  Ipv6_wire.Ra.set_cur_hop_limit icmpbuf 64;
  Ipv6_wire.Ra.set_router_lifetime icmpbuf 1800;
  let opt = Cstruct.shift icmpbuf Ipv6_wire.Ra.sizeof_ra in
  Ipv6_wire.set_ty opt 3;
  Ipv6_wire.Opt_prefix.set_len opt 4;
  Ipv6_wire.Opt_prefix.set_prefix_len opt (Ipaddr.V6.Prefix.bits ra_prefix);
  Ipv6_wire.Opt_prefix.set_reserved1 opt 0xc0; (* on-link, autonomous *)
  Ipv6_wire.Opt_prefix.set_valid_lifetime opt 2592000l;
  Ipv6_wire.Opt_prefix.set_preferred_lifetime opt 604800l;
  Ipv6_wire.Opt_prefix.set_prefix opt (Ipaddr.V6.Prefix.network ra_prefix);
  Ipv6_wire.Icmpv6.set_checksum icmpbuf 0;
  Ipv6_wire.Icmpv6.set_checksum icmpbuf @@ Ndpv6.checksum hdr [icmpbuf];
  buf

let ra_received () =
  let mac = Macaddr.of_string_exn "02:00:00:00:00:01" in
  let ctx, _ = Ndpv6.local ~handle_ra:true ~now:0L mac in
  let ctx, _, _ = Ndpv6.handle ~now:0L ctx (ra_packet ()) in
  ctx

let ra_prefix_length () =
  let ctx = ra_received () in
  Alcotest.(check (list prefix)) "the RA prefix is on-link"
    [ra_prefix; Ipaddr.V6.Prefix.link] (Ndpv6.get_prefix ctx);
  Lwt.return_unit

let ra_lifetimes () =
  let ctx = ra_received () in
  let ctx, _ = Ndpv6.tick ~now:(Duration.of_sec 1) ctx in
  Alcotest.(check (list ip)) "the router is still a default router"
    [router_address] (Ndpv6.get_routers ctx);
  Alcotest.(check (list prefix)) "the RA prefix is still on-link"
    [ra_prefix; Ipaddr.V6.Prefix.link] (Ndpv6.get_prefix ctx);
  Lwt.return_unit

let ra_expires () =
  let ctx = ra_received () in
  let ctx, _ = Ndpv6.tick ~now:(Duration.of_sec 1801) ctx in
  Alcotest.(check (list ip)) "the router expired" [] (Ndpv6.get_routers ctx);
  Alcotest.(check (list prefix)) "the RA prefix is still on-link"
    [ra_prefix; Ipaddr.V6.Prefix.link] (Ndpv6.get_prefix ctx);
  let ctx, _ = Ndpv6.tick ~now:(Duration.of_day 31) ctx in
  Alcotest.(check (list prefix)) "the RA prefix expired"
    [Ipaddr.V6.Prefix.link] (Ndpv6.get_prefix ctx);
  Lwt.return_unit

let suite = [
  "Send a UDP packet from one IPV6 stack and check it is received by another", `Quick, pass_udp_traffic;
  "NA is sent when a ND is received", `Quick, dad_na_is_sent;
  "NA is received, stack fails to initialise", `Quick, dad_na_is_received;
  "RA prefix uses the Prefix Length", `Quick, ra_prefix_length;
  "RA lifetimes are in seconds", `Quick, ra_lifetimes;
  "RA router and prefix lifetimes expire", `Quick, ra_expires;
]
