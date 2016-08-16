module Time = Vnetif_common.Time
module B = Basic_backend.Make
module V = Vnetif.Make(B)
module E = Ethif.Make(V)
module Static_arp = Static_arp.Make(E)(Clock)(Time)
module Ip = Ipv4.Make(E)(Static_arp)
module Udp = Udp.Make(Ip)

type stack = {
  backend : B.t;
  netif : V.t;
  ethif : E.t;
  arp : Static_arp.t;
  ip : Ip.t;
  udp : Udp.t;
}

let get_stack ?(backend = B.create ~use_async_readers:true
                  ~yield:(fun() -> Lwt_main.yield ()) ()) () =
  let open Lwt.Infix in
  let or_error = Common.or_error in
  or_error "backend" V.connect backend >>= fun netif ->
  or_error "ethif" E.connect netif >>= fun ethif ->
  or_error "arp" Static_arp.connect ethif >>= fun arp ->
  or_error "ipv4" (Ip.connect ethif) arp >>= fun ip ->
  or_error "udp" Udp.connect ip >>= fun udp ->
  Lwt.return { backend; netif; ethif; arp; ip; udp }

(* assume a class C network with no default gateway *)
let configure ip stack =
  let open Lwt.Infix in
  Ip.set_ip stack.ip ip >>= fun () ->
  Ip.set_ip_netmask stack.ip (Ipaddr.V4.of_string_exn "255.255.255.0") >>= fun
    () ->
  Lwt.return stack

let fails msg f args =
  match f args with
  | Result.Ok _ -> Alcotest.fail msg
  | Result.Error _ -> ()

let marshal_unmarshal () =
  let parse = Udp_packet.Unmarshal.of_cstruct in
  fails "unmarshal a 0-length packet" parse (Cstruct.create 0);
  fails "unmarshal a too-short packet" parse (Cstruct.create 2);
  let with_data = Cstruct.create 8 in
  Cstruct.memset with_data 0;
  Udp_wire.set_udp_source_port with_data 2000;
  Udp_wire.set_udp_dest_port with_data 21;
  Udp_wire.set_udp_length with_data 20;
  let payload = Cstruct.of_string "abcdefgh1234" in
  let with_data = Cstruct.concat [with_data; payload] in
  match Udp_packet.Unmarshal.of_cstruct with_data with
  | Result.Error s -> Alcotest.fail s
  | Result.Ok (_header, data) ->
    Alcotest.(check Common.cstruct) "unmarshalling gives expected data" payload data;
    Lwt.return_unit

let write () =
  let open Lwt.Infix in
  let dst = Ipaddr.V4.of_string_exn "192.168.4.20" in
  get_stack () >>= configure (Ipaddr.V4.of_string_exn "192.168.4.20") >>= fun stack ->
  Static_arp.add_entry stack.arp dst (Macaddr.of_string_exn "00:16:3e:ab:cd:ef");
  Udp.write ~src_port:1212 ~dst_port:21 ~dst stack.udp (Cstruct.of_string "MGET *") >>= fun () -> Lwt.return_unit

let suite = [
  "marshal/unmarshal", `Quick, marshal_unmarshal;
  "write packets", `Quick, write;
]
