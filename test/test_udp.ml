open Common
open Result

module Time = Vnetif_common.Time
module B = Basic_backend.Make
module V = Vnetif.Make(B)
module E = Ethif.Make(V)
module Static_arp = Static_arp.Make(E)(Mclock)(Time)
module Ip = Static_ipv4.Make(E)(Static_arp)
module Udp = Udp.Make(Ip)(Stdlibrandom)

type stack = {
  clock : Mclock.t;
  backend : B.t;
  netif : V.t;
  ethif : E.t;
  arp : Static_arp.t;
  ip : Ip.t;
  udp : Udp.t;
}

let get_stack ?(backend = B.create ~use_async_readers:true
                  ~yield:(fun() -> Lwt_main.yield ()) ()) ip =
  let open Lwt.Infix in
  let network = Ipaddr.V4.Prefix.make 24 ip in
  let gateway = None in
  Mclock.connect () >>= fun clock ->
  V.connect backend >>= fun netif ->
  E.connect netif >>= fun ethif ->
  Static_arp.connect ethif clock >>= fun arp ->
  Ip.connect ~ip ~network ~gateway ethif arp >>= fun ip ->
  Udp.connect ip >>= fun udp ->
  Lwt.return { clock; backend; netif; ethif; arp; ip; udp }

let fails msg f args =
  match f args with
  | Ok _ -> Alcotest.fail msg
  | Error _ -> ()

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
  | Error s -> Alcotest.fail s
  | Ok (_header, data) ->
    Alcotest.(check cstruct) "unmarshalling gives expected data" payload data;
    Lwt.return_unit

let write () =
  let open Lwt.Infix in
  let dst = Ipaddr.V4.of_string_exn "192.168.4.20" in
  get_stack dst >>= fun stack ->
  Static_arp.add_entry stack.arp dst (Macaddr.of_string_exn "00:16:3e:ab:cd:ef");
  Udp.write ~src_port:1212 ~dst_port:21 ~dst stack.udp (Cstruct.of_string "MGET *") >|= Rresult.R.get_ok

let unmarshal_regression () =
  let i = Cstruct.create 1016 in
  Cstruct.memset i 30;
  Cstruct.set_char i 4 '\x04';
  Cstruct.set_char i 5 '\x00';
  Alcotest.(check (result reject pass)) "correctly return error for bad packet"
    (Error "parse failed") (Udp_packet.Unmarshal.of_cstruct i);
  Lwt.return_unit


let marshal_marshal () =
  let error_str = Alcotest.result Alcotest.reject Alcotest.string in
  let udp = {Udp_packet.src_port = 1; dst_port = 2} in
  let payload = Cstruct.create 100 in
  let buffer = Cstruct.create Udp_wire.sizeof_udp in
  let src = Ipaddr.V4.of_string_exn "127.0.0.1" in
  let dst = Ipaddr.V4.of_string_exn "127.0.0.1" in
  let pseudoheader = Ipv4_packet.Marshal.pseudoheader ~src ~dst ~proto:`UDP (Cstruct.len buffer + Cstruct.len payload) in
  Udp_packet.Marshal.into_cstruct ~pseudoheader ~payload udp (Cstruct.shift buffer 1)
  |> Alcotest.check error_str "Buffer too short" (Error "Not enough space for a UDP header");
  Udp_packet.Marshal.into_cstruct ~pseudoheader ~payload udp buffer
  |> Alcotest.(check (result unit string)) "Buffer big enough for header" (Ok ());
  Udp_packet.Unmarshal.of_cstruct (Cstruct.concat [buffer; payload])
  |> Alcotest.(check (result (pair udp_packet cstruct) string)) "Save and reload" (Ok (udp, payload));
  Lwt.return_unit

let suite = [
  "unmarshal regression", `Quick, unmarshal_regression;
  "marshal/marshal", `Quick, marshal_marshal;
  "marshal/unmarshal", `Quick, marshal_unmarshal;
  "write packets", `Quick, write;
]
