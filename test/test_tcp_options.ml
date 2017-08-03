open Common

let check = Alcotest.(check @@ result (list options) string)

let errors ?(check_msg = false) exp = function
  | Ok opt ->
    Fmt.kstrf Alcotest.fail "Result.Ok %a when Result.error %s expected"
      Tcp.Options.pps opt exp
  | Error p -> if check_msg then
      Alcotest.(check string)
        "Result.Error didn't give the expected error message" exp p
    else ()

let test_unmarshal_bad_mss () =
  let odd_sized_mss = Cstruct.create 3 in
  Cstruct.set_uint8 odd_sized_mss 0 2;
  Cstruct.set_uint8 odd_sized_mss 1 3;
  Cstruct.set_uint8 odd_sized_mss 2 255;
  errors "MSS size is unreasonable" (Tcp.Options.unmarshal odd_sized_mss)

let test_unmarshal_bogus_length () =
  let bogus = Cstruct.create (4*8-1) in
  Cstruct.memset bogus 0;
  Cstruct.blit_from_string "\x6e\x73\x73\x68\x2e\x63\x6f\x6d" 0 bogus 0 8;
  (* some unknown option (0x6e) with claimed length 0x73, longer than
     the buffer. This invalidates later results, but previous ones are
     still valid, if any *)
  check "length" (Ok []) (Tcp.Options.unmarshal bogus)

let test_unmarshal_zero_length () =
  let bogus = Cstruct.create 10 in
  Cstruct.memset bogus 1; (* noops *)
  Cstruct.set_uint8 bogus 0 64; (* arbitrary unknown option-kind *)
  Cstruct.set_uint8 bogus 1 0;
  (* this invalidates later results, but previous ones are still
     valid, if any *)
  check "zero" (Ok []) (Tcp.Options.unmarshal bogus)

let test_unmarshal_simple_options () =
  (* empty buffer should give empty list *)
  check "simple" (Ok []) (Tcp.Options.unmarshal (Cstruct.create 0));

  (* buffer with just eof should give empty list *)
  let just_eof = Cstruct.create 1 in
  Cstruct.set_uint8 just_eof 0 0;
  check "eof" (Ok []) (Tcp.Options.unmarshal just_eof);

  (* buffer with single noop should give a list with 1 noop *)
  let just_noop = Cstruct.create 1 in
  Cstruct.set_uint8 just_noop 0 1;
  check "noop" (Ok [ Tcp.Options.Noop ]) (Tcp.Options.unmarshal just_noop);

  (* buffer with valid, but unknown, option should be correctly communicated *)
  let unknown = Cstruct.create 10 in
  let data = "hi mom!!" in
  let kind = 18 in (* TODO: more canonically unknown option-kind *)
  Cstruct.blit_from_string data 0 unknown 2 (String.length data);
  Cstruct.set_uint8 unknown 0 kind;
  Cstruct.set_uint8 unknown 1 (Cstruct.len unknown);
  check "more"
    (Ok [Tcp.Options.Unknown (kind, data)])
    (Tcp.Options.unmarshal unknown)

let test_unmarshal_stops_at_eof () =
  let buf = Cstruct.create 14 in
  let ts1 = (Int32.of_int 0xabad1dea) in
  let ts2 = (Int32.of_int 0xc0ffee33) in
  Cstruct.memset buf 0;
  Cstruct.set_uint8 buf 0 4; (* sack_ok *)
  Cstruct.set_uint8 buf 1 2; (* length of two *)
  Cstruct.set_uint8 buf 2 1; (* noop *)
  Cstruct.set_uint8 buf 3 0; (* eof *)
  Cstruct.set_uint8 buf 4 8; (* timestamp *)
  Cstruct.set_uint8 buf 5 10; (* timestamps are 2 4-byte times *)
  Cstruct.BE.set_uint32 buf 6 ts1;
  Cstruct.BE.set_uint32 buf 10 ts2;
  (* correct parsing will ignore options from after eof, so we shouldn't see
     timestamp or noop *)
  match Tcp.Options.unmarshal buf with
  | Error s -> Alcotest.fail s
  | Ok result ->
    Alcotest.(check bool) "SACK_ok missing"
      true (List.mem Tcp.Options.SACK_ok result);
    Alcotest.(check bool) "noop missing"
      true (List.mem Tcp.Options.Noop result);
    Alcotest.(check bool) "timestamp present"
      false (List.mem (Tcp.Options.Timestamp (ts1, ts2)) result)

let test_unmarshal_ok_options () =
  let buf = Cstruct.create 8 in
  Cstruct.memset buf 0;
  let opts = [ Tcp.Options.MSS 536; Tcp.Options.SACK_ok; Tcp.Options.Noop;
               Tcp.Options.Noop ] in
  let marshalled = Tcp.Options.marshal buf opts in
  Alcotest.(check int) "marshalled" marshalled 8;
  (* order is reversed by the unmarshaller, which is fine but we need to
     account for that when making equality assertions *)
  match Tcp.Options.unmarshal buf with
  | Error s -> Alcotest.fail s
  | Ok l    -> Alcotest.(check @@ list options) "l" l opts

let test_unmarshal_random_data () =
  let random = Cstruct.create 64 in
  let iterations = 100 in
  Random.self_init ();
  let set_random pos =
    let num = Random.int32 Int32.max_int in
    Cstruct.BE.set_uint32 random pos num;
  in
  let rec check = function
    | n when n <= 0 -> ()
    | n ->
      List.iter set_random [0;4;8;12;16;20;24;28;32;36;40;44;48;52;56;60];
      Cstruct.hexdump random;
      (* acceptable outcomes: some list of options or the expected exception *)
      match Tcp.Options.unmarshal random with
      | Error _ -> (* Errors are OK, just finish *) ()
      | Ok l ->
        Tcp.Options.pps Format.std_formatter l;
        (* a really basic truth: the longest list we can have is 64 noops *)
        Alcotest.(check bool) "random" true (List.length l < 65);
        check (n - 1)
  in
  check iterations

let test_marshal_unknown () =
  let buf = Cstruct.create 10 in
  Cstruct.memset buf 255;
  let unknown = [ Tcp.Options.Unknown (64, "  ") ] in (* overall, length 4 *)
  Alcotest.(check int) "4 bytes"
    4 (Tcp.Options.marshal buf unknown); (* should have written 4 bytes *)
  Cstruct.hexdump buf;
  (* option-kind *)
  Alcotest.(check int) "option kind" 64 (Cstruct.get_uint8 buf 0);
  (* option-length *)
  Alcotest.(check int)"option length" 4 (Cstruct.get_uint8 buf 1);
  (* data *)
  Alcotest.(check int) "data 1" 0x20 (Cstruct.get_uint8 buf 2);
  (* moar data *)
  Alcotest.(check int) "data 2" 0x20 (Cstruct.get_uint8 buf 3);
   (* unwritten region *)
  Alcotest.(check int) "canary" 255 (Cstruct.get_uint8 buf 4)

let test_options_marshal_padding () =
  let buf = Cstruct.create 8 in
  Cstruct.memset buf 255;
  let extract = Cstruct.get_uint8 buf in
  let needs_padding = [ Tcp.Options.SACK_ok ] in
  Alcotest.(check int) "padding"   4 (Tcp.Options.marshal buf needs_padding);
  Alcotest.(check int) "extract 0" 4 (extract 0);
  Alcotest.(check int) "extract 1" 2 (extract 1);
  (* should pad out the rest of the buffer with 0 *)
  Alcotest.(check int) "extract 2" 0 (extract 2);
  Alcotest.(check int) "extract 3" 0 (extract 3);
  (* but not keep padding into random memory *)
  Alcotest.(check int) "extract 4" 255 (extract 4)

let test_marshal_empty () =
  let buf = Cstruct.create 4 in
  Cstruct.memset buf 255;
  Alcotest.(check int) "0"   0 (Tcp.Options.marshal buf []);
  Alcotest.(check int) "255" 255 (Cstruct.get_uint8 buf 0)

let test_marshal_into_cstruct () =
  let options = [
    Tcp.Options.MSS 1460;
    Tcp.Options.SACK_ok;
    Tcp.Options.Window_size_shift 2
  ] in
  (* MSS is 4 bytes, SACK_OK is 4 bytes, window_size_shift is 3, plus
     1 for padding *)
  let options_size = 12 in
  let buf = Cstruct.create (Tcp.Tcp_wire.sizeof_tcp + options_size) in
  Cstruct.memset buf 255;
  let src = Ipaddr.V4.of_string_exn "127.0.0.1" in
  let dst = Ipaddr.V4.of_string_exn "127.0.0.1" in
  let ipv4_header =
    {Ipv4_packet.src; dst; proto = 6; ttl = 64; options = Cstruct.create 0}
  in
  let payload = Cstruct.of_string "ab" in
  let pseudoheader =
    Ipv4_packet.Marshal.pseudoheader ~src ~dst ~proto:`TCP
      (Tcp.Tcp_wire.sizeof_tcp + options_size + Cstruct.len payload)
  in
  let packet =
    Tcp.Tcp_packet.{
      urg = false;
      ack = true;
      psh = false;
      rst = false;
      syn = true;
      fin = false;
      window = 0;
      options;
      sequence = Tcp.Sequence.of_int 255;
      ack_number = Tcp.Sequence.of_int 1024;
      src_port = 3000;
      dst_port = 6667;
    }
  in
  Tcp.Tcp_packet.Marshal.into_cstruct ~pseudoheader ~payload packet buf
  |> Alcotest.(check (result int string)) "correct size written"
    (Ok (Cstruct.len buf));
  let raw =Cstruct.concat [buf; payload]  in
  Ipv4_packet.Unmarshal.verify_transport_checksum ~proto:`TCP ~ipv4_header
    ~transport_packet:raw
  |> Alcotest.(check bool) "Checksum correct" true;
  Tcp.Tcp_packet.Unmarshal.of_cstruct raw
  |> Alcotest.(check (result (pair tcp_packet cstruct) string))
    "reload TCP packet" (Ok (packet, payload));
  let just_options = Cstruct.create options_size in
  let generated_options = Cstruct.shift buf Tcp.Tcp_wire.sizeof_tcp in
  Alcotest.(check int) "size of options buf" options_size @@
  Tcp.Options.marshal just_options options;
  (* expecting the result of Options.Marshal to be here *)
  Alcotest.check cstruct "marshalled options are as expected"
    just_options generated_options;
  (* Now try with make_cstruct *)
  let headers =
    Tcp.Tcp_packet.Marshal.make_cstruct ~pseudoheader ~payload packet
  in
  let raw =Cstruct.concat [headers; payload]  in
  Ipv4_packet.Unmarshal.verify_transport_checksum ~proto:`TCP ~ipv4_header
    ~transport_packet:raw
  |> Alcotest.(check bool) "Checksum correct" true

let test_marshal_without_padding () =
  let options = [ Tcp.Options.MSS 1460 ] in
  let options_size = 4 in (* MSS is 4 bytes *)
  let buf = Cstruct.create (Tcp.Tcp_wire.sizeof_tcp + options_size) in
  Cstruct.memset buf 255;
  let src = Ipaddr.V4.of_string_exn "127.0.0.1" in
  let dst = Ipaddr.V4.of_string_exn "127.0.0.1" in
  let ipv4_header =
    {Ipv4_packet.src; dst; proto = 6; ttl = 64; options = Cstruct.create 0}
  in
  let payload = Cstruct.of_string "\x02\x04\x05\xb4" in
  let pseudoheader =
    Ipv4_packet.Marshal.pseudoheader ~src ~dst ~proto:`TCP
      (Tcp.Tcp_wire.sizeof_tcp + options_size + Cstruct.len payload)
  in
  let packet =
    Tcp.Tcp_packet.{
      urg = false;
      ack = true;
      psh = false;
      rst = false;
      syn = true;
      fin = false;
      window = 0;
      options;
      sequence = Tcp.Sequence.of_int 255;
      ack_number = Tcp.Sequence.of_int 1024;
      src_port = 3000;
      dst_port = 6667;
    }
  in
  Tcp.Tcp_packet.Marshal.into_cstruct ~pseudoheader ~payload packet buf
  |> Alcotest.(check (result int string)) "correct size written"
    (Ok (Cstruct.len buf));
  let raw =Cstruct.concat [buf; payload]  in
  Ipv4_packet.Unmarshal.verify_transport_checksum ~proto:`TCP ~ipv4_header
    ~transport_packet:raw
  |> Alcotest.(check bool) "Checksum correct" true;
  Tcp.Tcp_packet.Unmarshal.of_cstruct raw
  |> Alcotest.(check (result (pair tcp_packet cstruct) string))
    "reload TCP packet" (Ok (packet, payload))

let suite = [
  "unmarshal broken mss", `Quick, test_unmarshal_bad_mss;
  "unmarshal option with bogus length", `Quick, test_unmarshal_bogus_length;
  "unmarshal option with zero length", `Quick, test_unmarshal_zero_length;
  "unmarshal simple cases", `Quick, test_unmarshal_simple_options;
  "unmarshal stops at eof", `Quick, test_unmarshal_stops_at_eof;
  "unmarshal non-broken tcp options", `Quick, test_unmarshal_ok_options;
  "unmarshalling random data returns", `Quick, test_unmarshal_random_data;
  "test marshalling into a cstruct", `Quick, test_marshal_into_cstruct;
  "test marshalling without padding", `Quick, test_marshal_without_padding;
  "test marshalling an unknown value", `Quick, test_marshal_unknown;
  "test options marshalling when padding is needed", `Quick,
  test_options_marshal_padding;
  "test marshalling the empty list", `Quick, test_marshal_empty;
]

let suite =
  List.map (fun (n, s, f) -> n, s, (fun () -> Lwt.return (f ()))) suite
