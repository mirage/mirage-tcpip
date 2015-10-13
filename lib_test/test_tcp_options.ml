let test_unmarshal_bad_mss () =
  let odd_sized_mss = Cstruct.create 3 in
  Cstruct.set_uint8 odd_sized_mss 0 2;
  Cstruct.set_uint8 odd_sized_mss 1 3;
  Cstruct.set_uint8 odd_sized_mss 2 255;
  OUnit.assert_raises (Tcp.Options.Bad_option "Invalid option 2 presented")
    (fun () -> Tcp.Options.unmarshal odd_sized_mss);
  Lwt.return_unit

let test_unmarshal_bogus_length () =
  let bogus = Cstruct.create (4*8-1) in
  Cstruct.memset bogus 0;
  Cstruct.blit_from_string "\x6e\x73\x73\x68\x2e\x63\x6f\x6d" 0 bogus 0 8;
  (* some unknown option (0x6e) with claimed length 0x73, longer than the buffer *)
  OUnit.assert_raises (Tcp.Options.Bad_option "Invalid option 110 presented")
    (fun () -> Tcp.Options.unmarshal bogus);
  Lwt.return_unit

let test_unmarshal_zero_length () =
  let bogus = Cstruct.create 10 in
  Cstruct.memset bogus 1; (* noops *)
  Cstruct.set_uint8 bogus 0 64; (* arbitrary unknown option-kind *)
  Cstruct.set_uint8 bogus 1 0;
  OUnit.assert_raises (Tcp.Options.Bad_option "Invalid option 64 presented")
    (fun () -> Tcp.Options.unmarshal bogus);
  Lwt.return_unit

let test_unmarshal_simple_options () =
  (* empty buffer should give empty list *)
  OUnit.assert_equal [] (Tcp.Options.unmarshal (Cstruct.create 0));

  (* buffer with just eof should give empty list *)
  let just_eof = Cstruct.create 1 in
  Cstruct.set_uint8 just_eof 0 0;
  OUnit.assert_equal [] (Tcp.Options.unmarshal just_eof);

  (* buffer with single noop should give a list with 1 noop *)
  let just_noop = Cstruct.create 1 in
  Cstruct.set_uint8 just_noop 0 1;
  OUnit.assert_equal [ Tcp.Options.Noop ] (Tcp.Options.unmarshal just_noop); 

  (* buffer with valid, but unknown, option should be correctly communicated *)
  let unknown = Cstruct.create 10 in
  let data = "hi mom!!" in
  let kind = 18 in (* TODO: more canonically unknown option-kind *)
  Cstruct.blit_from_string data 0 unknown 2 (String.length data);
  Cstruct.set_uint8 unknown 0 kind;
  Cstruct.set_uint8 unknown 1 (Cstruct.len unknown);
  OUnit.assert_equal (Tcp.Options.unmarshal unknown) [Tcp.Options.Unknown (kind, data) ];
  Lwt.return_unit

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
  let result = Tcp.Options.unmarshal buf in
  OUnit.assert_equal ~msg:"SACK_ok missing" ~printer:string_of_bool
    true (List.mem Tcp.Options.SACK_ok result);
  OUnit.assert_equal ~msg: "noop missing" ~printer:string_of_bool
    true (List.mem Tcp.Options.Noop result);
  OUnit.assert_equal ~msg:"timestamp present" ~printer:string_of_bool
    false (List.mem (Tcp.Options.Timestamp (ts1, ts2)) result);
  Lwt.return_unit

let test_unmarshal_ok_options () =
  let buf = Cstruct.create 8 in
  Cstruct.memset buf 0;
  let opts = [ Tcp.Options.MSS 536; Tcp.Options.SACK_ok; Tcp.Options.Noop;
               Tcp.Options.Noop ] in
  let printer l =
    let buf = Buffer.create 10 in
    Buffer.clear buf;
    Tcp.Options.pps (Format.formatter_of_buffer buf) l;
    Buffer.to_bytes buf
  in
  let marshalled = Tcp.Options.marshal buf opts in
  OUnit.assert_equal ~printer:string_of_int marshalled 8;
  (* order is reversed by the unmarshaller, which is fine but we need to
     account for that when making equality assertions *)
  OUnit.assert_equal ~printer (List.rev (Tcp.Options.unmarshal buf)) opts;
  Lwt.return_unit

let test_unmarshal_random_data () =
  let random = Cstruct.create 64 in
  let iterations = 100 in
  Random.self_init ();
  let set_random pos =
    let num = Random.int32 Int32.max_int in
    Cstruct.BE.set_uint32 random pos num;
  in
  let rec check = function
    | n when n <= 0 -> Lwt.return_unit
    | n ->
      List.iter set_random [0;4;8;12;16;20;24;28;32;36;40;44;48;52;56;60];
      Cstruct.hexdump random;
      (* acceptable outcomes: some list of options or the expected exception *)
      try
        let l = Tcp.Options.unmarshal random in
        Tcp.Options.pps Format.std_formatter l;
        (* a really basic truth: the longest list we can have is 64 noops *)
        OUnit.assert_equal true (List.length l < 65);
        check (n - 1)
      with
      | Tcp.Options.Bad_option _ -> check (n - 1)
  in
  check iterations


let suite = [
  "unmarshal broken mss", `Quick, test_unmarshal_bad_mss;
  "unmarshal option with bogus length", `Quick, test_unmarshal_bogus_length;
  "unmarshal option with zero length", `Quick, test_unmarshal_zero_length;
  "unmarshal simple cases", `Quick, test_unmarshal_simple_options;
  "unmarshal stops at eof", `Quick, test_unmarshal_stops_at_eof;
  "unmarshal non-broken tcp options", `Quick, test_unmarshal_ok_options;
  "unmarshalling random data returns", `Quick, test_unmarshal_random_data;
]
