let fails msg f args =
  match f args with
  | Result.Ok p -> Alcotest.fail msg
  | Result.Error s -> ()

let cstruct =
  let module M = struct
    type t = Cstruct.t
    let pp = Cstruct.hexdump_pp
    let equal = Cstruct.equal
  end in
  (module M : Alcotest.TESTABLE with type t = M.t)

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
  | Result.Ok (header, data) ->
    Alcotest.(check cstruct) "unmarshalling gives expected data" payload data;
    Lwt.return_unit

let suite = [
  "marshal/unmarshal", `Quick, marshal_unmarshal;
]
