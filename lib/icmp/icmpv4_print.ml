let echo_request id seq =
  let open Icmpv4_wire in
  (* TODO: can this just be an appropriately-sized cstruct? *)
  let buf = Io_page.(get 1 |> to_cstruct) in
  let buf = Cstruct.set_len buf sizeof_icmpv4 in
  set_icmpv4_ty buf 0x08;
  set_icmpv4_code buf 0x00;
  set_icmpv4_seq buf seq;
  set_icmpv4_id buf id;
  buf
