open Rresult

let print_tcp_header ~tcp_buf ~src_port ~dst_port ~pseudoheader ~options ~syn
    ~fin ~rst ~psh ~window ~payload ~seq ~rx_ack =
  let open Tcp_wire in
  let check_header_len () =
    if (Cstruct.len tcp_buf) < sizeof_tcp then Error "Not enough space for a TCP header"
    else Ok ()
  in
  let check_overall_len header_length =
    if (Cstruct.len tcp_buf) < ((Cstruct.lenv payload) + header_length) then
      Error (Printf.sprintf "Not enough space for header and payload: %d < %d"
               (Cstruct.len tcp_buf) (Cstruct.lenv payload + header_length))
    else Ok ((Cstruct.lenv payload) + sizeof_tcp)
  in
  let insert_options options_frame =
    match options with
    |[] -> Ok 0
    |options -> try
        Ok (Options.marshal options_frame options)
      with
      (* handle the case where we ran out of room in the buffer while attempting
         to write the options *)
      | Invalid_argument s -> Error s
  in
  let options_frame = Cstruct.shift tcp_buf sizeof_tcp in
  check_header_len () >>= fun () ->
  insert_options options_frame >>= fun options_len ->
  check_overall_len (sizeof_tcp + options_len) >>= fun len ->
  let sequence = Sequence.to_int32 seq in
  let ack_number =
    match rx_ack with Some n -> Sequence.to_int32 n |None -> 0l
  in
  let data_off = (sizeof_tcp / 4) + (options_len / 4) in
  set_tcp_src_port tcp_buf src_port;
  set_tcp_dst_port tcp_buf dst_port;
  set_tcp_sequence tcp_buf sequence;
  set_tcp_ack_number tcp_buf ack_number;
  set_data_offset tcp_buf data_off;
  set_tcp_flags tcp_buf 0;
  if rx_ack <> None then set_ack tcp_buf;
  if rst then set_rst tcp_buf;
  if syn then set_syn tcp_buf;
  if fin then set_fin tcp_buf;
  if psh then set_psh tcp_buf;
  set_tcp_window tcp_buf window;
  set_tcp_checksum tcp_buf 0;
  set_tcp_urg_ptr tcp_buf 0;
  let checksum = Tcpip_checksum.ones_complement_list (pseudoheader :: (tcp_buf :: payload)) in
  set_tcp_checksum tcp_buf checksum;
  Ok (sizeof_tcp + options_len)
