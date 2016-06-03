open Rresult
open Tcp_wire

type error = string

let to_cstruct ~buf ~src_port ~dst_port ~pseudoheader ~options ~syn
    ~fin ~rst ~psh ~window ~payload ~seq ~rx_ack =
  let check_header_len () =
    if (Cstruct.len buf) < sizeof_tcp then Error "Not enough space for a TCP header"
    else Ok ()
  in
  let check_overall_len header_length =
    if (Cstruct.len buf) < ((Cstruct.lenv payload) + header_length) then
      Error (Printf.sprintf "Not enough space for header and payload: %d < %d"
               (Cstruct.len buf) (Cstruct.lenv payload + header_length))
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
  let options_frame = Cstruct.shift buf sizeof_tcp in
  check_header_len () >>= fun () ->
  insert_options options_frame >>= fun options_len ->
  check_overall_len (sizeof_tcp + options_len) >>= fun len ->
  let sequence = Sequence.to_int32 seq in
  let ack_number =
    match rx_ack with Some n -> Sequence.to_int32 n |None -> 0l
  in
  let data_off = (sizeof_tcp / 4) + (options_len / 4) in
  set_tcp_src_port buf src_port;
  set_tcp_dst_port buf dst_port;
  set_tcp_sequence buf sequence;
  set_tcp_ack_number buf ack_number;
  set_data_offset buf data_off;
  set_tcp_flags buf 0;
  if rx_ack <> None then set_ack buf;
  if rst then set_rst buf;
  if syn then set_syn buf;
  if fin then set_fin buf;
  if psh then set_psh buf;
  set_tcp_window buf window;
  set_tcp_checksum buf 0;
  set_tcp_urg_ptr buf 0;
  let checksum = Tcpip_checksum.ones_complement_list (pseudoheader :: (buf :: payload)) in
  set_tcp_checksum buf checksum;
  Ok (sizeof_tcp + options_len)

let make_cstruct ~pseudoheader t =
  let open Tcp_unmarshal in
  let options_buf = Cstruct.create 40 in (* more than 40 bytes of options can't
                                            be signalled in the length field of
                                            the tcp header *)
  let options_len = Options.marshal options_buf t.options in
  let options_buf = Cstruct.set_len options_buf options_len in
  let buf = Cstruct.create sizeof_tcp in
  let sequence = Sequence.to_int32 t.sequence in
  let ack_number = Sequence.to_int32 t.ack_number in
  let data_off = (sizeof_tcp / 4) + (options_len / 4) in
  set_tcp_src_port buf t.source_port;
  set_tcp_dst_port buf t.dest_port;
  set_tcp_sequence buf sequence;
  set_tcp_ack_number buf ack_number;
  set_data_offset buf data_off;
  set_tcp_flags buf 0;
  if t.ack then set_ack buf;
  if t.rst then set_rst buf;
  if t.syn then set_syn buf;
  if t.fin then set_fin buf;
  if t.psh then set_psh buf;
  set_tcp_window buf t.window;
  set_tcp_checksum buf 0;
  set_tcp_urg_ptr buf 0;
  let checksum = Tcpip_checksum.ones_complement_list [pseudoheader ; buf ;
                                                      options_buf  ; t.data ] in
  set_tcp_checksum buf checksum;
  Cstruct.concat [buf; options_buf]
