type t = {
  urg : bool;
  ack : bool;
  psh : bool;
  rst : bool;
  syn : bool;
  fin : bool;
  window : Cstruct.uint16;
  options : Options.t list;
  sequence : Sequence.t;
  ack_number : Sequence.t;
  src_port : Cstruct.uint16;
  dst_port : Cstruct.uint16;
}

let equal {urg; ack; psh; rst; syn; fin; window; options; sequence; ack_number;
           src_port; dst_port} q =
  src_port = q.src_port &&
  dst_port = q.dst_port &&
  window = q.window &&
  urg = q.urg && ack = q.ack && psh = q.psh && rst = q.rst && syn = q.syn && fin = q.fin &&
  Sequence.compare sequence q.sequence = 0 &&
  Sequence.compare ack_number q.ack_number = 0 &&
  List.for_all2 Options.equal options q.options

let pp fmt t =
  Format.fprintf fmt
    "TCP packet seq=%a acknum=%a ack=%b rst=%b syn=%b fin=%b win=%d options=%a"
    Sequence.pp t.sequence Sequence.pp t.ack_number
    t.ack t.rst t.syn t.fin t.window Options.pps t.options

module Unmarshal = struct
  open Rresult

  type error = string

  let of_cstruct pkt =
    let open Tcp_wire in
    let check_len pkt =
      if Cstruct.len pkt < sizeof_tcp then
        Result.Error "packet too short to contain a TCP packet of any size"
      else
        Ok (Tcp_wire.get_data_offset pkt)
    in
    let long_enough data_offset = if Cstruct.len pkt < data_offset then
        Result.Error "packet too short to contain a TCP packet of the size claimed"
      else
        Ok ()
    in
    let options data_offset pkt =
      if data_offset > 20 then
        Options.unmarshal (Cstruct.sub pkt sizeof_tcp (data_offset - sizeof_tcp))
      else if data_offset < 20 then
        Result.Error "data offset was unreasonably short; TCP header can't be valid"
      else (Ok [])
    in
    check_len pkt >>= fun data_offset ->
    long_enough data_offset >>= fun () ->
    options data_offset pkt >>= fun options ->
    let sequence = get_tcp_sequence pkt |> Sequence.of_int32 in
    let ack_number = get_tcp_ack_number pkt |> Sequence.of_int32 in
    let urg = get_urg pkt in
    let ack = get_ack pkt in
    let psh = get_psh pkt in
    let rst = get_rst pkt in
    let syn = get_syn pkt in
    let fin = get_fin pkt in
    let window = get_tcp_window pkt in
    let src_port = get_tcp_src_port pkt in
    let dst_port = get_tcp_dst_port pkt in
    let data = Cstruct.shift pkt data_offset in
    Result.Ok ({ urg; ack; psh; rst; syn; fin; window; options;
                sequence; ack_number; src_port; dst_port }, data)
end
module Marshal = struct
  open Rresult
  open Tcp_wire

  type error = string

  let unsafe_fill ~pseudoheader ~payload t buf options_len =
    let data_off = sizeof_tcp + options_len in
    let buf = Cstruct.sub buf 0 data_off in
    set_tcp_src_port buf t.src_port;
    set_tcp_dst_port buf t.dst_port;
    set_tcp_sequence buf (Sequence.to_int32 t.sequence);
    set_tcp_ack_number buf (Sequence.to_int32 t.ack_number);
    set_data_offset buf (data_off / 4);
    set_tcp_flags buf 0;
    if t.urg then set_urg buf;
    if t.ack then set_ack buf;
    if t.rst then set_rst buf;
    if t.syn then set_syn buf;
    if t.fin then set_fin buf;
    if t.psh then set_psh buf;
    set_tcp_window buf t.window;
    set_tcp_checksum buf 0;
    set_tcp_urg_ptr buf 0;
    (* it's possible we've been passed a buffer larger than the size of the header,
     * which contains some data after the end of the header we'll write;
     * in this case, make sure we compute the checksum properly *)
    let checksum = Tcpip_checksum.ones_complement_list [pseudoheader ; buf ;
                                                        payload] in
    set_tcp_checksum buf checksum;
    ()

  let into_cstruct ~pseudoheader ~payload t buf =
    let check_header_len () =
      if (Cstruct.len buf) < sizeof_tcp then Error "Not enough space for a TCP header"
      else Ok ()
    in
    let check_overall_len header_length =
      if (Cstruct.len buf) < header_length then
        Error (Printf.sprintf "Not enough space for TCP header: %d < %d"
                 (Cstruct.len buf) header_length)
      else Ok ()
    in
    let insert_options options_frame =
      match t.options with
      |[] -> Ok 0
      |options ->
        try
          Ok (Options.marshal options_frame options)
        with
        (* handle the case where we ran out of room in the buffer while attempting
           to write the options *)
        | Invalid_argument s -> Error s
    in
    let options_frame = Cstruct.shift buf sizeof_tcp in
    check_header_len () >>= fun () ->
    insert_options options_frame >>= fun options_len ->
    check_overall_len (sizeof_tcp + options_len) >>= fun () ->
    let buf = Cstruct.sub buf 0 (sizeof_tcp + options_len) in
    unsafe_fill ~pseudoheader ~payload t buf options_len;
    Ok (sizeof_tcp + options_len)

  let make_cstruct ~pseudoheader ~payload t =
    let buf = Cstruct.create (sizeof_tcp + 40) in (* more than 40 bytes of options can't
                                                     be signalled in the length field of
                                                     the tcp header *)
    let options_buf = Cstruct.shift buf sizeof_tcp in
    let options_len = Options.marshal options_buf t.options in
    let buf = Cstruct.set_len buf (sizeof_tcp + options_len) in
    unsafe_fill ~pseudoheader ~payload t buf options_len;
    buf
end
