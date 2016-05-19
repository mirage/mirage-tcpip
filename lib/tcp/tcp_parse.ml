open Rresult

type t = {
  urg : bool;
  ack : bool;
  psh : bool;
  rst : bool;
  syn : bool;
  fin : bool;
  window : Cstruct.uint16;
  options : Options.t list;
  data : Cstruct.t;
  sequence : Sequence.t;
  ack_number : Sequence.t;
  source_port : Cstruct.uint16;
  dest_port : Cstruct.uint16;
  }

let parse_tcp_header pkt =
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
      Options.unmarshal (Cstruct.shift pkt sizeof_tcp)
    else if data_offset < 20 then
      Result.Error "data offset was unreasonably short; TCP header can't be valid"
    else (Ok [])
  in
  try
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
    let source_port = get_tcp_src_port pkt in
    let dest_port = get_tcp_dst_port pkt in
    let data = Cstruct.shift pkt data_offset in
    Result.Ok { urg; ack; psh; rst; syn; fin; window; options; data;
                sequence; ack_number; source_port; dest_port }
  with
  | Invalid_argument s -> Result.Error s
