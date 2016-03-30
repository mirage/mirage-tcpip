type t = {src_port: Cstruct.uint16; dst_port : Cstruct.uint16; payload : Cstruct.t }

let parse_udp_header buf =
  let open Rresult in
  let open Udp_wire in
  let header_length_check () = 
    if Cstruct.len buf < sizeof_udp then Error "UDP header too short" else Ok ()
  in
  let payload_length_check hlen buflen () =
    let payload_len = buflen - hlen in
    if payload_len < 0
    then Error "UDP header claimed payload longer than it was"
    else Ok payload_len
  in
  let length = get_udp_length buf in
  header_length_check () >>=
  payload_length_check length (Cstruct.len buf) >>= fun payload_len ->
  let src_port = Udp_wire.get_udp_source_port buf in
  let dst_port = Udp_wire.get_udp_dest_port buf in
  let payload = Cstruct.sub buf Udp_wire.sizeof_udp payload_len in
  Ok { src_port; dst_port; payload }
