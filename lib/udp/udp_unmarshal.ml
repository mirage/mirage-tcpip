type t = {src_port: Cstruct.uint16; dst_port : Cstruct.uint16; payload : Cstruct.t }

let of_cstruct buf =
  let open Rresult in
  let open Udp_wire in
  let check_header_length () =
    if Cstruct.len buf < sizeof_udp then Error "UDP header too short" else Ok ()
  in
  let check_payload_length hlen buflen () =
    let payload_len = buflen - hlen in
    if payload_len < 0
    then Error "UDP header claimed payload longer than it was"
    else Ok payload_len
  in
  let length = get_udp_length buf in
  check_header_length () >>=
  check_payload_length length (Cstruct.len buf) >>= fun payload_len ->
  let src_port = Udp_wire.get_udp_source_port buf in
  let dst_port = Udp_wire.get_udp_dest_port buf in
  let payload = Cstruct.sub buf Udp_wire.sizeof_udp payload_len in
  Ok { src_port; dst_port; payload }
