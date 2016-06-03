type t = {
  src_port : Cstruct.uint16;
  dst_port : Cstruct.uint16;
}

module Unmarshal = struct

  type error = string

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
    Ok ({ src_port; dst_port; }, payload)
end
module Marshal = struct
  open Rresult

  type error = string

  let to_cstruct ~udp_buf ~src_port ~dst_port ~pseudoheader ~payload =
    let open Udp_wire in
    let check_header_len () =
      if (Cstruct.len udp_buf) < sizeof_udp then Error "Not enough space for a UDP header"
      else Ok ()
    in
    let check_overall_len () =
      if (Cstruct.len udp_buf) < ((Cstruct.len payload) + sizeof_udp) then
        Error "Not enough space for header and payload"
      else Ok ((Cstruct.len payload) + sizeof_udp)
    in
    check_header_len () >>= check_overall_len >>= fun len ->
    set_udp_source_port udp_buf src_port;
    set_udp_dest_port udp_buf dst_port;
    set_udp_length udp_buf len;
    set_udp_checksum udp_buf 0;
    let csum = Tcpip_checksum.ones_complement_list [ pseudoheader ; udp_buf ; payload ] in
    set_udp_checksum udp_buf csum;
    Ok ()

  let make_cstruct ~pseudoheader ~payload t =
    let open Udp_wire in
    let buf = Cstruct.create Udp_wire.sizeof_udp in
    let len = sizeof_udp + Cstruct.len payload in
    set_udp_source_port buf t.src_port;
    set_udp_dest_port buf t.dst_port;
    set_udp_length buf len;
    set_udp_checksum buf 0;
    let csum = Tcpip_checksum.ones_complement_list [ pseudoheader ; buf ; payload ] in
    set_udp_checksum buf csum;
    buf
end
