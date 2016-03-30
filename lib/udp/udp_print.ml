open Rresult

let print_udp_header ~udp_buf ~src_port ~dst_port ~pseudoheader ~payload =
  let open Udp_wire in
  let check_header_len () =
    if (Cstruct.len udp_buf) < sizeof_udp then Error "Not enough space for a UDP header"
    else Ok ()
  in
  let check_overall_len () =
    if (Cstruct.len udp_buf) < ((Cstruct.lenv payload) + sizeof_udp) then
      Error "Not enough space for header and payload"
    else Ok ((Cstruct.lenv payload) + sizeof_udp)
  in
  check_header_len () >>= check_overall_len >>= fun len ->
  set_udp_source_port udp_buf src_port;
  set_udp_dest_port udp_buf dst_port;
  set_udp_length udp_buf len;
  set_udp_checksum udp_buf 0;
  let csum = Tcpip_checksum.ones_complement_list (pseudoheader :: (udp_buf :: payload)) in
  set_udp_checksum udp_buf csum;
  Ok ()
