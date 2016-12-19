open Rresult

let unwrap_ipv4 buf = Ipv4_packet.Unmarshal.of_cstruct buf |> R.reword_error R.msg |> R.error_msg_to_invalid_arg
let verify_ipv4_udp = Ipv4_packet.Unmarshal.verify_transport_checksum ~proto:`UDP
let verify_ipv4_tcp = Ipv4_packet.Unmarshal.verify_transport_checksum ~proto:`TCP

let example_ipv4_udp = "\
\x45\xb8\x00\x4c\xbf\x7c\x40\x00\x34\x11\xdf\x65\x90\x5c\x09\x16\
\x0a\x89\x03\x0c\x00\x7b\x00\x7b\x00\x38\xf4\xfb\x24\x01\x03\xee\
\x00\x00\x00\x00\x00\x00\x00\x43\x47\x50\x53\x00\xdc\x03\xd0\x04\
\x53\x76\x73\x95\xdc\x03\xd0\x06\xcb\xd2\x4f\xfb\xdc\x03\xd0\x06\
\xcd\x57\x43\xa0\xdc\x03\xd0\x06\xcd\xb6\x2e\x51"

let example_ipv4_tcp = "\
\x45\x00\x00\x34\x00\x00\x40\x00\x2d\x06\x47\x91\x93\x4b\x65\x53\
\x0a\x89\x03\x0c\x01\xbb\xe5\xd0\x6f\x75\x20\x55\xf6\x5e\xdb\xef\
\x80\x12\x72\x10\xad\x83\x00\x00\x02\x04\x05\x48\x01\x01\x04\x02\
\x01\x03\x03\x08"

let udp_ipv4_correct_positive () =
  let buf = Cstruct.of_string example_ipv4_udp in
  let (ipv4_header, transport_packet) = unwrap_ipv4 buf in
  Alcotest.(check bool) "for a correct UDP checksum, return true"
    true @@ verify_ipv4_udp ~ipv4_header ~transport_packet;
  Lwt.return_unit

let udp_ipv4_correct_negative () =
  let buf = Cstruct.of_string example_ipv4_udp in
  Cstruct.BE.set_uint32 buf ((Cstruct.len buf) - 4) 0x1234l;
  let (ipv4_header, transport_packet) = unwrap_ipv4 buf in
  Alcotest.(check bool) "mutating the packet w/o fixing checksum causes verification to fail"
    false @@ verify_ipv4_udp ~ipv4_header ~transport_packet;
  Lwt.return_unit

let udp_ipv4_allows_zero () =
  let buf = Cstruct.of_string example_ipv4_udp in
  let (ipv4_header, transport_packet) = unwrap_ipv4 buf in
  Udp_wire.set_udp_checksum transport_packet 0x0000;
  Alcotest.(check bool) "0x0000 checksum is OK for UDP"
    true @@ verify_ipv4_udp ~ipv4_header ~transport_packet;
  Lwt.return_unit

let tcp_ipv4_correct_positive () =
  let buf = Cstruct.of_string example_ipv4_tcp in
  let (ipv4_header, transport_packet) = unwrap_ipv4 buf in
  Alcotest.(check bool) "for a correct TCP checksum, return true"
    true @@ verify_ipv4_tcp ~ipv4_header ~transport_packet;
  Lwt.return_unit

let tcp_ipv4_correct_negative () =
  let buf = Cstruct.of_string example_ipv4_tcp in
  Cstruct.BE.set_uint32 buf ((Cstruct.len buf) - 4) 0x1234l;
  let (ipv4_header, transport_packet) = unwrap_ipv4 buf in
  Alcotest.(check bool) "mutating a TCP packet w/o fixing checksum causes verification to fail"
    false @@ verify_ipv4_tcp ~ipv4_header ~transport_packet;
  Lwt.return_unit

let suite =
[
  "correct UDP IPV4 checksums are recognized",  `Quick, udp_ipv4_correct_positive;
  "incorrect UDP IPV4 checksums are recognized",  `Quick, udp_ipv4_correct_negative;
  "0x00 UDP checksum is valid", `Quick, udp_ipv4_allows_zero;
  "correct TCP IPV4 checksums are recognized",  `Quick, tcp_ipv4_correct_positive;
  "incorrect TCP IPV4 checksums are recognized",  `Quick, tcp_ipv4_correct_negative;
]
