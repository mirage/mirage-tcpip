let adjust_output_header ~rng ~tlen buf =
  let open Ipv4_wire in
  (* Set the mutable values in the ipv4 header *)
  set_ipv4_len buf tlen;
  set_ipv4_id buf (Randomconv.int16 rng);
  set_ipv4_csum buf 0;
  let checksum = Tcpip_checksum.ones_complement buf in
  set_ipv4_csum buf checksum
