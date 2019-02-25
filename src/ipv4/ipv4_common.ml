let set_checksum buf =
  let open Ipv4_wire in
  (* Set the mutable values in the ipv4 header *)
  set_ipv4_csum buf 0;
  let checksum = Tcpip_checksum.ones_complement buf in
  set_ipv4_csum buf checksum
