open Ethif_wire
open Rresult

let check_len buf =
  if sizeof_ethernet > Cstruct.len buf then
    Result.Error "Not enough space for an Ethernet header"
  else Result.Ok ()

let print_ethif_header ~buf ~ethertype ~src_mac ~dst_mac = 
  check_len buf >>= fun () ->
  set_ethernet_dst (Macaddr.to_bytes dst_mac) 0 buf;
  set_ethernet_src (Macaddr.to_bytes src_mac) 0 buf;
  set_ethernet_ethertype buf (ethertype_to_int ethertype);
  Result.Ok buf
