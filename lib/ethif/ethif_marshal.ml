open Ethif_wire
open Rresult

type error = string

let check_len buf =
  if sizeof_ethernet > Cstruct.len buf then
    Result.Error "Not enough space for an Ethernet header"
  else Result.Ok ()

let to_cstruct ~buf ~ethertype ~src_mac ~dst_mac =
  check_len buf >>= fun () ->
  set_ethernet_dst (Macaddr.to_bytes dst_mac) 0 buf;
  set_ethernet_src (Macaddr.to_bytes src_mac) 0 buf;
  set_ethernet_ethertype buf (ethertype_to_int ethertype);
  Result.Ok ()

let make_cstruct t =
  let open Ethif_unmarshal in
  let buf = Cstruct.create sizeof_ethernet in
  Cstruct.memset buf 0x00; (* can be removed in the future *)
  set_ethernet_dst (Macaddr.to_bytes t.source) 0 buf;
  set_ethernet_src (Macaddr.to_bytes t.destination) 0 buf;
  set_ethernet_ethertype buf (ethertype_to_int t.ethertype);
  buf
