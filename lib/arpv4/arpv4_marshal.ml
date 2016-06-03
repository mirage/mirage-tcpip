open Arpv4_wire

let fill_constants buf =
  set_arp_htype buf 1; (* ethernet *)
  set_arp_ptype buf Ethif_wire.(ethertype_to_int IPv4);
  set_arp_hlen buf 6; (* ethernet mac size *)
  set_arp_plen buf 4; (* ipv4 size *)
  ()

let check_len buf =
  if sizeof_arp > Cstruct.len buf then
    Result.Error "Not enough space for an arpv4 header"
  else Result.Ok ()

let to_cstruct ~buf ~op ~src_ip ~dst_ip ~src_mac ~dst_mac =
  let open Rresult in
  check_len buf >>= fun () ->
  let dmac = Macaddr.to_bytes dst_mac in
  let smac = Macaddr.to_bytes src_mac in
  let spa = Ipaddr.V4.to_int32 src_ip in
  let tpa = Ipaddr.V4.to_int32 dst_ip in
  fill_constants buf;
  set_arp_op buf (op_to_int op);
  set_arp_sha smac 0 buf;
  set_arp_spa buf spa;
  set_arp_tha dmac 0 buf;
  set_arp_tpa buf tpa;
  Result.Ok ()

let make_cstruct t =
  let open Arpv4_unmarshal in
  let open Arpv4_wire in
  let buf = Cstruct.create sizeof_arp in
  let dmac = Macaddr.to_bytes t.tha in
  let smac = Macaddr.to_bytes t.sha in
  let spa = Ipaddr.V4.to_int32 t.spa in
  let tpa = Ipaddr.V4.to_int32 t.tpa in
  fill_constants buf;
  set_arp_op buf (op_to_int t.op);
  set_arp_sha smac 0 buf;
  set_arp_spa buf spa;
  set_arp_tha dmac 0 buf;
  set_arp_tpa buf tpa;
  buf
