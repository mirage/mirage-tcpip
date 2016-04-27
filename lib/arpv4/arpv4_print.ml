open Arpv4_wire

let fill_constants buf =
  set_arp_htype buf 1; (* ethernet *)
  set_arp_ptype buf 0x0800; (* IPv4 *)
  set_arp_hlen buf 6; (* ethernet mac size *)
  set_arp_plen buf 4; (* ipv4 size *)
  ()

let check_len buf =
  if sizeof_arp > Cstruct.len buf then
    Result.Error "Not enough space for an arpv4 header"
  else Result.Ok ()

let print_arpv4_header ~buf ~op ~src_ip ~dst_ip ~src_mac ~dst_mac =
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

let print_arp_request ~buf ~src_ip ~src_mac ~dst_ip =
  let open Rresult in
  let tha = Macaddr.(to_bytes broadcast) in
  let sha = Macaddr.to_bytes src_mac in
  let spa = Ipaddr.V4.to_int32 src_ip in
  let tpa = Ipaddr.V4.to_int32 dst_ip in
  check_len buf >>= fun () ->
  fill_constants buf;
  set_arp_op buf (op_to_int Request);
  set_arp_sha sha 0 buf;
  set_arp_spa buf spa;
  set_arp_tha tha 0 buf;
  set_arp_tpa buf tpa;
  Result.Ok ()
