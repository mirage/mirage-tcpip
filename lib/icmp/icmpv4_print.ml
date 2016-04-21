open Icmpv4_wire

let echo ?payload ty id seq =
  let header = Cstruct.create sizeof_icmpv4 in
  set_icmpv4_ty header (ty_to_int ty);
  set_icmpv4_code header 0x00;
  set_icmpv4_csum header 0x0000;
  set_icmpv4_seq header seq;
  set_icmpv4_id header id;
  let packet = match payload with
    | Some payload -> Cstruct.append header payload
    | None -> header
  in
  set_icmpv4_csum header (Tcpip_checksum.ones_complement_list [ packet ]);
  packet

let echo_request ?payload id seq =
  echo ?payload Echo_request id seq

let echo_reply ?payload id seq =
  echo ?payload Echo_reply id seq
