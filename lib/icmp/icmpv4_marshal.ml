open Icmpv4_wire

let echo ~buf ?payload ~ty ~id ~seq =
  let min_len = sizeof_icmpv4 + (match payload with | None -> 0 | Some payload ->
      Cstruct.len payload) in
  if Cstruct.len buf < min_len then
    Result.Error "Not enough space for ICMP header and payload"
  else begin
    let buf = Cstruct.set_len buf min_len in
    set_icmpv4_ty buf (ty_to_int ty);
    set_icmpv4_code buf 0x00;
    set_icmpv4_csum buf 0x0000;
    set_icmpv4_seq buf seq;
    set_icmpv4_id buf id;
    let packets = match payload with
      | Some payload -> [buf ; payload]
      | None -> [buf]
    in
    set_icmpv4_csum buf (Tcpip_checksum.ones_complement_list packets);
    Result.Ok ()
  end

let echo_request ~buf ?payload ~id ~seq =
  echo ~buf ?payload ~ty:Echo_request ~id ~seq

let echo_reply ~buf ?payload ~id ~seq =
  echo ~buf ?payload ~ty:Echo_reply ~id ~seq

(** [would_fragment ip_header ip_payload next_hop_mtu] generates an
    ICMP destination unreachable message, with the code set to 4 ("packet
    fragmentation is required but the don't-fragment bit is set").  [ip_header] should
    be the IP header of the packet which will be rejected; [ip_payload] is the
    optional first 8 bytes of the IPv4 payload (generally the first 8 bytes of
    a UDP or TCP header).  Payloads of length > 8 will be truncated. *)
let would_fragment ~buf ~ip_header ?ip_payload ~next_hop_mtu =
  (* type 3, code 4 *)
  let icmp_payload = match ip_payload with
    | Some ip_payload ->
      if (Cstruct.len ip_payload > 8) then begin
        let ip_payload = Cstruct.sub ip_payload 0 8 in
        Cstruct.append ip_header ip_payload
      end else Cstruct.append ip_header ip_payload
    | None -> ip_header
  in
  if (Cstruct.len buf < sizeof_icmpv4 + Cstruct.len icmp_payload) then
    Result.Error "buf is not large enough for icmp header and payload"
  else begin
    let header = Cstruct.create sizeof_icmpv4 in
    set_icmpv4_ty header (ty_to_int Destination_unreachable);
    set_icmpv4_code header (unreachable_reason_to_int Would_fragment);
    set_icmpv4_csum header 0x0000;
    (* this field is unused for icmp destination unreachable *)
    set_icmpv4_id header 0x00;
    set_icmpv4_seq header next_hop_mtu;
    let icmp_packet = Cstruct.append header icmp_payload in
    set_icmpv4_csum header (Tcpip_checksum.ones_complement_list [ icmp_packet ]);
    Result.Ok ()
  end
