open Icmpv4_wire

(* second 4 bytes of the message have varying interpretations *)
type subheader =
  | Id_and_seq of Cstruct.uint16 * Cstruct.uint16
  | Next_hop_mtu of Cstruct.uint16
  | Pointer of Cstruct.uint8
  | Address of Ipaddr.V4.t
  | Unused

type t = {
  code : Cstruct.uint8;
  ty : ty;
  csum : Cstruct.uint16;
  subheader : subheader;
}

let pp fmt t =
  let say = Format.fprintf in
  let pp_subheader fmt = function
    | Id_and_seq (id, seq) -> say fmt "subheader: id: %d, sequence %d" id seq
    | Next_hop_mtu mtu -> say fmt "subheader: MTU %d" mtu
    | Pointer pt -> say fmt "subheader: pointer to byte %d" pt
    | Address addr -> say fmt "subheader: ip %a" Ipaddr.V4.pp_hum addr
    | Unused -> ()
  in
  say fmt "ICMP type %s, code %d, subheader [%a]" (Icmpv4_wire.ty_to_string t.ty)
    t.code pp_subheader t.subheader

let equal p q = (p = q)

module Unmarshal = struct

  type error = string

  let subheader_of_cstruct ty buf =
    let open Cstruct.BE in
    match ty with
    | Echo_request | Echo_reply
    | Timestamp_request | Timestamp_reply
    | Information_request | Information_reply ->
      Id_and_seq (get_uint16 buf 0, get_uint16 buf 2)
    | Destination_unreachable -> Next_hop_mtu (get_uint16 buf 2)
    | Time_exceeded
    | Source_quench -> Unused
    | Redirect -> Address (Ipaddr.V4.of_int32 (get_uint32 buf 0))
    | Parameter_problem -> Pointer (Cstruct.get_uint8 buf 0)

  let of_cstruct buf =
    let open Rresult in
    let check_len () =
      if Cstruct.len buf < sizeof_icmpv4 then
        Result.Error "packet too short for ICMPv4 header"
      else Result.Ok () in
    let check_ty () =
      match int_to_ty (get_icmpv4_ty buf) with
      | None -> Result.Error "unrecognized ICMPv4 type"
      | Some ty -> Result.Ok ty
    in
    check_len () >>= check_ty >>= fun ty ->
    let code = get_icmpv4_code buf in
    let csum = get_icmpv4_csum buf in
    let subheader = subheader_of_cstruct ty (Cstruct.shift buf 4) in
    let payload = Cstruct.shift buf sizeof_icmpv4 in
    Result.Ok ({ code; ty; csum; subheader}, payload)
end

module Marshal = struct

  type error = string

  let subheader_to_cstruct ~buf sh =
    let open Cstruct.BE in
    match sh with
    | Id_and_seq (id, seq) -> set_uint16 buf 0 id; set_uint16 buf 2 seq
    | Next_hop_mtu mtu -> set_uint16 buf 0 0; set_uint16 buf 2 mtu
    | Pointer byte -> set_uint32 buf 0 Int32.zero; Cstruct.set_uint8 buf 0 byte;
    | Address addr -> set_uint32 buf 0 (Ipaddr.V4.to_int32 addr)
    | Unused -> set_uint32 buf 0 Int32.zero

  let echo ~buf ~payload ~ty ~id ~seq =
    let min_len = Icmpv4_wire.sizeof_icmpv4 + (Cstruct.len payload) in
    if Cstruct.len buf < min_len then
      Result.Error "Not enough space for ICMP header and payload"
    else begin
      let buf = Cstruct.set_len buf min_len in
      set_icmpv4_ty buf (ty_to_int ty);
      set_icmpv4_code buf 0x00;
      set_icmpv4_csum buf 0x0000;
      set_icmpv4_seq buf seq;
      set_icmpv4_id buf id;
      let packets = [buf ; payload] in
      set_icmpv4_csum buf (Tcpip_checksum.ones_complement_list packets);
      Result.Ok ()
    end

  let echo_request ~buf ~payload ~id ~seq =
    echo ~buf ~payload ~ty:Echo_request ~id ~seq

  let echo_reply ~buf ~payload ~id ~seq =
    echo ~buf ~payload ~ty:Echo_reply ~id ~seq

  (** [would_fragment ip_header ip_payload next_hop_mtu] generates an
      ICMP destination unreachable message, with the code set to 4 ("packet
      fragmentation is required but the don't-fragment bit is set").  [ip_header] should
      be the IP header of the packet which will be rejected; [ip_payload] is the
      optional first 8 bytes of the IPv4 payload (generally the first 8 bytes of
      a UDP or TCP header).  Payloads of length > 8 will be truncated. *)
  let would_fragment ~buf ~ip_header ~ip_payload ~next_hop_mtu =
    (* type 3, code 4 *)
    let icmp_payload = match Cstruct.len ip_payload with
      | 0 -> ip_header
      | n when n <= 8 ->
        Cstruct.append ip_header ip_payload
      | n ->
        Cstruct.append ip_header @@ Cstruct.sub ip_payload 0 8
    in
    if (Cstruct.len buf < sizeof_icmpv4 + Cstruct.len icmp_payload) then
      Result.Error "buf is not large enough for icmp header and payload"
    else begin
      set_icmpv4_ty buf (ty_to_int Destination_unreachable);
      set_icmpv4_code buf (unreachable_reason_to_int Would_fragment);
      set_icmpv4_csum buf 0x0000;
      (* this field is unused for icmp destination unreachable *)
      set_icmpv4_id buf 0x00;
      set_icmpv4_seq buf next_hop_mtu;
      let icmp_packet = Cstruct.append buf icmp_payload in
      set_icmpv4_csum buf (Tcpip_checksum.ones_complement_list [ icmp_packet ]);
      Result.Ok ()
    end

  let make_cstruct t ~payload =
    let buf = Cstruct.create Icmpv4_wire.sizeof_icmpv4 in
    Cstruct.memset buf 0x00; (* can be removed once cstructs are zero'd by default *)
    set_icmpv4_ty buf (ty_to_int t.ty);
    set_icmpv4_code buf t.code;
    set_icmpv4_csum buf 0x0000;
    subheader_to_cstruct ~buf:(Cstruct.shift buf 4) t.subheader;
    set_icmpv4_csum buf (Tcpip_checksum.ones_complement_list [ buf; payload ]);
    buf
end
