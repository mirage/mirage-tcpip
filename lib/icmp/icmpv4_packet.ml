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

let subheader_eq = function
  | Unused, Unused -> true
  | Id_and_seq (a, b), Id_and_seq (p, q) -> a = p && b = q
  | Next_hop_mtu a, Next_hop_mtu b-> a = b
  | Pointer a, Pointer b -> a = b
  | Address a, Address b -> Ipaddr.V4.compare a b = 0
  | _ -> false

let equal {code; ty; subheader} q =
  code = q.code &&
  ty = q.ty &&
  subheader_eq (subheader, q.subheader)


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
    (* TODO: check checksum as well, and return an error if it's invalid *)
    check_len () >>= check_ty >>= fun ty ->
    let code = get_icmpv4_code buf in
    let subheader = subheader_of_cstruct ty (Cstruct.shift buf 4) in
    let payload = Cstruct.shift buf sizeof_icmpv4 in
    Result.Ok ({ code; ty; subheader}, payload)
end

module Marshal = struct

  type error = string

  let subheader_into_cstruct ~buf sh =
    let open Cstruct.BE in
    match sh with
    | Id_and_seq (id, seq) -> set_uint16 buf 0 id; set_uint16 buf 2 seq
    | Next_hop_mtu mtu -> set_uint16 buf 0 0; set_uint16 buf 2 mtu
    | Pointer byte -> set_uint32 buf 0 Int32.zero; Cstruct.set_uint8 buf 0 byte;
    | Address addr -> set_uint32 buf 0 (Ipaddr.V4.to_int32 addr)
    | Unused -> set_uint32 buf 0 Int32.zero
  
  let unsafe_fill {ty; code; subheader} buf ~payload =
    set_icmpv4_ty buf (ty_to_int ty);
    set_icmpv4_code buf code;
    set_icmpv4_csum buf 0x0000;
    subheader_into_cstruct ~buf:(Cstruct.shift buf 4) subheader;
    let packets = [buf ; payload] in
    set_icmpv4_csum buf (Tcpip_checksum.ones_complement_list packets)

  let check_len buf =
    if Cstruct.len buf < Icmpv4_wire.sizeof_icmpv4 then
      Result.Error "Not enough space for ICMP header"
    else Result.Ok ()

  let into_cstruct t buf ~payload =
    let open Rresult in
    check_len buf >>= fun () ->
    unsafe_fill t buf ~payload;
    Result.Ok ()

  let make_cstruct t ~payload =
    let buf = Cstruct.create Icmpv4_wire.sizeof_icmpv4 in
    Cstruct.memset buf 0x00; (* can be removed once cstructs are zero'd by default *)
    unsafe_fill t buf ~payload;
    buf
end
