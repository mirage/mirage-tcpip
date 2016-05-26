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
  payload : Cstruct.t option;
}

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
  let payload =
    if Cstruct.len buf > sizeof_icmpv4
    then Some (Cstruct.shift buf sizeof_icmpv4)
    else None
  in
  Result.Ok { code; ty; csum; subheader; payload }
