
(* second 4 bytes of the message have varying interpretations *)
type subheader =
  | Id_and_seq of Cstruct.uint16 * Cstruct.uint16
  | Pointer of Cstruct.uint8
  | Address of Ipaddr.V4.t
  | Unused

type t = {
  code : Cstruct.uint8;
  ty : Cstruct.uint8;
  csum : Cstruct.uint16;
  subheader : subheader;
  payload : Cstruct.t option;
}

let subheader_of_cstruct ty buf =
  let open Cstruct.BE in
  match ty with
  | 0 | 8 | 13 | 14 | 15 | 16 -> Id_and_seq (get_uint16 buf 0, get_uint16 buf 2)
  | 3 | 11 | 4 -> Unused
  | 5 -> Address (Ipaddr.V4.of_int32 (get_uint32 buf 0))
  | 12 -> Pointer (Cstruct.get_uint8 buf 0)
  | _ -> Unused

let input buf =
  if Cstruct.len buf < Icmpv4_wire.sizeof_icmpv4 then
    Result.Error "packet too short for ICMPv4 header"
  else begin
    let open Icmpv4_wire in
    let ty = get_icmpv4_ty buf in
    let code = get_icmpv4_code buf in
    let csum = get_icmpv4_csum buf in
    let subheader = subheader_of_cstruct ty (Cstruct.shift buf 4) in
    let payload =
      if Cstruct.len buf > sizeof_icmpv4
      then Some (Cstruct.shift buf sizeof_icmpv4)
      else None
    in
    Result.Ok { code; ty; csum; subheader; payload }
  end
