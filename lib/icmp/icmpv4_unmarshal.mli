type subheader =
  | Id_and_seq of Cstruct.uint16 * Cstruct.uint16
  | Next_hop_mtu of Cstruct.uint16
  | Pointer of Cstruct.uint8
  | Address of Ipaddr.V4.t
  | Unused

type t = {
  code : Cstruct.uint8;
  ty : Icmpv4_wire.ty;
  csum : Cstruct.uint16;
  subheader : subheader;
  payload : Cstruct.t;
}

type error = string

val subheader_of_cstruct : Icmpv4_wire.ty -> Cstruct.t -> subheader

val of_cstruct : Cstruct.t -> (t, error) Result.result
