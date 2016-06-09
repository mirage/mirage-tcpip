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
}

val pp : Format.formatter -> t -> unit
val equal : t -> t -> bool

module Unmarshal : sig
  type error = string

  val subheader_of_cstruct : Icmpv4_wire.ty -> Cstruct.t -> subheader

  val of_cstruct : Cstruct.t -> (t * Cstruct.t, error) Result.result
end
module Marshal : sig
  type error = string

  val echo_request : buf:Cstruct.t -> payload:Cstruct.t ->
    id:Cstruct.uint8 -> seq:Cstruct.uint8 -> (unit, error) Result.result

  val echo_reply : buf:Cstruct.t -> payload:Cstruct.t ->
    id:Cstruct.uint8 -> seq:Cstruct.uint8 -> (unit, error) Result.result

  val would_fragment : buf:Cstruct.t -> ip_header:Cstruct.t ->
    ip_payload:Cstruct.t -> next_hop_mtu:Cstruct.uint16 -> (unit, error) Result.result

  (** [make_cstruct t ~payload] allocates, fills, and returns a Cstruct.t with the header
      information from [t].  The payload is used to calculate the ICMPv4 header
      checksum, but is not included in the generated buffer.  [make_cstruct] allocates
      8 bytes for the ICMPv4 header. *)
  val make_cstruct : t -> payload:Cstruct.t -> Cstruct.t
end
