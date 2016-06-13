type subheader =
  | Id_and_seq of Cstruct.uint16 * Cstruct.uint16
  | Next_hop_mtu of Cstruct.uint16
  | Pointer of Cstruct.uint8
  | Address of Ipaddr.V4.t
  | Unused

type t = {
  code : Cstruct.uint8;
  ty : Icmpv4_wire.ty;
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

  (** [into_cstruct t buf ~payload] generates an ICMPv4 header from [t] and
      writes it into [buf] at offset 0. [payload] is used to calculate the ICMPv4 header
      checksum, but is not included in the generated buffer. [into_cstruct] may
      fail if the buffer is of insufficient size. *)
  val into_cstruct : t -> Cstruct.t -> payload:Cstruct.t -> (unit, error) Result.result

  (** [make_cstruct t ~payload] allocates, fills, and returns a Cstruct.t with the header
      information from [t].  The payload is used to calculate the ICMPv4 header
      checksum, but is not included in the generated buffer.  [make_cstruct] allocates
      8 bytes for the ICMPv4 header. *)
  val make_cstruct : t -> payload:Cstruct.t -> Cstruct.t
end
