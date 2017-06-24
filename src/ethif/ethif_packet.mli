type t = {
  source : Macaddr.t;
  destination : Macaddr.t;
  ethertype : Ethif_wire.ethertype;
}

type error = string

val pp : Format.formatter -> t -> unit
val equal : t -> t -> bool

module Unmarshal : sig
  val of_cstruct : Cstruct.t -> ((t * Cstruct.t), error) Result.result
end
module Marshal : sig
  (** [into_cstruct t buf] writes a 14-byte ethernet header representing
      [t.ethertype], [t.src_mac], and [t.dst_mac] to [buf] at offset 0.
      Return Result.Ok () on success and Result.Error error on failure.
      Currently, the only possibility for failure
      is a [buf] too small to contain the header; to avoid this, provide a
      buffer of size at least 14. *)
  val into_cstruct : t -> Cstruct.t -> (unit, error) Result.result

  (** given a [t], construct and return an Ethernet header representing
      [t.ethertype], [t.source], and [t.destination].  [make_cstruct] will allocate
      a new 14 bytes for the Ethernet header it returns. *)
  val make_cstruct : t -> Cstruct.t
end
