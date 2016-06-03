type t = {
  source : Macaddr.t;
  destination : Macaddr.t;
  ethertype : Ethif_wire.ethertype;
}

module Unmarshal : sig
  type error = string

  val of_cstruct : Cstruct.t -> ((t * Cstruct.t), error) Result.result
end
module Marshal : sig
  type error = string

  (** write a 14-byte ethernet header representing [ethertype], [src_mac], and
      [dst_mac] to [buf] at offset 0. Return Result.Ok () on success and
      Result.Error error on failure.  Currently, the only possibility for failure
      is a [buf] too small to contain the header. *)
  val to_cstruct : buf:Cstruct.t -> ethertype:Ethif_wire.ethertype ->
    src_mac:Macaddr.t -> dst_mac:Macaddr.t -> (unit, error) Result.result

  (** given a [t], construct and return an Ethernet header representing
      [t.ethertype], [t.source], and [t.destination].  [make_cstruct] will allocate
      a new 14 bytes for the Ethernet header it returns. *)
  val make_cstruct : t -> Cstruct.t
end
