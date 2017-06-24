type t = {
  src_port : Cstruct.uint16;
  dst_port : Cstruct.uint16;
}

val pp : Format.formatter -> t -> unit
val equal : t -> t -> bool

module Unmarshal : sig

  type error = string 

(** [of_cstruct buf] attempts to interpret [buf] as a UDP header.  If
    successful, it returns [Ok (header, payload)], although [payload] may be an
    empty Cstruct.t . *)
  val of_cstruct : Cstruct.t -> (t * Cstruct.t, error) Result.result
end
module Marshal : sig

  type error = string

  (** [into_cstruct ~pseudoheader ~payload t buf] attempts to
      assemble a UDP header in [buf] with [t.src_port] and [t.dst_port] set,
      along with the correct length and checksum.
      It does not write [pseudoheader] or [payload] into the buffer,
      but requires them to calculate the correct checksum. *)
  val into_cstruct :
    pseudoheader:Cstruct.t  ->
    payload:Cstruct.t       ->
    t -> Cstruct.t ->
    (unit, error) Result.result

  (** [make_cstruct ~pseudoheader ~payload t] allocates, fills, and and returns a buffer
      representing the UDP header corresponding to [t].  [make_cstruct] will
      allocate 8 bytes for the UDP header.
      [payload] and [pseudoheader] are not directly represented in the output,
      and are required for correct computation of the UDP checksum only.
      The checksum will be properly set to reflect the pseudoheader, header, and payload. *)
  val make_cstruct : pseudoheader:Cstruct.t -> payload:Cstruct.t -> t -> Cstruct.t
end
