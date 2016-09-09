type t = {
  src           : Ipaddr.V4.t;
  dst           : Ipaddr.V4.t;
  proto         : Cstruct.uint8;
  ttl           : Cstruct.uint8;
  id            : Cstruct.uint16;
  more_frags    : bool;
  frag_offset   : Cstruct.uint16;
  options       : Cstruct.t;
}

val pp : Format.formatter -> t -> unit
val equal : t -> t -> bool

type protocol = [
  | `ICMP
  | `TCP
  | `UDP ]

module Unmarshal : sig
  type error = string

  val int_to_protocol : int -> protocol option

  val of_cstruct : Cstruct.t -> (t * Cstruct.t, error) Result.result
end

module Marshal : sig
  type error = string

  val protocol_to_int : protocol -> Cstruct.uint16

  val pseudoheader : src:Ipaddr.V4.t -> dst:Ipaddr.V4.t -> proto:([< `TCP | `UDP])
    -> int -> Cstruct.t
    (** [pseudoheader src dst proto len] constructs a pseudoheader, suitable for inclusion in transport-layer checksum calculations, including the information supplied.  [len] should be the total length of the transport-layer header and payload.  *)

(** [into_cstruct ~payload t buf] attempts to write a header representing [t] (including
    [t.options], but not [payload]  into [buf]
    at offset 0.  If there is insufficient space to represent [t], an error will
    be returned. *)
  val into_cstruct : payload:Cstruct.t -> t -> Cstruct.t -> (unit, error) Result.result

  (** [make_cstruct ~payload t] allocates, fills, and returns a buffer
      repesenting the IPV4 header corresponding to [t].
      If [t.options] is non-empty, [t.options] will be
      concatenated onto the result. A variable amount of memory (at least 20 bytes
      for a zero-length options field) will be allocated, but [t.payload] is not
      represented in the output. *)
  val make_cstruct : payload:Cstruct.t -> t -> Cstruct.t
end
