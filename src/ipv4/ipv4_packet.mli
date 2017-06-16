type t = {
  src     : Ipaddr.V4.t;
  dst     : Ipaddr.V4.t;
  proto   : Cstruct.uint8;
  ttl     : Cstruct.uint8;
  options : Cstruct.t;
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

  val verify_transport_checksum : proto:([`TCP | `UDP]) -> ipv4_header:t ->
      transport_packet:Cstruct.t -> bool
end

module Marshal : sig
  type error = string

  val protocol_to_int : protocol -> Cstruct.uint16

  val pseudoheader : src:Ipaddr.V4.t -> dst:Ipaddr.V4.t -> proto:([< `TCP | `UDP])
    -> int -> Cstruct.t
    (** [pseudoheader src dst proto len] constructs a pseudoheader, suitable for inclusion in transport-layer checksum calculations, including the information supplied.  [len] should be the total length of the transport-layer header and payload.  *)

(** [into_cstruct ~payload_len t buf] attempts to write a header representing [t] (including
    [t.options]) into [buf] at offset 0.
    If there is insufficient space to represent [t], an error will be returned. *)
  val into_cstruct : payload_len:int -> t -> Cstruct.t -> (unit, error) Result.result

  (** [make_cstruct ~payload_len t] allocates, fills, and returns a buffer
      repesenting the IPV4 header corresponding to [t].
      If [t.options] is non-empty, [t.options] will be
      concatenated onto the result. A variable amount of memory (at least 20 bytes
      for a zero-length options field) will be allocated.
      Note: no space is allocated for the payload. *)
  val make_cstruct : payload_len:int -> t -> Cstruct.t
end
