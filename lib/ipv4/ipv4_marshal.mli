type protocol = [
  | `ICMP
  | `TCP
  | `UDP ]

type error = string

val protocol_to_int : protocol -> Cstruct.uint16

val pseudoheader : src:Ipaddr.V4.t -> dst:Ipaddr.V4.t -> proto:([< `TCP | `UDP])
  -> int -> Cstruct.t

val to_cstruct : buf:Cstruct.t -> src:Ipaddr.V4.t -> dst:Ipaddr.V4.t ->
  proto:protocol -> ttl:Cstruct.uint16 -> (unit, error) Result.result

(** [make_cstruct t] allocates, fills, and returns  a buffer repesenting the IPV4 header
    corresponding to [t].  If [t.options] is non-empty, [t.options] will be
    concatenated onto the result. A variable amount of memory (at least 20 bytes
    for a zero-length options field) will be allocated, but [t.payload] is not
    represented in the output. *)
val make_cstruct : Ipv4_unmarshal.t -> Cstruct.t
