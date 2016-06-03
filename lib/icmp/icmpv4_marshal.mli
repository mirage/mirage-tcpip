type error = string

val echo_request : buf:Cstruct.t -> payload:Cstruct.t ->
  id:Cstruct.uint8 -> seq:Cstruct.uint8 -> (unit, error) Result.result

val echo_reply : buf:Cstruct.t -> payload:Cstruct.t ->
  id:Cstruct.uint8 -> seq:Cstruct.uint8 -> (unit, error) Result.result

val would_fragment : buf:Cstruct.t -> ip_header:Cstruct.t ->
  ip_payload:Cstruct.t -> next_hop_mtu:Cstruct.uint16 -> (unit, error) Result.result

(** [make_cstruct t] allocates, fills, and returns a Cstruct.t with the header
    information from [t].  The payload is not copied.  [make_cstruct] allocates
    8 bytes for the ICMPv4 header. *)
val make_cstruct : Icmpv4_unmarshal.t -> Cstruct.t
