val sizeof_ipv4 : int

val get_hlen_version : Cstruct.t -> int
val set_hlen_version : Cstruct.t -> int -> unit

val get_len : Cstruct.t -> int
val set_len : Cstruct.t -> int -> unit

val get_id : Cstruct.t -> int
val set_id : Cstruct.t -> int -> unit

val get_off : Cstruct.t -> int
val set_off : Cstruct.t -> int -> unit

val get_ttl : Cstruct.t -> int
val set_ttl : Cstruct.t -> int -> unit

val get_proto : Cstruct.t -> int
val set_proto : Cstruct.t -> int -> unit

val get_checksum : Cstruct.t -> int
val set_checksum : Cstruct.t -> int -> unit

val get_src : Cstruct.t -> Ipaddr.V4.t
val set_src : Cstruct.t -> Ipaddr.V4.t -> unit

val get_dst : Cstruct.t -> Ipaddr.V4.t
val set_dst : Cstruct.t -> Ipaddr.V4.t -> unit
