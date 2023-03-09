val sizeof_udp : int

val get_src_port : Cstruct.t -> int
val set_src_port : Cstruct.t -> int -> unit

val get_dst_port : Cstruct.t -> int
val set_dst_port : Cstruct.t -> int -> unit

val get_length : Cstruct.t -> int
val set_length : Cstruct.t -> int -> unit

val get_checksum : Cstruct.t -> int
val set_checksum : Cstruct.t -> int -> unit
