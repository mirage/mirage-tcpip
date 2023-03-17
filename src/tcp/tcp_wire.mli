val sizeof_tcp : int

val get_src_port : Cstruct.t -> int
val set_src_port : Cstruct.t -> int -> unit

val get_dst_port : Cstruct.t -> int
val set_dst_port : Cstruct.t -> int -> unit

val get_sequence : Cstruct.t -> int32
val set_sequence : Cstruct.t -> int32 -> unit

val get_ack_number : Cstruct.t -> int32
val set_ack_number : Cstruct.t -> int32 -> unit

val get_flags : Cstruct.t -> int
val set_flags : Cstruct.t -> int -> unit

val get_window : Cstruct.t -> int
val set_window : Cstruct.t -> int -> unit

val get_checksum : Cstruct.t -> int
val set_checksum : Cstruct.t -> int -> unit

val get_urg_ptr : Cstruct.t -> int
val set_urg_ptr : Cstruct.t -> int -> unit

val get_data_offset : Cstruct.t -> int
val set_data_offset : Cstruct.t -> int -> unit

val get_fin : Cstruct.t -> bool
val get_syn : Cstruct.t -> bool
val get_rst : Cstruct.t -> bool
val get_psh : Cstruct.t -> bool
val get_ack : Cstruct.t -> bool
val get_urg : Cstruct.t -> bool

val set_fin : Cstruct.t -> unit
val set_syn : Cstruct.t -> unit
val set_rst : Cstruct.t -> unit
val set_psh : Cstruct.t -> unit
val set_ack : Cstruct.t -> unit
val set_urg : Cstruct.t -> unit
