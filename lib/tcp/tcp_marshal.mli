type error = string

(** construct a packet in the given buffer with the information provided.
    Returns either the number of bytes written into the buffer or an error. *)
val to_cstruct : buf:Cstruct.t -> src_port:Cstruct.uint16 ->
  dst_port:Cstruct.uint16 -> pseudoheader:Cstruct.t -> options:Options.t list ->
  syn:bool -> fin:bool -> rst:bool -> psh:bool -> window:int ->
  payload:Cstruct.t list -> seq:Sequence.t -> rx_ack:Sequence.t option ->
  (int, error) Result.result
