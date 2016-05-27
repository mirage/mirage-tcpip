type error = string

(** construct a packet in the given buffer with the information provided.
    Returns either the number of bytes written into the buffer or an error. *)
val to_cstruct : buf:Cstruct.t -> src_port:Cstruct.uint16 ->
  dst_port:Cstruct.uint16 -> pseudoheader:Cstruct.t -> options:Options.t list ->
  syn:bool -> fin:bool -> rst:bool -> psh:bool -> window:int ->
  payload:Cstruct.t list -> seq:Sequence.t -> rx_ack:Sequence.t option ->
  (int, error) Result.result

(** [make_cstruct pseudoheader t] allocates, fills, and and returns a buffer
    representing the TCP header corresponding to [t].  If [t.options] is
    non-empty, [t.options] will be concatenated onto the result.  A variable
    amount of memory (at least 20 bytes, and at most 60) will be allocated, but
    [t.payload] is not represented in the output.  The checksum will be properly
    set to reflect the pseudoheader, header, options, and payload. *)
val make_cstruct : pseudoheader:Cstruct.t -> Tcp_unmarshal.t -> Cstruct.t
