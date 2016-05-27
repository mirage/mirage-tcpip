val to_cstruct :
  udp_buf:Cstruct.t       ->
  src_port:Cstruct.uint16 ->
  dst_port:Cstruct.uint16 ->
  pseudoheader:Cstruct.t  ->
  payload:Cstruct.t list  ->
  (unit, string) Result.result

(** [make_cstruct pseudoheader t] allocates, fills, and and returns a buffer
    representing the UDP header corresponding to [t].  [make_cstruct] will
    allocate 8 bytes for the UDP header.
    [t.payload] is not represented in the output.  The checksum will be properly
    set to reflect the pseudoheader, header, and payload. *)
val make_cstruct : pseudoheader:Cstruct.t -> Udp_unmarshal.t -> Cstruct.t
