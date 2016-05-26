val to_cstruct :
  udp_buf:Cstruct.t       ->
  src_port:Cstruct.uint16 ->
  dst_port:Cstruct.uint16 ->
  pseudoheader:Cstruct.t  ->
  payload:Cstruct.t list  ->
  (unit, string) Result.result
