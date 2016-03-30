type t = {
  src_port : Cstruct.uint16;
  dst_port : Cstruct.uint16;
  payload  : Cstruct.t
}

val parse_udp_header : Cstruct.t -> (t, string) Result.result
