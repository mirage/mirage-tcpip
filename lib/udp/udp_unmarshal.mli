type t = {
  src_port : Cstruct.uint16;
  dst_port : Cstruct.uint16;
  payload  : Cstruct.t list
}

val of_cstruct : Cstruct.t -> (t, string) Result.result
