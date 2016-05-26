type error = string

type t = {
  urg : bool;
  ack : bool;
  psh : bool;
  rst : bool;
  syn : bool;
  fin : bool;
  window : Cstruct.uint16;
  options : Options.t list;
  data : Cstruct.t;
  sequence : Sequence.t;
  ack_number : Sequence.t;
  source_port : Cstruct.uint16;
  dest_port : Cstruct.uint16;
}

val of_cstruct : Cstruct.t -> (t, error) Result.result
