type error = string

type t = {
  src     : Ipaddr.V4.t;
  dst     : Ipaddr.V4.t;
  proto   : Cstruct.uint8;
  ttl     : Cstruct.uint8;
  options : Cstruct.t;
  payload : Cstruct.t;
}

val int_to_protocol : int -> [> `ICMP | `TCP | `UDP ] option

val of_cstruct : Cstruct.t -> (t, error) Result.result
