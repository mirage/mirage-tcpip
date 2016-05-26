type t = {
  source : Macaddr.t;
  destination : Macaddr.t;
  ethertype : Ethif_wire.ethertype;
  payload : Cstruct.t;
}

type error = string

val of_cstruct : Cstruct.t -> (t, error) Result.result
