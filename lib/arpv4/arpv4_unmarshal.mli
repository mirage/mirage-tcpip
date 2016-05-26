type error =
  | Too_short
  | Unusable
  | Unknown_code of Cstruct.uint16
  | Bad_mac of string list

type t = {
  op: Arpv4_wire.op; (* Arpv4 operation -- one of "Request" or "Reply" *)
  sha: Macaddr.t;    (* source host address, in this case the sending Macaddr *)
  spa: Ipaddr.V4.t;  (* source protocol address, in this case the sending Ipaddr.V4 *)
  tha: Macaddr.t;    (* target host address - can be broadcast *)
  tpa: Ipaddr.V4.t;  (* target protocol address - can also be broadcast *)
}

val string_of_error : error -> string

val pp_error : Format.formatter -> error -> unit

val of_cstruct : Cstruct.t -> (t, error) Result.result
