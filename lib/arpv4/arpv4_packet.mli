type t = {
  op: Arpv4_wire.op; (* Arpv4 operation -- one of "Request" or "Reply" *)
  sha: Macaddr.t;    (* source host address, in this case the sending Macaddr *)
  spa: Ipaddr.V4.t;  (* source protocol address, in this case the sending Ipaddr.V4 *)
  tha: Macaddr.t;    (* target host address - can be broadcast *)
  tpa: Ipaddr.V4.t;  (* target protocol address - can also be broadcast *)
}

module Unmarshal : sig
  type error =
    | Too_short
    | Unusable
    | Unknown_code of Cstruct.uint16
    | Bad_mac of string list

  val string_of_error : error -> string

  val pp_error : Format.formatter -> error -> unit

  val of_cstruct : Cstruct.t -> (t, error) Result.result
end
module Marshal : sig
  type error = string

  val to_cstruct : buf:Cstruct.t -> op:Arpv4_wire.op ->
    src_ip:Ipaddr.V4.t -> dst_ip:Ipaddr.V4.t ->
    src_mac:Macaddr.t -> dst_mac:Macaddr.t ->
    (unit, error) Result.result

  (** given a [t], construct and return an ARP header representing
      [t.op], and the source/destination ip/mac in [t].  [make_cstruct] will allocate
      a new 24 bytes for the ARP header it returns. *)
  val make_cstruct : t -> Cstruct.t
end
