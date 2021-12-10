type error = [
  | `No_route of string (** can't send a message to that destination *)
  | `Would_fragment
]
let pp_error ppf = function
  | `No_route s -> Fmt.pf ppf "no route to destination: %s" s
  | `Would_fragment -> Fmt.string ppf "would fragment"

type proto = [ `TCP | `UDP | `ICMP ]
let pp_proto ppf = function
  | `TCP -> Fmt.string ppf "TCP"
  | `UDP -> Fmt.string ppf "UDP"
  | `ICMP -> Fmt.string ppf "ICMP"

module type S = sig
  type nonrec error = private [> error]
  val pp_error: error Fmt.t
  type ipaddr
  val pp_ipaddr : ipaddr Fmt.t
  type t
  val disconnect : t -> unit Lwt.t
  type callback = src:ipaddr -> dst:ipaddr -> Cstruct.t -> unit Lwt.t
  val input:
    t ->
    tcp:callback -> udp:callback -> default:(proto:int -> callback) ->
    Cstruct.t -> unit Lwt.t
  val write: t -> ?fragment:bool -> ?ttl:int ->
    ?src:ipaddr -> ipaddr -> proto -> ?size:int -> (Cstruct.t -> int) ->
    Cstruct.t list -> (unit, error) result Lwt.t
  val pseudoheader : t -> ?src:ipaddr -> ipaddr -> proto -> int -> Cstruct.t
  val src: t -> dst:ipaddr -> ipaddr
  val get_ip: t -> ipaddr list
  val mtu: t -> dst:ipaddr -> int
end
