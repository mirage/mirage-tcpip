module type S = sig
  type error
  val pp_error: error Fmt.t
  type ipaddr
  type t
  val disconnect : t -> unit Lwt.t
  type callback = src:ipaddr -> dst:ipaddr -> src_port:int -> Cstruct.t -> unit Lwt.t
  val listen : t -> port:int -> callback -> unit
  val unlisten : t -> port:int -> unit
  val input: t -> src:ipaddr -> dst:ipaddr -> Cstruct.t -> unit Lwt.t
  val write: ?src:ipaddr -> ?src_port:int -> ?ttl:int -> dst:ipaddr -> dst_port:int -> t -> Cstruct.t ->
    (unit, error) result Lwt.t
end
