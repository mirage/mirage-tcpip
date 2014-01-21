module Make(Time : T.LWT_TIME) : sig
  val fin_wait_2_time : float
  val time_wait_time : float
  val finwait2timer : State.t -> int -> float -> unit Lwt.t
  val timewait : State.t -> float -> unit Lwt.t
  val tick : State.t -> State.action -> unit
end
