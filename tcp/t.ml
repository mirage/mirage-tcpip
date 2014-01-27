(* TODO purge *)
module type TIME = sig
  type +'a io
  val sleep: float -> unit io
end

module type LWT_TIME = sig
  val sleep: float -> unit Lwt.t
end

module type CLOCK = sig
  val time: unit -> float
end

module type RANDOM = sig
  val self_init : unit -> unit
  val int : int -> int
end
