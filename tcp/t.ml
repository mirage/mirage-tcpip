module type TIME = sig
  type +'a io
  val sleep: float -> unit io
end

module type LWT_TIME =
  TIME with type 'a io = 'a Lwt.t

module type CLOCK = sig
  val time: unit -> float
end
