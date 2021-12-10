type error = [ `Timeout | `Refused]
type write_error = [ error | Mirage_flow.write_error]

let pp_error ppf = function
  | `Timeout -> Fmt.string ppf "connection attempt timed out"
  | `Refused -> Fmt.string ppf "connection attempt was refused"

let pp_write_error ppf = function
  | #Mirage_flow.write_error as e -> Mirage_flow.pp_write_error ppf e
  | #error as e                   -> pp_error ppf e

module Keepalive = struct
  type t = {
    after: Duration.t;
    interval: Duration.t;
    probes: int;
  }
end

module type S = sig
  type nonrec error = private [> error]
  type nonrec write_error = private [> write_error]
  type ipaddr
  type flow
  type t
  val disconnect : t -> unit Lwt.t
  include Mirage_flow.S with
      type flow   := flow
  and type error  := error
  and type write_error := write_error

  val dst: flow -> ipaddr * int
  val write_nodelay: flow -> Cstruct.t -> (unit, write_error) result Lwt.t
  val writev_nodelay: flow -> Cstruct.t list -> (unit, write_error) result Lwt.t
  val create_connection: ?keepalive:Keepalive.t -> t -> ipaddr * int -> (flow, error) result Lwt.t
  val listen : t -> port:int -> ?keepalive:Keepalive.t -> (flow -> unit Lwt.t) -> unit
  val unlisten : t -> port:int -> unit
  val input: t -> src:ipaddr -> dst:ipaddr -> Cstruct.t -> unit Lwt.t
end
