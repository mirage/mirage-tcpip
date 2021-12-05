type error = [ `Timeout | `Refused]
type write_error = [ error | Mirage_flow.write_error ]

val pp_error : error Fmt.t
val pp_write_error : write_error Fmt.t

(** Configuration for TCP keep-alives.
    Keep-alive messages are probes sent on an idle connection. If no traffic
    is received after a certain number of probes are sent, then the connection
    is assumed to have been lost. *)
module Keepalive: sig
  type t = {
    after: Duration.t;    (** initial delay before sending probes on an idle
                              connection *)
    interval: Duration.t; (** interval between successive probes *)
    probes: int;          (** total number of probes to send before assuming
                              that, if the connection is still idle it has
                              been lost *)
  }
  (** Configuration for TCP keep-alives *)
end

(** Transmission Control Protocol layer: reliable ordered streaming
    communication. *)
module type S = sig

  type nonrec error = private [> error]
  (** The type for TCP errors. *)

  type nonrec write_error = private [> write_error]
  (** The type for TCP write errors. *)

  type ipaddr
  (** The type for IP address representations. *)

  type flow
  (** A flow represents the state of a single TCP stream that is connected
      to an endpoint. *)

  type t
  (** The type representing the internal state of the TCP layer. *)

  val disconnect: t -> unit Lwt.t
  (** Disconnect from the TCP layer. While this might take some time to
      complete, it can never result in an error. *)

  include Mirage_flow.S with
      type flow   := flow
  and type error  := error
  and type write_error := write_error

  val dst: flow -> ipaddr * int
  (** Get the destination IP address and destination port that a
      flow is currently connected to. *)

  val write_nodelay: flow -> Cstruct.t -> (unit, write_error) result Lwt.t
  (** [write_nodelay flow buffer] writes the contents of [buffer]
      to the flow. The thread blocks until all data has been successfully
      transmitted to the remote endpoint.
      Buffering within the layer is minimized in this mode.
      Note that this API will change in a future revision to be a
      per-flow attribute instead of a separately exposed function. *)

  val writev_nodelay: flow -> Cstruct.t list -> (unit, write_error) result Lwt.t
  (** [writev_nodelay flow buffers] writes the contents of [buffers]
      to the flow. The thread blocks until all data has been successfully
      transmitted to the remote endpoint.
      Buffering within the layer is minimized in this mode.
      Note that this API will change in a future revision to be a
      per-flow attribute instead of a separately exposed function. *)

  val create_connection: ?keepalive:Keepalive.t -> t -> ipaddr * int -> (flow, error) result Lwt.t
  (** [create_connection ~keepalive t (addr,port)] opens a TCP connection
      to the specified endpoint.

      If the optional argument [?keepalive] is provided then TCP keep-alive
      messages will be sent to the server when the connection is idle. If
      no responses are received then eventually the connection will be disconnected:
      [read] will return [Ok `Eof] and write will return [Error `Closed] *)

  val listen : t -> port:int -> ?keepalive:Keepalive.t -> (flow -> unit Lwt.t) -> unit
  (** [listen t ~port ~keepalive callback] listens on [port]. The [callback] is
      executed for each flow that was established. If [keepalive] is provided,
      this configuration will be applied before calling [callback].

      @raise Invalid_argument if [port < 0] or [port > 65535]
 *)

  val unlisten : t -> port:int -> unit
  (** [unlisten t ~port] stops any listener on [port]. *)

  val input: t -> src:ipaddr -> dst:ipaddr -> Cstruct.t -> unit Lwt.t
  (** [input t] returns an input function continuation to be
      passed to the underlying {!IP} layer. *)
end
