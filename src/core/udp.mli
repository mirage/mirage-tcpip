(** User datagram protocol layer: connectionless message-oriented
    communication. *)
module type S = sig

  type error (* entirely abstract since we expose none in a Udp module *)
  (** The type for UDP errors. *)

  val pp_error: error Fmt.t
  (** [pp] is the pretty-printer for errors. *)

  type ipaddr
  (** The type for an IP address representations. *)

  type t
  (** The type representing the internal state of the UDP layer. *)

  val disconnect: t -> unit Lwt.t
  (** Disconnect from the UDP layer. While this might take some time to
      complete, it can never result in an error. *)

  type callback = src:ipaddr -> dst:ipaddr -> src_port:int -> Cstruct.t -> unit Lwt.t
  (** The type for callback functions that adds the UDP metadata for
      [src] and [dst] IP addresses, the [src_port] of the
      connection and the [buffer] payload of the datagram. *)

  val listen : t -> port:int -> callback -> unit
  (** [listen t ~port callback] executes [callback] for each packet received
      on [port].

      @raise Invalid_argument if [port < 0] or [port > 65535] *)

  val unlisten : t -> port:int -> unit
  (** [unlisten t ~port] stops any listeners on [port]. *)

  val input: t -> src:ipaddr -> dst:ipaddr -> Cstruct.t -> unit Lwt.t
  (** [input t] demultiplexes incoming datagrams based on
      their destination port. *)

  val write: ?src:ipaddr -> ?src_port:int -> ?ttl:int -> dst:ipaddr ->
    dst_port:int -> t -> Cstruct.t -> (unit, error) result Lwt.t
  (** [write ~src ~src_port ~ttl ~dst ~dst_port udp data] is a task
      that writes [data] from an optional [src] and [src_port] to a [dst]
      and [dst_port] IP address pair. An optional time-to-live ([ttl]) is passed
      through to the IP layer. *)

end
