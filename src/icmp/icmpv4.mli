(** {2 ICMP layer} *)

(** Internet Control Message Protocol: error messages and operational
    information. *)
module type S = sig

  type t
  (** The type representing the internal state of the ICMP layer. *)

  val disconnect: t -> unit Lwt.t
  (** Disconnect from the ICMP layer. While this might take some time to
      complete, it can never result in an error. *)

  type ipaddr = Ipaddr.V4.t
  (** The type for IP addresses. *)

  type error (* entirely abstract since we expose none in an Icmp module *)
  (** The type for ICMP errors. *)

  val pp_error: error Fmt.t
  (** [pp_error] is the pretty-printer for errors. *)

  val input : t -> src:ipaddr -> dst:ipaddr -> Cstruct.t -> unit Lwt.t
  (** [input t src dst buffer] reacts to the ICMP message in
      [buffer]. *)

  val write : t -> ?src:ipaddr -> dst:ipaddr -> ?ttl:int -> Cstruct.t -> (unit, error) result Lwt.t
  (** [write t ~src ~dst ~ttl buffer] sends the ICMP message in [buffer] to [dst]
      over IP. Passes the time-to-live ([ttl]) to the IP stack if given. *)
end

module Make (I : Tcpip.Ip.S with type ipaddr = Ipaddr.V4.t) : sig
  include S

  val connect : I.t -> t Lwt.t
end
