module type V4 = sig

  type t
  (** The type representing the internal state of the IPv4 stack. *)

  val disconnect: t -> unit Lwt.t
  (** Disconnect from the IPv4 stack. While this might take some time to
      complete, it can never result in an error. *)

  module UDPV4: Udp.S with type ipaddr = Ipaddr.V4.t

  module TCPV4: Tcp.S with type ipaddr = Ipaddr.V4.t

  module IPV4: Ip.S with type ipaddr = Ipaddr.V4.t

  val udpv4: t -> UDPV4.t
  (** [udpv4 t] obtains a descriptor for use with the [UDPV4] module,
      usually to transmit traffic. *)

  val tcpv4: t -> TCPV4.t
  (** [tcpv4 t] obtains a descriptor for use with the [TCPV4] module,
      usually to initiate outgoing connections. *)

  val ipv4: t -> IPV4.t
  (** [ipv4 t] obtains a descriptor for use with the [IPV4] module,
      which can handle raw IPv4 frames, or manipulate IP address
      configuration on the stack interface. *)

  val listen_udpv4: t -> port:int -> UDPV4.callback -> unit
  [@@ocaml.deprecated "use UDPV4.listen instead (since mirage-protocols 6.0.0)."]
  (** [listen_udpv4 t ~port cb] registers the [cb] callback on the
      UDPv4 [port] and immediately return.  If [port] is invalid (not
      between 0 and 65535 inclusive), it raises [Invalid_argument].
      Multiple bindings to the same port will overwrite previous
      bindings, so callbacks will not chain if ports clash. *)

  val listen_tcpv4: ?keepalive:Tcp.Keepalive.t
    -> t -> port:int -> (TCPV4.flow -> unit Lwt.t) -> unit
  [@@ocaml.deprecated "use TCPV4.listen instead (since mirage-protocols 6.0.0)."]
  (** [listen_tcpv4 ~keepalive t ~port cb] registers the [cb] callback
      on the TCPv4 [port] and immediately return.  If [port] is invalid (not
      between 0 and 65535 inclusive), it raises [Invalid_argument].
      Multiple bindings to the same port will overwrite previous
      bindings, so callbacks will not chain if ports clash.
      If [~keepalive] is provided then these keepalive settings will be
      applied to the accepted connections before the callback is called. *)

  val listen: t -> unit Lwt.t
  (** [listen t] requests that the stack listen for traffic on the
      network interface associated with the stack, and demultiplex
      traffic to the appropriate callbacks. *)
end

module type V6 = sig
  type t
  (** The type representing the internal state of the IPv6 stack. *)

  val disconnect: t -> unit Lwt.t
  (** Disconnect from the IPv6 stack. While this might take some time to
      complete, it can never result in an error. *)

  module UDP: Udp.S with type ipaddr = Ipaddr.V6.t

  module TCP: Tcp.S with type ipaddr = Ipaddr.V6.t

  module IP: Ip.S with type ipaddr = Ipaddr.V6.t

  val udp: t -> UDP.t
  (** [udp t] obtains a descriptor for use with the [UDPV6] module,
      usually to transmit traffic. *)

  val tcp: t -> TCP.t
  (** [tcp t] obtains a descriptor for use with the [TCPV6] module,
      usually to initiate outgoing connections. *)

  val ip: t -> IP.t
  (** [ip t] obtains a descriptor for use with the [IPV6] module,
      which can handle raw IPv6 frames, or manipulate IP address
      configuration on the stack interface. *)

  val listen_udp: t -> port:int -> UDP.callback -> unit
  [@@ocaml.deprecated "use UDP.listen instead (since mirage-protocols 6.0.0)."]
  (** [listen_udp t ~port cb] registers the [cb] callback on the
      UDPv6 [port] and immediately return.  If [port] is invalid (not
      between 0 and 65535 inclusive), it raises [Invalid_argument].
      Multiple bindings to the same port will overwrite previous
      bindings, so callbacks will not chain if ports clash. *)

  val listen_tcp: ?keepalive:Tcp.Keepalive.t
    -> t -> port:int -> (TCP.flow -> unit Lwt.t) -> unit
  [@@ocaml.deprecated "use TCP.listen instead (since mirage-protocols 6.0.0)."]
  (** [listen_tcp ~keepalive t ~port cb] registers the [cb] callback
      on the TCPv6 [port] and immediately return.  If [port] is invalid (not
      between 0 and 65535 inclusive), it raises [Invalid_argument].
      Multiple bindings to the same port will overwrite previous
      bindings, so callbacks will not chain if ports clash.
      If [~keepalive] is provided then these keepalive settings will be
      applied to the accepted connections before the callback is called. *)

  val listen: t -> unit Lwt.t
  (** [listen t] requests that the stack listen for traffic on the
      network interface associated with the stack, and demultiplex
      traffic to the appropriate callbacks. *)
end

module type V4V6 = sig
  type t
  (** The type representing the internal state of the dual IPv4 and IPv6 stack. *)

  val disconnect: t -> unit Lwt.t
  (** Disconnect from the dual IPv4 and IPv6 stack. While this might take some
      time to complete, it can never result in an error. *)

  module UDP: Udp.S with type ipaddr = Ipaddr.t

  module TCP: Tcp.S with type ipaddr = Ipaddr.t

  module IP: Ip.S with type ipaddr = Ipaddr.t

  val udp: t -> UDP.t
  (** [udp t] obtains a descriptor for use with the [UDP] module,
      usually to transmit traffic. *)

  val tcp: t -> TCP.t
  (** [tcp t] obtains a descriptor for use with the [TCP] module,
      usually to initiate outgoing connections. *)

  val ip: t -> IP.t
  (** [ip t] obtains a descriptor for use with the [IP] module,
      which can handle raw IPv4 and IPv6 frames, or manipulate IP address
      configuration on the stack interface. *)

  val listen_udp: t -> port:int -> UDP.callback -> unit
  [@@ocaml.deprecated "use UDP.listen instead (since mirage-protocols 6.0.0)."]
  (** [listen_udp t ~port cb] registers the [cb] callback on the
      UDP [port] and immediately return.  If [port] is invalid (not
      between 0 and 65535 inclusive), it raises [Invalid_argument].
      Multiple bindings to the same port will overwrite previous
      bindings, so callbacks will not chain if ports clash. *)

  val listen_tcp: ?keepalive:Tcp.Keepalive.t
    -> t -> port:int -> (TCP.flow -> unit Lwt.t) -> unit
  [@@ocaml.deprecated "use TCP.listen instead (since mirage-protocols 6.0.0)."]
  (** [listen_tcp ~keepalive t ~port cb] registers the [cb] callback
      on the TCP [port] and immediately return.  If [port] is invalid (not
      between 0 and 65535 inclusive), it raises [Invalid_argument].
      Multiple bindings to the same port will overwrite previous
      bindings, so callbacks will not chain if ports clash.
      If [~keepalive] is provided then these keepalive settings will be
      applied to the accepted connections before the callback is called. *)

  val listen: t -> unit Lwt.t
  (** [listen t] requests that the stack listen for traffic on the
      network interface associated with the stack, and demultiplex
      traffic to the appropriate callbacks. *)
end
