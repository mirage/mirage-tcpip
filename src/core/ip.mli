(** {2 IP layer} *)

(** IP errors and protocols. *)
type error = [
  | `No_route of string (** can't send a message to that destination *)
  | `Would_fragment (** would need to fragment, but fragmentation is disabled *)
]

val pp_error : error Fmt.t

type proto = [ `TCP | `UDP | `ICMP ]
val pp_proto: proto Fmt.t

(** An Internet Protocol (IP) layer reassembles IP fragments into packets,
   removes the IP header, and on the sending side fragments overlong payload
   and inserts IP headers. *)
module type S = sig

  type nonrec error = private [> error]
  (** The type for IP errors. *)

  val pp_error: error Fmt.t
  (** [pp_error] is the pretty-printer for errors. *)

  type ipaddr
  (** The type for IP addresses. *)

  val pp_ipaddr : ipaddr Fmt.t
  (** [pp_ipaddr] is the pretty-printer for IP addresses. *)

  type t
  (** The type representing the internal state of the IP layer. *)

  val disconnect: t -> unit Lwt.t
  (** Disconnect from the IP layer. While this might take some time to
      complete, it can never result in an error. *)

  type callback = src:ipaddr -> dst:ipaddr -> Cstruct.t -> unit Lwt.t
  (** An input continuation used by the parsing functions to pass on
      an input packet down the stack.

      [callback ~src ~dst buf] will be called with [src] and [dst]
      containing the source and destination IP address respectively,
      and [buf] will be a buffer pointing at the start of the IP
      payload. *)

  val input:
    t ->
    tcp:callback -> udp:callback -> default:(proto:int -> callback) ->
    Cstruct.t -> unit Lwt.t
  (** [input ~tcp ~udp ~default ip buf] demultiplexes an incoming
      [buffer] that contains an IP frame. It examines the protocol
      header and passes the result onto either the [tcp] or [udp]
      function, or the [default] function for unknown IP protocols. *)

  val write: t -> ?fragment:bool -> ?ttl:int ->
    ?src:ipaddr -> ipaddr -> proto -> ?size:int -> (Cstruct.t -> int) ->
    Cstruct.t list -> (unit, error) result Lwt.t
  (** [write t ~fragment ~ttl ~src dst proto ~size headerf payload] allocates a
     buffer, writes the IP header, and calls the headerf function. This may
     write to the provided buffer of [size] (default 0). If [size + ip header]
     exceeds the maximum transfer unit, an error is returned. The [payload] is
     appended. The optional [fragment] argument defaults to [true], in which
     case multiple IP-fragmented frames are sent if the payload is too big for a
     single frame. When it is [false], the don't fragment bit is set and if the
     payload and header would exceed the maximum transfer unit, an error is
     returned. *)

  val pseudoheader : t -> ?src:ipaddr -> ipaddr -> proto -> int -> Cstruct.t
  (** [pseudoheader t ~src dst proto len] gives a pseudoheader suitable for use in
      TCP or UDP checksum calculation based on [t]. *)

  val src: t -> dst:ipaddr -> ipaddr
  (** [src ip ~dst] is the source address to be used to send a
      packet to [dst].  In the case of IPv4, this will always return
      the same IP, which is the only one set. *)

  val get_ip: t -> ipaddr list
  (** Get the IP addresses associated with this interface. For IPv4, only
      one IP address can be set at a time, so the list will always be of
      length 1 (and may be the default value, 0.0.0.0). *)

  val mtu: t -> dst:ipaddr -> int
  (** [mtu ~dst ip] is the Maximum Transmission Unit of the [ip] i.e. the
      maximum size of the payload, not including the IP header. *)
end
