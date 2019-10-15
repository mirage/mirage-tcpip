include Mirage_protocols.ICMP with type ipaddr = Ipaddr.V4.t

val connect : unit -> t Lwt.t

val listen : t -> ipaddr -> (Cstruct.t -> unit Lwt.t) -> unit Lwt.t
(** [listen t addr fn] attempts to create an unprivileged listener on IP address [addr].

    When a packet is received, the callback [fn] will be called in a fresh background
    thread. The callback will be provided a buffer containing an IP datagram with an
    ICMP payload inside.

    The thread returned by [listen] blocks until the stack is disconnected.
*)
