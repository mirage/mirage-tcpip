include Mirage_protocols_lwt.ICMPV4

val connect : unit -> t io

val listen : t -> ipaddr -> (buffer -> unit io) -> unit io
(** [listen t addr fn] attempts to create an unprivileged listener on IP address [addr].

    When a packet is received, the callback [fn] will be called in a fresh background
    thread. The callback will be provided a buffer containing an IP datagram with an
    ICMP payload inside.

    The thread returned by [listen] blocks until the stack is disconnected.
*)
