include Mirage_protocols_lwt.ICMPV4

val connect : unit -> t io

val listen : t -> ipaddr -> (buffer -> unit io) -> unit io
(** [listen t addr fn] attempts to create an unprivileged listener on IP address [addr].
 * It will take any incoming ICMP packets and process them with the provided [fn]. *)
