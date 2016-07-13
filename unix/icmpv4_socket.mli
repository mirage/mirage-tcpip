include V1_LWT.ICMP with type ipaddr = Ipaddr.V4.t
                     and type buffer = Cstruct.t
                     and type 'a io = 'a Lwt.t

val connect : unit -> t io

val listen : t -> ipaddr -> (buffer -> unit io) -> unit io
(** [listen t addr fn] attempts to create an unprivileged listener on IP address [addr].
 * It will take any incoming ICMP packets and process them with the provided [fn]. *)
