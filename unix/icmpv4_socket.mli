include V1_LWT.ICMP with type ipaddr = Ipaddr.V4.t
                     and type buffer = Cstruct.t
                     and type 'a io = 'a Lwt.t

val connect : unit -> unit io
