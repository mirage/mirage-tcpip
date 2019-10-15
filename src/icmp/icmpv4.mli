module Make (I:Mirage_protocols.IP with type ipaddr = Ipaddr.V4.t) : sig
  include Mirage_protocols.ICMP with type ipaddr = Ipaddr.V4.t

  val connect : I.t -> t Lwt.t
end
