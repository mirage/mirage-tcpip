module Make ( I:Mirage_protocols_lwt.IPV4 ) : sig
  include Mirage_protocols_lwt.ICMPV4

  val connect : I.t -> t io
end
