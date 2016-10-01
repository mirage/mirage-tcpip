module Make ( I:V1_LWT.IPV4 ) : sig
  include V1_LWT.ICMPV4

  val connect : I.t -> t io
end
