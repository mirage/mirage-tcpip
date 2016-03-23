module Parse : sig
  type subheader =
    | Id_and_seq of Cstruct.uint16 * Cstruct.uint16
    | Pointer of Cstruct.uint8
    | Address of Ipaddr.V4.t
    | Unused

  type t = {
    code : Cstruct.uint8;
    ty : Cstruct.uint8;
    csum : Cstruct.uint16;
    subheader : subheader;
    payload : Cstruct.t option;
  }

  val input : Cstruct.t -> (t, string) Result.result

end

module Print : sig
  val echo_request : Cstruct.uint16 -> Cstruct.uint16 -> Cstruct.t

end
module Make ( I:V1_LWT.IPV4 ) : sig
  include V1_LWT.ICMPV4

  val connect : I.t -> [ `Ok of t | `Error of error ] io

end
