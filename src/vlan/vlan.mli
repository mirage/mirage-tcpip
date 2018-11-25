module Make (N : Mirage_net_lwt.S) : sig
  module Vlan_ethernet : sig
    include Mirage_protocols_lwt.ETHERNET
  end

  type t

  val register : t -> int -> (Vlan_ethernet.t, [ `Conflict ]) result

  val connect : N.t -> t Lwt.t
  (** [connect netif] connects an vlan layer on top of the raw
      network device [netif]. *)
end
