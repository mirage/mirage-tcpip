module Make ( E : V1_LWT.ETHIF) : sig
  include V1_LWT.ARP with type ipaddr = Ipaddr.V4.t
  val connect : E.t -> [> `Ok of t | `Error of error ] Lwt.t
  val add_entry : t -> Ipaddr.V4.t -> macaddr -> unit
  val remove_entry : t -> Ipaddr.V4.t -> bool
end
