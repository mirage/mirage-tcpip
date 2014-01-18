
(* Temporary: move to mirage-types *)
module type XETHIF = sig
  open V1

  (** Abstract type for a memory buffer that may not be page aligned *)
  type buffer

  type netif

  type ipv4addr

  (** IO operation errors *)
  type error = [
    | `Unknown of string (** an undiagnosed error *)
    | `Unimplemented     (** operation not yet implemented in the code *)
    | `Disconnected      (** the device has been previously disconnected *)
  ]

  (** Unique MAC identifier for the device *)
  type macaddr

  include DEVICE with
        type error := error
    and type id    := netif

  val write : t -> buffer -> unit io
  (** [write nf buf] outputs [buf] to netfront [nf]. *)

  val writev : t -> buffer list -> unit io
  (** [writev nf bufs] output a list of buffers to netfront [nf] as a
      single packet. *)

  val mac : t -> macaddr
  (** [mac nf] is the MAC address of [nf]. *)

  val input : ipv4:(buffer -> unit io) -> ipv6:(buffer -> unit io) -> t -> buffer -> unit io
  (** [listen nf fn] is a blocking operation that calls [fn buf] with
      every packet that is read from the interface.  It returns as soon
      as it has initialised, and the function can be stopped by calling
      [disconnect] in the device layer. *)
 
  val query_arpv4 : t -> ipv4addr -> macaddr io
  val add_ipv4 : t -> ipv4addr -> unit io
end

module type XIPV4 = sig
  open V1
  type buffer
  type ethif
  type ipaddr

  (** IO operation errors *)
  type error = [
    | `Unknown of string (** an undiagnosed error *)
    | `Unimplemented     (** operation not yet implemented in the code *)
  ]

  include DEVICE with
        type error := error
    and type id    := ethif
  
  val get_header: proto:[< `ICMP | `TCP | `UDP ] -> dest_ip:ipaddr -> t -> (buffer * int) io
  val write: t -> buffer -> buffer -> unit io
  val writev: t -> buffer -> buffer list -> unit io
  val set_ip: t -> ipaddr -> unit io
  val get_ip: t -> ipaddr
  val set_netmask: t -> ipaddr -> unit io
  val get_netmask: t -> ipaddr
  val set_gateways: t -> ipaddr list -> unit io
end

module type LWT_NETWORK = V1.NETWORK
  with type 'a io   = 'a Lwt.t
   and type buffer  = Cstruct.t
   and type macaddr = Macaddr.t
  
module type LWT_ETHIF = XETHIF 
  with type 'a io = 'a Lwt.t
   and type buffer = Cstruct.t
   and type macaddr = Macaddr.t
   and type ipv4addr = Ipaddr.V4.t

module type LWT_IPV4 = XIPV4
  with type 'a io = 'a Lwt.t
   and type buffer = Cstruct.t
   and type ipaddr = Ipaddr.V4.t
  
