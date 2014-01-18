(* Temporary: move to mirage-types *)

open V1
module type XETHIF = sig

  (** Abstract type for a memory buffer that may not be page aligned *)
  type buffer

  type netif

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

  val input : ipv4:(buffer -> unit io) -> ipv6:(buffer -> unit io) -> t -> unit io
  (** [listen nf fn] is a blocking operation that calls [fn buf] with
      every packet that is read from the interface.  It returns as soon
      as it has initialised, and the function can be stopped by calling
      [disconnect] in the device layer. *)
end

