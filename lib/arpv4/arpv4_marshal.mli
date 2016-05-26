val to_cstruct : buf:Cstruct.t -> op:Arpv4_wire.op ->
  src_ip:Ipaddr.V4.t -> dst_ip:Ipaddr.V4.t ->
  src_mac:Macaddr.t -> dst_mac:Macaddr.t ->
  (unit, string) Result.result

(** given an [Arpv4_unmarshal.t], construct and return an ARP header representing
    [t.op], and the source/destination ip/mac in [t].  [make_cstruct] will allocate
   a new 24 bytes for the ARP header it returns. *)
val make_cstruct : Arpv4_unmarshal.t -> Cstruct.t
