
module type LWT_NETWORK = V1.NETWORK
  with type 'a io   = 'a Lwt.t
   and type buffer  = Cstruct.t
   and type macaddr = Macaddr.t
  
module type LWT_ETHIF = V1.ETHIF 
  with type 'a io = 'a Lwt.t
   and type buffer = Cstruct.t
   and type macaddr = Macaddr.t
   and type ipv4addr = Ipaddr.V4.t

module type LWT_IPV4 = V1.IPV4
  with type 'a io = 'a Lwt.t
   and type buffer = Cstruct.t
   and type ipaddr = Ipaddr.V4.t
