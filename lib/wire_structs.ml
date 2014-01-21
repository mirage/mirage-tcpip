cstruct ethernet {
  uint8_t        dst[6];
  uint8_t        src[6];
  uint16_t       ethertype
} as big_endian

cstruct ipv4 {
  uint8_t        hlen_version;
  uint8_t        tos;
  uint16_t       len;
  uint16_t       id;
  uint16_t       off;
  uint8_t        ttl;
  uint8_t        proto;
  uint16_t       csum;
  uint32_t       src;
  uint32_t       dst
} as big_endian

cstruct icmpv4 {
  uint8_t ty;
  uint8_t code;
  uint16_t csum;
  uint16_t id;
  uint16_t seq
} as big_endian

cstruct udpv4 {
  uint16_t source_port;                                                                               
  uint16_t dest_port;
  uint16_t length;                                                                                    
  uint16_t checksum
} as big_endian

module Tcp_wire = struct
  cstruct tcpv4 {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t sequence;
    uint32_t ack_number;
    uint8_t  dataoff;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr
  } as big_endian

  cstruct tcpv4_pseudo_header {
    uint32_t src;
    uint32_t dst;
    uint8_t res;
    uint8_t proto;
    uint16_t len
  } as big_endian

  open Cstruct

  (* XXX note that we overwrite the lower half of dataoff
   * with 0, so be careful when implemented CWE flag which 
   * sits there *)
  let get_data_offset buf = ((get_tcpv4_dataoff buf) lsr 4) * 4
  let set_data_offset buf v = set_tcpv4_dataoff buf (v lsl 4)

  let get_fin buf = ((get_uint8 buf 13) land (1 lsl 0)) > 0
  let get_syn buf = ((get_uint8 buf 13) land (1 lsl 1)) > 0
  let get_rst buf = ((get_uint8 buf 13) land (1 lsl 2)) > 0
  let get_psh buf = ((get_uint8 buf 13) land (1 lsl 3)) > 0
  let get_ack buf = ((get_uint8 buf 13) land (1 lsl 4)) > 0
  let get_urg buf = ((get_uint8 buf 13) land (1 lsl 5)) > 0
  let get_ece buf = ((get_uint8 buf 13) land (1 lsl 6)) > 0
  let get_cwr buf = ((get_uint8 buf 13) land (1 lsl 7)) > 0

  let set_fin buf = set_uint8 buf 13 ((get_uint8 buf 13) lor (1 lsl 0))
  let set_syn buf = set_uint8 buf 13 ((get_uint8 buf 13) lor (1 lsl 1))
  let set_rst buf = set_uint8 buf 13 ((get_uint8 buf 13) lor (1 lsl 2))
  let set_psh buf = set_uint8 buf 13 ((get_uint8 buf 13) lor (1 lsl 3))
  let set_ack buf = set_uint8 buf 13 ((get_uint8 buf 13) lor (1 lsl 4))
  let set_urg buf = set_uint8 buf 13 ((get_uint8 buf 13) lor (1 lsl 5))
  let set_ece buf = set_uint8 buf 13 ((get_uint8 buf 13) lor (1 lsl 6))
  let set_cwr buf = set_uint8 buf 13 ((get_uint8 buf 13) lor (1 lsl 7))
end
