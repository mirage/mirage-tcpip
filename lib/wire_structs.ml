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
  
