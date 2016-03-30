[%%cstruct
type ipv4 = {
    hlen_version: uint8_t;
    tos:          uint8_t;
    len:          uint16_t;
    id:           uint16_t;
    off:          uint16_t;
    ttl:          uint8_t;
    proto:        uint8_t;
    csum:         uint16_t;
    src:          uint32_t;
    dst:          uint32_t;
  } [@@big_endian]
]
[%%cstruct
type icmpv4 = {
    ty:   uint8_t;
    code: uint8_t;
    csum: uint16_t;
    id:   uint16_t;
    seq:  uint16_t;
  } [@@big_endian]
]
