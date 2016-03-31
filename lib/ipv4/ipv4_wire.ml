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
