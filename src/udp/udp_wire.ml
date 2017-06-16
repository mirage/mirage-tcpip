[%%cstruct
type udp = {
    source_port: uint16_t;
    dest_port: uint16_t;
    length: uint16_t;
    checksum: uint16_t;
  } [@@big_endian]
]

