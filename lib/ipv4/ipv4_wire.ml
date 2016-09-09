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

(* more fragments flag *)
let get_more_frags buf = (get_ipv4_off buf) land (1 lsl 13) > 0

(* offset *)
let get_frag_offset buf = (get_ipv4_off buf) land 0x1FFF

