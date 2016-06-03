[%%cstruct
type tcp = {
    src_port:   uint16_t;
    dst_port:   uint16_t;
    sequence:   uint32_t;
    ack_number: uint32_t;
    dataoff:    uint8_t;
    flags:      uint8_t;
    window:     uint16_t;
    checksum:   uint16_t;
    urg_ptr:    uint16_t;
  } [@@big_endian]
]

[%%cstruct
type tcpv4_pseudo_header = {
    src:   uint32_t;
    dst:   uint32_t;
    res:   uint8_t;
    proto: uint8_t;
    len:   uint16_t;
  } [@@big_endian]
]

(* XXX note that we overwrite the lower half of dataoff
 * with 0, so be careful when implemented CWE flag which
 * sits there *)
let get_data_offset buf = ((get_tcp_dataoff buf) lsr 4) * 4
let set_data_offset buf v = set_tcp_dataoff buf (v lsl 4)

let get_fin buf = ((Cstruct.get_uint8 buf 13) land (1 lsl 0)) > 0
let get_syn buf = ((Cstruct.get_uint8 buf 13) land (1 lsl 1)) > 0
let get_rst buf = ((Cstruct.get_uint8 buf 13) land (1 lsl 2)) > 0
let get_psh buf = ((Cstruct.get_uint8 buf 13) land (1 lsl 3)) > 0
let get_ack buf = ((Cstruct.get_uint8 buf 13) land (1 lsl 4)) > 0
let get_urg buf = ((Cstruct.get_uint8 buf 13) land (1 lsl 5)) > 0
let get_ece buf = ((Cstruct.get_uint8 buf 13) land (1 lsl 6)) > 0
let get_cwr buf = ((Cstruct.get_uint8 buf 13) land (1 lsl 7)) > 0

let set_fin buf =
  Cstruct.set_uint8 buf 13 ((Cstruct.get_uint8 buf 13) lor (1 lsl 0))
let set_syn buf =
  Cstruct.set_uint8 buf 13 ((Cstruct.get_uint8 buf 13) lor (1 lsl 1))
let set_rst buf =
  Cstruct.set_uint8 buf 13 ((Cstruct.get_uint8 buf 13) lor (1 lsl 2))
let set_psh buf =
  Cstruct.set_uint8 buf 13 ((Cstruct.get_uint8 buf 13) lor (1 lsl 3))
let set_ack buf =
  Cstruct.set_uint8 buf 13 ((Cstruct.get_uint8 buf 13) lor (1 lsl 4))
let set_urg buf =
  Cstruct.set_uint8 buf 13 ((Cstruct.get_uint8 buf 13) lor (1 lsl 5))
let set_ece buf =
  Cstruct.set_uint8 buf 13 ((Cstruct.get_uint8 buf 13) lor (1 lsl 6))
let set_cwr buf =
  Cstruct.set_uint8 buf 13 ((Cstruct.get_uint8 buf 13) lor (1 lsl 7))
