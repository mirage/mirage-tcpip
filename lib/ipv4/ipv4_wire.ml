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
let int_to_protocol = function
  | 1  -> Some `ICMP
  | 6  -> Some `TCP
  | 17 -> Some `UDP
  | _  -> None

let protocol_to_int = function
  | `ICMP   -> 1
  | `TCP    -> 6
  | `UDP    -> 17

(* [checksum packet bufs] computes the IP checksum of [bufs]
    computing the pseudo-header from the actual header [packet]
    (which does NOT include the link-layer part). *)
let checksum =
  let pbuf = Io_page.to_cstruct (Io_page.get 1) in
  let pbuf = Cstruct.set_len pbuf 4 in
  Cstruct.set_uint8 pbuf 0 0;
  fun packet bufs ->
    Cstruct.set_uint8 pbuf 1 (get_ipv4_proto packet);
    Cstruct.BE.set_uint16 pbuf 2 (Cstruct.lenv bufs);
    let src_dst = Cstruct.sub packet 12 (2 * 4) in
    Tcpip_checksum.ones_complement_list (src_dst :: pbuf :: bufs)
