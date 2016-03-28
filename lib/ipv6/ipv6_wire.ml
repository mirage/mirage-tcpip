
[%%cstruct
type ipv6 = {
    version_flow: uint32_t;
    len:          uint16_t;  (* payload length (includes extensions) *)
    nhdr:         uint8_t; (* next header *)
    hlim:         uint8_t; (* hop limit *)
    src:          uint8_t [@len 16];
    dst:          uint8_t [@len 16];
  } [@@big_endian]
]

let int_to_protocol = function
  | 58  -> Some `ICMP
  | 6  -> Some `TCP
  | 17 -> Some `UDP
  | _  -> None

let protocol_to_int = function
  | `ICMP   -> 58
  | `TCP    -> 6
  | `UDP    -> 17

[%%cstruct
type icmpv6 = {
    ty:       uint8_t;
    code:     uint8_t;
    csum:     uint16_t;
    reserved: uint32_t;
  } [@@big_endian]
]

[%%cstruct
type pingv6 = {
    ty:   uint8_t;
    code: uint8_t;
    csum: uint16_t;
    id:   uint16_t;
    seq:  uint16_t;
  } [@@big_endian]
]
[%%cstruct
type ns = {
    ty:       uint8_t;
    code:     uint8_t;
    csum:     uint16_t;
    reserved: uint32_t;
    target:   uint8_t  [@len 16];
  } [@@big_endian]
]
[%%cstruct
type na = {
    ty: uint8_t;
    code: uint8_t;
    csum: uint16_t;
    reserved: uint32_t;
    target: uint8_t [@len 16];
  } [@@big_endian]
]
let get_na_router buf =
  (Cstruct.get_uint8 buf 4 land 0x80) <> 0

let get_na_solicited buf =
  (Cstruct.get_uint8 buf 4 land 0x40) <> 0

let get_na_override buf =
  (Cstruct.get_uint8 buf 4 land 0x20) <> 0

[%%cstruct
type rs = {
    ty:       uint8_t;
    code:     uint8_t;
    csum:     uint16_t;
    reserved: uint32_t;
  } [@@big_endian]
]
[%%cstruct
type opt_prefix = {
    ty:                 uint8_t;
    len:                uint8_t;
    prefix_len:         uint8_t;
    reserved1:          uint8_t;
    valid_lifetime:     uint32_t;
    preferred_lifetime: uint32_t;
    reserved2:          uint32_t;
    prefix:             uint8_t [@len 16];
  } [@@big_endian]
]
let get_opt_prefix_on_link buf =
  get_opt_prefix_reserved1 buf land 0x80 <> 0

let get_opt_prefix_autonomous buf =
  get_opt_prefix_reserved1 buf land 0x40 <> 0

[%%cstruct
type opt = {
    ty:  uint8_t;
    len: uint8_t;
  } [@@big_endian]
]
[%%cstruct
type llopt = {
    ty:   uint8_t;
    len:  uint8_t;
    addr: uint8_t [@len 6];
  } [@@big_endian]
]

[%%cstruct
type ra = {
    ty:              uint8_t;
    code:            uint8_t;
    csum:            uint16_t;
    cur_hop_limit:   uint8_t;
    reserved:        uint8_t;
    router_lifetime: uint16_t;
    reachable_time:  uint32_t;
    retrans_timer:   uint32_t;
  } [@@big_endian]
]
let sizeof_ipv6_pseudo_header = 16 + 16 + 4 + 4
