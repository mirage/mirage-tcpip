[%%cstruct
type arp = {
  htype: uint16_t;
  ptype: uint16_t;
  hlen: uint8_t;
  plen: uint8_t;
  op: uint16_t;
  sha: uint8_t [@len 6];
  spa: uint32_t;
  tha: uint8_t [@len 6];
  tpa: uint32_t;
} [@@big_endian]
]

[%%cenum
type op =
  | Request [@id 1]
  | Reply
  [@@uint16_t]
]
