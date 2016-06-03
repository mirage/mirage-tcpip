[%%cstruct
type ethernet = {
    dst: uint8_t        [@len 6];
    src: uint8_t        [@len 6];
    ethertype: uint16_t;
  } [@@big_endian]
]

[%%cenum
type ethertype =
  | ARP  [@id 0x0806]
  | IPv4 [@id 0x0800]
  | IPv6 [@id 0x86dd]
  [@@uint16_t]
]
