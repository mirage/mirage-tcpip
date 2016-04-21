[%%cstruct
  type icmpv4 = {
    ty:   uint8_t;
    code: uint8_t;
    csum: uint16_t;
    id:   uint16_t;
    seq:  uint16_t;
  } [@@big_endian]
]

[%%cenum
type ty =
  | Echo_reply [@id 0]
  | Destination_unreachable [@id 3]
  | Source_quench
  | Redirect
  | Echo_request [@id 8]
  | Time_exceeded [@id 11]
  | Parameter_problem
  | Timestamp_request
  | Timestamp_reply
  | Information_request
  | Information_reply
  [@@uint8_t]
]
