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

[%%cenum
type unreachable_reason =
  | Network_unreachable [@id 0]
  | Host_unreachable
  | Protocol_unreachable
  | Port_unreachable
  | Would_fragment
  | Source_route_failed
  | Destination_network_unknown
  | Destination_host_unknown
  | Source_host_isolated
  | Destination_net_prohibited
  | Destination_host_prohibited
  | TOS_network_unreachable
  | TOS_host_unreachable
  | Communication_prohibited
  | Host_precedence_violation
  | Precedence_insufficient [@id 15]
  [@@uint8_t]
]
