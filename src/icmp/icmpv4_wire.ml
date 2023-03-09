type ty =
  | Echo_reply
  | Destination_unreachable
  | Source_quench
  | Redirect
  | Echo_request
  | Time_exceeded
  | Parameter_problem
  | Timestamp_request
  | Timestamp_reply
  | Information_request
  | Information_reply

let ty_to_string = function
  | Echo_reply -> "echo reply"
  | Destination_unreachable -> "destination unreachable"
  | Source_quench -> "source quench"
  | Redirect -> "redirect"
  | Echo_request -> "echo request"
  | Time_exceeded -> "time exceeded"
  | Parameter_problem -> "parameter problem"
  | Timestamp_request -> "timestamp request"
  | Timestamp_reply -> "timestamp reply"
  | Information_request -> "information request"
  | Information_reply -> "information reply"

let int_to_ty = function
  | 0 -> Some Echo_reply
  | 3 -> Some Destination_unreachable
  | 4 -> Some Source_quench
  | 5 -> Some Redirect
  | 8 -> Some Echo_request
  | 11 -> Some Time_exceeded
  | 12 -> Some Parameter_problem
  | 13 -> Some Timestamp_request
  | 14 -> Some Timestamp_reply
  | 15 -> Some Information_request
  | 16 -> Some Information_reply
  | _ -> None

let ty_to_int = function
  | Echo_reply -> 0
  | Destination_unreachable -> 3
  | Source_quench -> 4
  | Redirect -> 5
  | Echo_request -> 8
  | Time_exceeded -> 11
  | Parameter_problem -> 12
  | Timestamp_request -> 13
  | Timestamp_reply -> 14
  | Information_request -> 15
  | Information_reply -> 16

type unreachable_reason =
  | Network_unreachable
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
  | Precedence_insufficient

let unreachable_reason_to_int = function
  | Network_unreachable -> 0
  | Host_unreachable -> 1
  | Protocol_unreachable -> 2
  | Port_unreachable -> 3
  | Would_fragment -> 4
  | Source_route_failed -> 5
  | Destination_network_unknown -> 6
  | Destination_host_unknown -> 7
  | Source_host_isolated -> 8
  | Destination_net_prohibited -> 9
  | Destination_host_prohibited -> 10
  | TOS_network_unreachable -> 11
  | TOS_host_unreachable -> 12
  | Communication_prohibited -> 13
  | Host_precedence_violation -> 14
  | Precedence_insufficient -> 15

let sizeof_icmpv4 = 8

let ty_off = 0
let code_off = 1
let csum_off = 2

let get_ty buf = Cstruct.get_uint8 buf ty_off
let set_ty buf value = Cstruct.set_uint8 buf ty_off value

let get_code buf = Cstruct.get_uint8 buf code_off
let set_code buf value = Cstruct.set_uint8 buf code_off value

let get_checksum buf = Cstruct.BE.get_uint16 buf csum_off
let set_checksum buf value = Cstruct.BE.set_uint16 buf csum_off value
