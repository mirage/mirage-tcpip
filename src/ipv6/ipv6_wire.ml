let sizeof_ipv6 = 40

let int_to_protocol = function
  | 58  -> Some `ICMP
  | 6  -> Some `TCP
  | 17 -> Some `UDP
  | _  -> None

let protocol_to_int = function
  | `ICMP   -> 58
  | `TCP    -> 6
  | `UDP    -> 17

let set_ip buf off v =
  Ipaddr_cstruct.V6.write_cstruct_exn v (Cstruct.shift buf off)
let get_ip buf off =
  Ipaddr_cstruct.V6.of_cstruct_exn (Cstruct.shift buf off)

let version_flow_off = 0
let len_off = 4
let nhdr_off = 6
let hlim_off = 7
let src_off = 8
let dst_off = 24

let get_version_flow buf = Cstruct.BE.get_uint32 buf version_flow_off
let set_version_flow buf v = Cstruct.BE.set_uint32 buf version_flow_off v

let get_nhdr buf = Cstruct.get_uint8 buf nhdr_off
let set_nhdr buf v = Cstruct.set_uint8 buf nhdr_off v

let get_len buf = Cstruct.BE.get_uint16 buf len_off
let set_len buf v = Cstruct.BE.set_uint16 buf len_off v

let get_hlim buf = Cstruct.get_uint8 buf hlim_off
let set_hlim buf v = Cstruct.set_uint8 buf hlim_off v

let get_src buf = get_ip buf src_off
let set_src buf v = set_ip buf src_off v

let get_dst buf = get_ip buf dst_off
let set_dst buf v = set_ip buf dst_off v

let ty_off = 0
let get_ty buf = Cstruct.get_uint8 buf ty_off
let set_ty buf v = Cstruct.set_uint8 buf ty_off v

let code_off = 1
let get_code buf = Cstruct.get_uint8 buf code_off
let set_code buf v = Cstruct.set_uint8 buf code_off v

module Ns = struct
  let sizeof_ns = 24

  let csum_off = 2
  let reserved_off = 4
  let target_off = 8

  let get_checksum buf = Cstruct.BE.get_uint16 buf csum_off
  let set_checksum buf v = Cstruct.BE.set_uint16 buf csum_off v
  let get_reserved buf = Cstruct.BE.get_uint32 buf reserved_off
  let set_reserved buf v = Cstruct.BE.set_uint32 buf reserved_off v
  let get_target buf = get_ip buf target_off
  let set_target buf v = set_ip buf target_off v
end

module Llopt = struct
  let sizeof_llopt = 8

  let len_off = 1
  let addr_off = 2

  let get_len buf = Cstruct.get_uint8 buf len_off
  let set_len buf v = Cstruct.set_uint8 buf len_off v

  let get_addr buf = Macaddr_cstruct.of_cstruct_exn (Cstruct.shift buf addr_off)
  let set_addr buf v =
    Macaddr_cstruct.write_cstruct_exn v (Cstruct.shift buf addr_off)
end

module Icmpv6 = struct
  let sizeof_icmpv6 = 8

  let _reserved_off = 4

  let set_checksum = Ns.set_checksum
end

module Na = struct
  let sizeof_na = 24

  let get_reserved = Ns.get_reserved
  let set_reserved = Ns.set_reserved
  let get_target = Ns.get_target
  let set_target = Ns.set_target

  let get_first_reserved_byte buf =
    Cstruct.get_uint8 buf Ns.reserved_off

  let get_router buf = (get_first_reserved_byte buf land 0x80) <> 0
  let get_solicited buf = (get_first_reserved_byte buf land 0x40) <> 0
  let get_override buf = (get_first_reserved_byte buf land 0x20) <> 0
end

module Rs = struct
  let sizeof_rs = 8

  let set_checksum = Ns.set_checksum
  let set_reserved = Ns.set_reserved
end

module Pingv6 = struct
  let sizeof_pingv6 = 8

  let id_off = 4
  let seq_off = 6

  let get_checksum = Ns.get_checksum
  let set_checksum = Ns.set_checksum

  let get_id buf = Cstruct.BE.get_uint16 buf id_off
  let set_id buf v = Cstruct.BE.set_uint16 buf id_off v

  let get_seq buf = Cstruct.BE.set_uint16 buf seq_off
  let set_seq buf v = Cstruct.BE.set_uint16 buf seq_off v
end

module Opt = struct
  let sizeof_opt = 2

  let get_len = Llopt.get_len
  let set_len = Llopt.set_len
end

module Opt_prefix = struct
  let sizeof_opt_prefix = 32

  let get_len = Llopt.get_len
  let set_len = Llopt.set_len

  let prefix_len_off = 2
  let get_prefix_len buf = Cstruct.get_uint8 buf prefix_len_off
  let set_prefix_len buf v = Cstruct.set_uint8 buf prefix_len_off v

  let reserved1_off = 3
  let get_reserved1 buf = Cstruct.get_uint8 buf reserved1_off
  let set_reserved1 buf v = Cstruct.set_uint8 buf reserved1_off v

  let valid_lifetime_off = 4
  let get_valid_lifetime buf = Cstruct.BE.get_uint32 buf valid_lifetime_off
  let set_valid_lifetime buf v = Cstruct.BE.set_uint32 buf valid_lifetime_off v

  let preferred_lifetime_off = 8
  let get_preferred_lifetime buf = Cstruct.BE.get_uint32 buf preferred_lifetime_off
  let set_preferred_lifetime buf v = Cstruct.BE.set_uint32 buf preferred_lifetime_off v

  let reserved2_off = 12

  let prefix_off = 16
  let get_prefix buf = get_ip buf prefix_off
  let set_prefix buf v = set_ip buf prefix_off v

  let on_link buf = get_reserved1 buf land 0x80 <> 0

  let autonomous buf = get_reserved1 buf land 0x40 <> 0

end

module Ra = struct
  let sizeof_ra = 16

  let get_checksum = Ns.get_checksum
  let set_checksum = Ns.set_checksum

  let cur_hop_limit_off = 4
  let get_cur_hop_limit buf = Cstruct.get_uint8 buf cur_hop_limit_off

  let reserved_off = 5

  let router_lifetime_off = 6
  let get_router_lifetime buf = Cstruct.BE.get_uint16 buf router_lifetime_off

  let reachable_time_off = 8
  let get_reachable_time buf = Cstruct.BE.get_uint32 buf reachable_time_off

  let retrans_timer_off = 12
  let get_retrans_timer buf = Cstruct.BE.get_uint32 buf retrans_timer_off
end

module Redirect = struct
  let sizeof_redirect = 40

  let get_checksum = Ns.get_checksum
  let set_checksum = Ns.set_checksum

  let get_reserved = Ns.get_reserved
  let set_reserved = Ns.set_reserved

  let get_target = Ns.get_target
  let set_target = Ns.set_target

  let destination_off = 24
  let get_destination buf = get_ip buf destination_off
  let set_destination buf v = set_ip buf destination_off v
end

(* let sizeof_ipv6_pseudo_header = 16 + 16 + 4 + 4 *)
