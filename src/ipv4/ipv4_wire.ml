let sizeof_ipv4 = 20

let hlen_version_off = 0
let _tos_off = 1
let len_off = 2
let id_off = 4
let off_off = 6
let ttl_off = 8
let proto_off = 9
let csum_off = 10
let src_off = 12
let dst_off = 16

let get_hlen_version buf = Cstruct.get_uint8 buf hlen_version_off
let set_hlen_version buf v = Cstruct.set_uint8 buf hlen_version_off v

let get_len buf = Cstruct.BE.get_uint16 buf len_off
let set_len buf v = Cstruct.BE.set_uint16 buf len_off v

let get_id buf = Cstruct.BE.get_uint16 buf id_off
let set_id buf v = Cstruct.BE.set_uint16 buf id_off v

let get_off buf = Cstruct.BE.get_uint16 buf off_off
let set_off buf v = Cstruct.BE.set_uint16 buf off_off v

let get_ttl buf = Cstruct.get_uint8 buf ttl_off
let set_ttl buf v = Cstruct.set_uint8 buf ttl_off v

let get_proto buf = Cstruct.get_uint8 buf proto_off
let set_proto buf v = Cstruct.set_uint8 buf proto_off v

let get_checksum buf = Cstruct.BE.get_uint16 buf csum_off
let set_checksum buf value = Cstruct.BE.set_uint16 buf csum_off value

let get_src buf = Ipaddr.V4.of_int32 (Cstruct.BE.get_uint32 buf src_off)
let set_src buf v = Cstruct.BE.set_uint32 buf src_off (Ipaddr.V4.to_int32 v)

let get_dst buf = Ipaddr.V4.of_int32 (Cstruct.BE.get_uint32 buf dst_off)
let set_dst buf v = Cstruct.BE.set_uint32 buf dst_off (Ipaddr.V4.to_int32 v)
