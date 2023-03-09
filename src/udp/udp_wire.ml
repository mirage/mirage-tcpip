let sizeof_udp = 8

let src_port_offset = 0
let dst_port_offset = 2
let length_offset = 4
let checksum_offset = 6

let get_src_port buf = Cstruct.BE.get_uint16 buf src_port_offset
let set_src_port buf v = Cstruct.BE.set_uint16 buf src_port_offset v

let get_dst_port buf = Cstruct.BE.get_uint16 buf dst_port_offset
let set_dst_port buf v = Cstruct.BE.set_uint16 buf dst_port_offset v

let get_length buf = Cstruct.BE.get_uint16 buf length_offset
let set_length buf v = Cstruct.BE.set_uint16 buf length_offset v

let get_checksum buf = Cstruct.BE.get_uint16 buf checksum_offset
let set_checksum buf value = Cstruct.BE.set_uint16 buf checksum_offset value
