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

let parse_ethernet_frame frame =
  if Cstruct.len frame >= 14 then
    (* source + destination + type = 14 *)
    let payload = Cstruct.shift frame sizeof_ethernet
    and typ = get_ethernet_ethertype frame
    and dst = Macaddr.of_bytes_exn (copy_ethernet_dst frame)
    in
    Some (int_to_ethertype typ, dst, payload)
  else
    None


[%%cstruct
type udp = {
    source_port: uint16_t;
    dest_port: uint16_t;
    length: uint16_t;
    checksum: uint16_t;
  } [@@big_endian]
]

module Ipv4_wire = struct
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
end

module Tcp_wire = struct
  [%%cstruct
  type tcp = {
      src_port:   uint16_t;
      dst_port:   uint16_t;
      sequence:   uint32_t;
      ack_number: uint32_t;
      dataoff:    uint8_t;
      flags:      uint8_t;
      window:     uint16_t;
      checksum:   uint16_t;
      urg_ptr:    uint16_t;
    } [@@big_endian]
  ]

  [%%cstruct
  type tcpv4_pseudo_header = {
      src:   uint32_t;
      dst:   uint32_t;
      res:   uint8_t;
      proto: uint8_t;
      len:   uint16_t;
    } [@@big_endian]
  ]

  (* XXX note that we overwrite the lower half of dataoff
   * with 0, so be careful when implemented CWE flag which
   * sits there *)
  let get_data_offset buf = ((get_tcp_dataoff buf) lsr 4) * 4
  let set_data_offset buf v = set_tcp_dataoff buf (v lsl 4)

  let get_fin buf = ((Cstruct.get_uint8 buf 13) land (1 lsl 0)) > 0
  let get_syn buf = ((Cstruct.get_uint8 buf 13) land (1 lsl 1)) > 0
  let get_rst buf = ((Cstruct.get_uint8 buf 13) land (1 lsl 2)) > 0
  let get_psh buf = ((Cstruct.get_uint8 buf 13) land (1 lsl 3)) > 0
  let get_ack buf = ((Cstruct.get_uint8 buf 13) land (1 lsl 4)) > 0
  let get_urg buf = ((Cstruct.get_uint8 buf 13) land (1 lsl 5)) > 0
  let get_ece buf = ((Cstruct.get_uint8 buf 13) land (1 lsl 6)) > 0
  let get_cwr buf = ((Cstruct.get_uint8 buf 13) land (1 lsl 7)) > 0

  let set_fin buf =
    Cstruct.set_uint8 buf 13 ((Cstruct.get_uint8 buf 13) lor (1 lsl 0))
  let set_syn buf =
    Cstruct.set_uint8 buf 13 ((Cstruct.get_uint8 buf 13) lor (1 lsl 1))
  let set_rst buf =
    Cstruct.set_uint8 buf 13 ((Cstruct.get_uint8 buf 13) lor (1 lsl 2))
  let set_psh buf =
    Cstruct.set_uint8 buf 13 ((Cstruct.get_uint8 buf 13) lor (1 lsl 3))
  let set_ack buf =
    Cstruct.set_uint8 buf 13 ((Cstruct.get_uint8 buf 13) lor (1 lsl 4))
  let set_urg buf =
    Cstruct.set_uint8 buf 13 ((Cstruct.get_uint8 buf 13) lor (1 lsl 5))
  let set_ece buf =
    Cstruct.set_uint8 buf 13 ((Cstruct.get_uint8 buf 13) lor (1 lsl 6))
  let set_cwr buf =
    Cstruct.set_uint8 buf 13 ((Cstruct.get_uint8 buf 13) lor (1 lsl 7))
end

module Ipv6_wire = struct
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
end
