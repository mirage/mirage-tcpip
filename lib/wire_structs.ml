cstruct ethernet {
    uint8_t        dst[6];
    uint8_t        src[6];
    uint16_t       ethertype
  } as big_endian

cenum ethertype {
    ARP  = 0x0806;
    IPv4 = 0x0800;
    IPv6 = 0x86dd;
  } as uint16_t

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


cstruct udp {
    uint16_t source_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum
  } as big_endian

module Ipv4_wire = struct
  cstruct ipv4 {
      uint8_t        hlen_version;
      uint8_t        tos;
      uint16_t       len;
      uint16_t       id;
      uint16_t       off;
      uint8_t        ttl;
      uint8_t        proto;
      uint16_t       csum;
      uint32_t       src;
      uint32_t       dst
    } as big_endian

  cstruct icmpv4 {
      uint8_t ty;
      uint8_t code;
      uint16_t csum;
      uint16_t id;
      uint16_t seq
    } as big_endian

  let int_to_protocol = function
    | 1  -> Some `ICMP
    | 6  -> Some `TCP
    | 17 -> Some `UDP
    | _  -> None

  let protocol_to_int = function
    | `ICMP   -> 1
    | `TCP    -> 6
    | `UDP    -> 17
end

module Tcp_wire = struct
  cstruct tcp {
      uint16_t src_port;
      uint16_t dst_port;
      uint32_t sequence;
      uint32_t ack_number;
      uint8_t  dataoff;
      uint8_t  flags;
      uint16_t window;
      uint16_t checksum;
      uint16_t urg_ptr
    } as big_endian

  cstruct tcpv4_pseudo_header {
      uint32_t src;
      uint32_t dst;
      uint8_t res;
      uint8_t proto;
      uint16_t len
    } as big_endian

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
  cstruct ipv6 {
      uint32_t       version_flow;
      uint16_t       len;  (* payload length (includes extensions) *)
      uint8_t        nhdr; (* next header *)
      uint8_t        hlim; (* hop limit *)
      uint8_t        src[16];
      uint8_t        dst[16]
    } as big_endian

  let int_to_protocol = function
    | 58  -> Some `ICMP
    | 6  -> Some `TCP
    | 17 -> Some `UDP
    | _  -> None

  let protocol_to_int = function
    | `ICMP   -> 58
    | `TCP    -> 6
    | `UDP    -> 17

  cstruct icmpv6 {
      uint8_t        ty;
      uint8_t        code;
      uint16_t       csum;
      uint32_t       reserved
    } as big_endian

  cstruct pingv6 {
      uint8_t       ty;
      uint8_t       code;
      uint16_t      csum;
      uint16_t      id;
      uint16_t      seq
    } as big_endian

  cstruct ns {
      uint8_t  ty;
      uint8_t  code;
      uint16_t csum;
      uint32_t reserved;
      uint8_t  target[16]
    } as big_endian

  cstruct na {
      uint8_t  ty;
      uint8_t  code;
      uint16_t csum;
      uint32_t reserved;
      uint8_t  target[16]
    } as big_endian

  let get_na_router buf =
    (Cstruct.get_uint8 buf 4 land 0x80) <> 0

  let get_na_solicited buf =
    (Cstruct.get_uint8 buf 4 land 0x40) <> 0

  let get_na_override buf =
    (Cstruct.get_uint8 buf 4 land 0x20) <> 0

  cstruct rs {
      uint8_t  ty;
      uint8_t  code;
      uint16_t csum;
      uint32_t reserved
    } as big_endian

  cstruct opt_prefix {
      uint8_t    ty;
      uint8_t    len;
      uint8_t    prefix_len;
      uint8_t    reserved1;
      uint32_t   valid_lifetime;
      uint32_t   preferred_lifetime;
      uint32_t   reserved2;
      uint8_t    prefix[16]
    } as big_endian

  let get_opt_prefix_on_link buf =
    get_opt_prefix_reserved1 buf land 0x80 <> 0

  let get_opt_prefix_autonomous buf =
    get_opt_prefix_reserved1 buf land 0x40 <> 0

  cstruct opt {
      uint8_t  ty;
      uint8_t  len
    } as big_endian

  cstruct llopt {
      uint8_t ty;
      uint8_t len;
      uint8_t addr[6]
    } as big_endian

  cstruct ra {
      uint8_t   ty;
      uint8_t   code;
      uint16_t  csum;
      uint8_t   cur_hop_limit;
      uint8_t   reserved;
      uint16_t  router_lifetime;
      uint32_t  reachable_time;
      uint32_t  retrans_timer
    } as big_endian

  let sizeof_ipv6_pseudo_header = 16 + 16 + 4 + 4
end
