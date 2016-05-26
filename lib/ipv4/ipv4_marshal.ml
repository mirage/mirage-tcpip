open Ipv4_wire

type error = string

type protocol = [
  | `ICMP
  | `TCP
  | `UDP ]

let protocol_to_int = function
  | `ICMP   -> 1
  | `TCP    -> 6
  | `UDP    -> 17

let pseudoheader ~src ~dst ~proto len =
  let proto = protocol_to_int proto in
  let ph = Cstruct.create 12 in
  let numify = Ipaddr.V4.to_int32 in
  Cstruct.BE.set_uint32 ph 0 (numify src);
  Cstruct.BE.set_uint32 ph 4 (numify dst);
  Cstruct.set_uint8 ph 8 0;
  Cstruct.set_uint8 ph 9 proto;
  Cstruct.BE.set_uint16 ph 10 len;
  ph

let to_cstruct ~buf ~src ~dst ~proto ~ttl =
  if Cstruct.len buf < sizeof_ipv4 then
    Result.Error "Not enough space for IPv4 header"
  else begin
    set_ipv4_hlen_version buf ((4 lsl 4) + (5));
    set_ipv4_tos buf 0;
    set_ipv4_off buf 0; (* TODO fragmentation *)
    set_ipv4_ttl buf ttl;
    set_ipv4_proto buf (protocol_to_int proto);
    set_ipv4_src buf (Ipaddr.V4.to_int32 src);
    set_ipv4_dst buf (Ipaddr.V4.to_int32 dst);
    Result.Ok ()
  end
