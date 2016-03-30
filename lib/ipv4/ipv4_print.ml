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
