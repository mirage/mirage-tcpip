let parse_ethernet_frame frame =
  let open Ethif_wire in
  if Cstruct.len frame >= 14 then
    (* source + destination + type = 14 *)
    let payload = Cstruct.shift frame sizeof_ethernet
    and typ = get_ethernet_ethertype frame
    and dst = Macaddr.of_bytes_exn (copy_ethernet_dst frame)
    in
    Some (int_to_ethertype typ, dst, payload)
  else
    None

