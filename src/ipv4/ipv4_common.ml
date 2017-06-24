let adjust_output_header ~dmac ~tlen frame =
  let open Ipv4_wire in
  Ethif_wire.set_ethernet_dst dmac 0 frame;
  let buf = Cstruct.sub frame Ethif_wire.sizeof_ethernet sizeof_ipv4 in
  (* Set the mutable values in the ipv4 header *)
  set_ipv4_len buf tlen;
  set_ipv4_id buf (Random.int 65535); (* TODO *)
  set_ipv4_csum buf 0;
  let checksum = Tcpip_checksum.ones_complement buf in
  set_ipv4_csum buf checksum

let allocate_frame ~src ~source ~(dst:Ipaddr.V4.t) ~(proto : [`ICMP | `TCP | `UDP]) : (Cstruct.t * int) =
  let open Ipv4_wire in
  let ethernet_frame = Io_page.to_cstruct (Io_page.get 1) in
  let len = Ethif_wire.sizeof_ethernet + sizeof_ipv4 in
  let eth_header = Ethif_packet.({ethertype = Ethif_wire.IPv4;
                                  source;
                                  destination = Macaddr.broadcast}) in
  match Ethif_packet.Marshal.into_cstruct eth_header ethernet_frame with
  | Error _s -> 
    raise (Invalid_argument "writing ethif header to ipv4.allocate_frame failed")
  | Ok () ->
    let buf = Cstruct.shift ethernet_frame Ethif_wire.sizeof_ethernet in
    (* TODO: why 38 for TTL? *)
    let ipv4_header = Ipv4_packet.({options = Cstruct.create 0;
                                    src; dst; ttl = 38; 
                                    proto = Ipv4_packet.Marshal.protocol_to_int proto; }) in
    (* set the payload_len to 0, since we don't know what it'll be yet *)
    (* the caller needs to then use [writev] or [write] to output the buffer;
       otherwise length, id, and checksum won't be set properly *)
    match Ipv4_packet.Marshal.into_cstruct ~payload_len:0 ipv4_header buf with
    | Error _s ->
      raise (Invalid_argument "writing ipv4 header to ipv4.allocate_frame failed")
    | Ok () ->
      (ethernet_frame, len)

let checksum frame bufs =
  let packet = Cstruct.shift frame Ethif_wire.sizeof_ethernet in
  Ipv4_wire.set_ipv4_csum packet 0;
  Tcpip_checksum.ones_complement_list (packet :: bufs)
