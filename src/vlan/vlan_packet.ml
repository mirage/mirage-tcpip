type t = {
  vlan_id : int ;
  proto : Mirage_protocols.Ethernet.Proto.t ;
  source : Macaddr.t ;
  destination : Macaddr.t ;
}

let pp ppf t =
  Fmt.pf ppf "vlan id %d proto %a source %s destination %s"
    t.vlan_id Mirage_protocols.Ethernet.Proto.pp t.proto (Macaddr.to_string t.source) (Macaddr.to_string t.destination)

let header_size = 18

let unmarshal frame =
  if Cstruct.len frame >= header_size then
    let typ = Ethernet_wire.get_ethernet_ethertype frame in
    if typ = 0x8100 then
      let vlan_id = Cstruct.BE.get_uint16 frame 14 land 0x0FFF in
      let ethertype = Cstruct.BE.get_uint16 frame 16 in
      match Ethernet_wire.ethertype_of_int ethertype with
      | None ->
        Logs.warn (fun m -> m "unknown ethertype 0x%x in frame" ethertype);
        None
      | Some proto ->
        let payload = Cstruct.shift frame header_size
        and source = Macaddr.of_bytes_exn (Ethernet_wire.copy_ethernet_src frame)
        and destination = Macaddr.of_bytes_exn (Ethernet_wire.copy_ethernet_dst frame)
        in
        Some ({ destination; source; proto; vlan_id}, payload)
    else begin
      Logs.warn (fun m -> m "not a vlan packet");
      None
    end else begin
    Logs.warn (fun m -> m "frame too small to contain a valid vlan header");
    None
  end

let marshal hdr buf =
  Ethernet_wire.set_ethernet_dst (Macaddr.to_bytes hdr.destination) 0 buf;
  Ethernet_wire.set_ethernet_src (Macaddr.to_bytes hdr.source) 0 buf;
  Cstruct.BE.set_uint16 buf 12 0x8100;
  Cstruct.BE.set_uint16 buf 14 (hdr.vlan_id land 0xFFF);
  Cstruct.BE.set_uint16 buf 16 (Ethernet_wire.ethertype_to_int hdr.proto)
