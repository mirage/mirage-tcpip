type t = {
  src     : Ipaddr.V4.t;
  dst     : Ipaddr.V4.t;
  proto   : Cstruct.uint8;
  ttl     : Cstruct.uint8;
  options : Cstruct.t;
}

type protocol = [
  | `ICMP
  | `TCP
  | `UDP ]

let pp fmt t =
  Format.fprintf fmt "IPv4 packet %a -> %a: proto %d, ttl %d, options %a"
    Ipaddr.V4.pp_hum t.src Ipaddr.V4.pp_hum t.dst t.proto t.ttl Cstruct.hexdump_pp t.options

let equal {src; dst; proto; ttl; options} q =
  src = q.src &&
  dst = q.dst &&
  proto = q.proto &&
  ttl = q.ttl &&
  Cstruct.equal options q.options

module Marshal = struct
  open Ipv4_wire

  type error = string

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

  let unsafe_fill ~payload_len t buf =
    let nearest_4 n = match n mod 4 with
      | 0 -> n
      | k -> (4 - k) + n
    in
    let options_len = nearest_4 @@ Cstruct.len t.options in
    set_ipv4_hlen_version buf ((4 lsl 4) + 5 + (options_len / 4));
    set_ipv4_ttl buf t.ttl;
    set_ipv4_proto buf t.proto;
    set_ipv4_src buf (Ipaddr.V4.to_int32 t.src);
    set_ipv4_dst buf (Ipaddr.V4.to_int32 t.dst);
    Cstruct.blit t.options 0 buf sizeof_ipv4 (Cstruct.len t.options);
    set_ipv4_len buf (sizeof_ipv4 + options_len + payload_len);
    let checksum = Tcpip_checksum.ones_complement @@ Cstruct.sub buf 0 (20 + options_len) in
    set_ipv4_csum buf checksum


  let into_cstruct ~payload_len t buf =
    if Cstruct.len buf < (sizeof_ipv4 + Cstruct.len t.options) then
      Result.Error "Not enough space for IPv4 header"
    else begin
      Result.Ok (unsafe_fill ~payload_len t buf)
    end

  let make_cstruct ~payload_len t =
    let nearest_4 n = match n mod 4 with
      | 0 -> n
      | k -> (4 - k) + n
    in
    let options_len = nearest_4 @@ Cstruct.len t.options in
    let buf = Cstruct.create (sizeof_ipv4 + options_len) in
    Cstruct.memset buf 0x00; (* should be removable in the future *)
    unsafe_fill ~payload_len t buf;
    buf
end
module Unmarshal = struct
  type error = string

  let int_to_protocol = function
    | 1  -> Some `ICMP
    | 6  -> Some `TCP
    | 17 -> Some `UDP
    | _  -> None

  let of_cstruct buf =
    let open Rresult in
    let open Ipv4_wire in
    let check_version buf =
      let version n = (n land 0xf0) in
      match get_ipv4_hlen_version buf |> version with
      | 0x40 -> Result.Ok buf
      | n -> Result.Error (Printf.sprintf "IPv4 presented with a packet that claims a different IP version: %x" n)
    in
    let size_check buf =
      if (Cstruct.len buf < sizeof_ipv4) then Result.Error "buffer sent to IPv4 parser had size < 20"
      else Result.Ok buf
    in
    let get_header_length buf =
      let length_of_hlen_version n = (n land 0x0f) * 4 in
      let hlen = get_ipv4_hlen_version buf |> length_of_hlen_version in
        if (get_ipv4_len buf) < sizeof_ipv4 then
          Result.Error (Printf.sprintf
                          "total length %d is smaller than minimum header length"
                          (get_ipv4_len buf))
        else if get_ipv4_len buf < hlen then
          Result.Error (Printf.sprintf
                          "total length %d is smaller than stated header length %d"
                          (get_ipv4_len buf) hlen)
        else if hlen < sizeof_ipv4 then Result.Error
          (Printf.sprintf "IPv4 header claimed to have size < 20: %d" hlen)
        else if Cstruct.len buf < hlen then Result.Error
          (Printf.sprintf "IPv4 packet w/length %d claimed to have header of size %d" (Cstruct.len buf) hlen)
        else Result.Ok hlen
    in
    let parse buf options_end =
      let payload_len = (get_ipv4_len buf) - options_end in
      let src = Ipaddr.V4.of_int32 (get_ipv4_src buf) in
      let dst = Ipaddr.V4.of_int32 (get_ipv4_dst buf) in
      let proto = get_ipv4_proto buf in
      let ttl = get_ipv4_ttl buf in
      let options =
        if options_end > sizeof_ipv4 then (Cstruct.sub buf sizeof_ipv4 (options_end - sizeof_ipv4))
        else (Cstruct.create 0)
      in
      let payload_available = Cstruct.len buf - options_end in
      if payload_available < payload_len then (
        Error (Printf.sprintf "Payload buffer (%d bytes) too small to contain payload (of size %d from header)" payload_available payload_len)
      ) else (
        let payload = Cstruct.sub buf options_end payload_len in
        Ok ({src; dst; proto; ttl; options;}, payload)
      )
    in
    size_check buf >>= check_version >>= get_header_length >>= parse buf

  let verify_transport_checksum ~proto ~ipv4_header ~transport_packet =
    (* note: it's not necessary to ensure padding to integral number of 16-bit fields here; ones_complement_list does this for us *)
    let check ~proto ipv4_header len =
      try
        let ph = Marshal.pseudoheader ~src:ipv4_header.src ~dst:ipv4_header.dst ~proto len in
        let calculated_checksum = Tcpip_checksum.ones_complement_list [ph ; transport_packet] in
        0 = compare 0x0000 calculated_checksum
      with
      | Invalid_argument _ -> false
    in
    match proto with
    | `TCP -> (* checksum isn't optional in tcp, but pkt must be long enough *)
      check ipv4_header ~proto (Cstruct.len transport_packet)
    | `UDP ->
      match Udp_wire.get_udp_checksum transport_packet with
      | n when (=) 0 @@ compare n 0x0000 -> true (* no checksum supplied, so the check trivially passes *)
      | _ ->
        check ipv4_header ~proto (Cstruct.len transport_packet)

end
