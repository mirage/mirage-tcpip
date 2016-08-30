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

let equal p q = (p = q)

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
      let payload = Cstruct.sub buf options_end payload_len in
      Result.Ok ({src; dst; proto; ttl; options;}, payload)
    in
    size_check buf >>= check_version >>= get_header_length >>= parse buf
end
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

  let unsafe_fill ~payload t buf =
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
    set_ipv4_len buf (sizeof_ipv4 + (options_len / 4) + (Cstruct.len payload));
    let checksum = Tcpip_checksum.ones_complement @@ Cstruct.sub buf 0 (20 + options_len) in
    set_ipv4_csum buf checksum


  let into_cstruct ~payload t buf =
    if Cstruct.len buf < (sizeof_ipv4 + Cstruct.len t.options) then
      Result.Error "Not enough space for IPv4 header"
    else begin
      Result.Ok (unsafe_fill ~payload t buf)
    end

  let make_cstruct ~payload t =
    let nearest_4 n = match n mod 4 with
      | 0 -> n
      | k -> (4 - k) + n
    in
    let options_len = nearest_4 @@ Cstruct.len t.options in
    let buf = Cstruct.create (sizeof_ipv4 + options_len) in
    Cstruct.memset buf 0x00; (* should be removable in the future *)
    unsafe_fill ~payload t buf;
    buf
end
