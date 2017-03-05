open Ethif_wire

type t = {
  source : Macaddr.t;
  destination : Macaddr.t;
  ethertype : Ethif_wire.ethertype;
}

type error = string

let pp fmt t =
  Format.fprintf fmt "%s -> %s: %s" (Macaddr.to_string t.source)
    (Macaddr.to_string t.destination) (Ethif_wire.ethertype_to_string t.ethertype)

let equal {source; destination; ethertype} q =
  (Macaddr.compare source q.source) = 0 &&
  (Macaddr.compare destination q.destination) = 0 &&
  Ethif_wire.(compare (ethertype_to_int ethertype) (ethertype_to_int q.ethertype)) = 0

module Unmarshal = struct

  let of_cstruct frame =
    if Cstruct.len frame >= sizeof_ethernet then
      match get_ethernet_ethertype frame |> int_to_ethertype with
      | None -> Result.Error (Printf.sprintf "unknown ethertype 0x%x in frame"
                                (get_ethernet_ethertype frame))
      | Some ethertype ->
        let payload = Cstruct.shift frame sizeof_ethernet
        and source = Macaddr.of_bytes_exn (copy_ethernet_src frame)
        and destination = Macaddr.of_bytes_exn (copy_ethernet_dst frame)
        in
        Result.Ok ({ destination; source; ethertype;}, payload)
    else
      Result.Error "frame too small to contain a valid ethernet header"
end

module Marshal = struct
  open Rresult

  let check_len buf =
    if sizeof_ethernet > Cstruct.len buf then
      Result.Error "Not enough space for an Ethernet header"
    else Result.Ok ()

  let unsafe_fill t buf =
    set_ethernet_dst (Macaddr.to_bytes t.destination) 0 buf;
    set_ethernet_src (Macaddr.to_bytes t.source) 0 buf;
    set_ethernet_ethertype buf (ethertype_to_int t.ethertype);
    ()

  let into_cstruct t buf =
    check_len buf >>= fun () ->
    Result.Ok (unsafe_fill t buf)

  let make_cstruct t =
    let buf = Cstruct.create sizeof_ethernet in
    Cstruct.memset buf 0x00; (* can be removed in the future *)
    unsafe_fill t buf;
    buf
end
