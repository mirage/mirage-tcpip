open Ethif_wire

type t = {
  source : Macaddr.t;
  destination : Macaddr.t;
  ethertype : Ethif_wire.ethertype;
  payload : Cstruct.t; (* bare ethernet frames not allowed *)
}

type error = string

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
      Result.Ok { destination; source; ethertype; payload }
  else
    Result.Error "frame too small to contain a valid ethernet header"
