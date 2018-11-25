[%%cstruct
type ethernet = {
    dst: uint8_t        [@len 6];
    src: uint8_t        [@len 6];
    ethertype: uint16_t;
  } [@@big_endian]
]


let ethertype_to_int, ethertype_of_int =
  let (alist : (Mirage_protocols.Ethernet.Proto.t * int) list) =
    [ (`ARP, 0x0806) ; (`IPv4, 0x0800) ; (`IPv6, 0x86dd) ]
  in
  let rev = List.map (fun (a, b) -> (b, a)) alist in
  (fun x -> List.assoc x alist),
  (fun i -> try Some (List.assoc i rev) with Not_found -> None)
