include Ipv6.Make (Ethif_unix) (OS.Time) (Clock)
let to_string = Ipaddr.V6.to_string ~v4:false
let of_string_exn = Ipaddr.V6.of_string_exn
