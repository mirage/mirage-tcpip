(* RFC 1112: 01-00-5E-00-00-00 ORed with lower 23 bits of the ip address *)
let mac_of_multicast ip =
  let ipb = Ipaddr.V4.to_bytes ip in
  let macb = Bytes.create 6 in
  Bytes.set macb 0 (Char.chr 0x01);
  Bytes.set macb 1 (Char.chr 0x00);
  Bytes.set macb 2 (Char.chr 0x5E);
  Bytes.set macb 3 (Char.chr ((Char.code ipb.[1]) land 0x7F));
  Bytes.set macb 4 (Bytes.get ipb 2);
  Bytes.set macb 5 (Bytes.get ipb 3);
  Macaddr.of_bytes_exn macb

exception No_route_to_destination_address of Ipaddr.V4.t

module Make(Log : Logs.LOG) (A : V1_LWT.ARP) = struct
  open Lwt.Infix

  let destination_mac network gateway arp = function
    |ip when ip = Ipaddr.V4.broadcast || ip = Ipaddr.V4.any -> (* Broadcast *)
      Lwt.return Macaddr.broadcast
    |ip when Ipaddr.V4.is_multicast ip ->
      Lwt.return (mac_of_multicast ip)
    |ip when Ipaddr.V4.Prefix.mem ip network -> (* Local *)
      A.query arp ip >>= begin function
        | `Ok mac -> Lwt.return mac
        | `Timeout ->
          Log.info (fun f -> f "IP.output: could not determine link-layer address for local network (%a) ip %a" Ipaddr.V4.Prefix.pp_hum network Ipaddr.V4.pp_hum ip);
          Lwt.fail (No_route_to_destination_address ip)
      end
    |ip -> (* Gateway *)
      match gateway with
      | None ->
          Log.info (fun f -> f "IP.output: no route to %a (no default gateway is configured)" Ipaddr.V4.pp_hum ip);
          Lwt.fail (No_route_to_destination_address ip)
      | Some gateway ->
        A.query arp gateway >>= function
          | `Ok mac -> Lwt.return mac
          | `Timeout ->
            Log.info (fun f -> f "IP.output: could not send to %a: failed to contact gateway %a"
                         Ipaddr.V4.pp_hum ip Ipaddr.V4.pp_hum gateway);
            Lwt.fail (No_route_to_destination_address ip)
end
