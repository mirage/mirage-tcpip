(* RFC 1112: 01-00-5E-00-00-00 ORed with lower 23 bits of the ip address *)
let mac_of_multicast ip =
  let ipb = Ipaddr.V4.to_octets ip in
  let macb = Bytes.create 6 in
  Bytes.set macb 0 (Char.chr 0x01);
  Bytes.set macb 1 (Char.chr 0x00);
  Bytes.set macb 2 (Char.chr 0x5E);
  Bytes.set macb 3 (Char.chr (Char.code ipb.[1] land 0x7F));
  Bytes.set macb 4 (String.get ipb 2);
  Bytes.set macb 5 (String.get ipb 3);
  Macaddr.of_octets_exn (Bytes.to_string macb)

type routing_error = [ `Local | `Gateway ]

module Make (Log : Logs.LOG) (A : Arp.S) = struct
  open Lwt.Infix

  let destination_mac network gateway arp = function
    | ip
      when Ipaddr.V4.(compare ip broadcast) = 0
           || Ipaddr.V4.(compare ip any) = 0
           || Ipaddr.V4.(compare (Prefix.broadcast network) ip) = 0 ->
        (* Broadcast *)
        Lwt.return @@ Ok Macaddr.broadcast
    | ip when Ipaddr.V4.is_multicast ip ->
        Lwt.return @@ Ok (mac_of_multicast ip)
    | ip when Ipaddr.V4.Prefix.mem ip network -> (
        (* Local *)
        A.query arp ip >|= function
        | Ok mac -> Ok mac
        | Error `Timeout ->
            Log.info (fun f ->
                f
                  "IP.output: could not determine link-layer address for local \
                   network (%a) ip %a"
                  Ipaddr.V4.Prefix.pp network Ipaddr.V4.pp ip);
            Error `Local
        | Error e ->
            Log.info (fun f -> f "IP.output: %a" A.pp_error e);
            Error `Local)
    | ip -> (
        (* Gateway *)
        match gateway with
        | None ->
            Log.info (fun f ->
                f "IP.output: no route to %a (no default gateway is configured)"
                  Ipaddr.V4.pp ip);
            Lwt.return (Error `Gateway)
        | Some gateway -> (
            A.query arp gateway >|= function
            | Ok mac -> Ok mac
            | Error `Timeout ->
                Log.info (fun f ->
                    f
                      "IP.output: could not send to %a: failed to contact \
                       gateway %a"
                      Ipaddr.V4.pp ip Ipaddr.V4.pp gateway);
                Error `Gateway
            | Error e ->
                Log.info (fun f -> f "IP.output: %a" A.pp_error e);
                Error `Gateway))
end
