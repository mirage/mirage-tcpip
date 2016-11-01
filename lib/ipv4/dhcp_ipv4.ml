open Lwt.Infix
open V1_LWT

module Make(Dhcp_client : DHCP_CLIENT) (Ethif : ETHIF)(Arp : ARP) = struct
  (* for now, just wrap a static ipv4 *)
  module I = Static_ipv4.Make(Ethif)(Arp)
  include I
  let connect dhcp ethif arp =
    Lwt_stream.last_new dhcp >>= fun (config : ipv4_config) ->
    I.connect ~ip:config.address ~network:config.network ~gateway:config.gateway ethif arp
end
