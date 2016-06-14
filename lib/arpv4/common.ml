module Make(Ethif : V1_LWT.ETHIF) (Log : Logs.LOG) = struct
  type result = [ `Ok of Macaddr.t | `Timeout ]

  type entry =
    | Pending of result Lwt.t * result Lwt.u
    | Confirmed of float * Macaddr.t

  type t = {
    ethif : Ethif.t;
    cache: (Ipaddr.V4.t, entry) Hashtbl.t;
    mutable bound_ips: Ipaddr.V4.t list;
  }

  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t
  type ipaddr = Ipaddr.V4.t
  type macaddr = Macaddr.t
  type ethif = Ethif.t
  type repr = string
  type id = t
  type error

  let output t arp =
    (* Obtain a buffer to write into *)
    let payload = Arpv4_packet.Marshal.make_cstruct arp in
    let ethif_packet = Ethif_packet.(Marshal.make_cstruct {
        source = arp.sha;
        destination = arp.tha;
        ethertype = Ethif_wire.ARP;
      }) in
    Ethif.writev t.ethif [ethif_packet ; payload]

  (* Send a gratuitous ARP for our IP addresses *)
  let output_garp t =
    let tha = Macaddr.broadcast in
    let sha = Ethif.mac t.ethif in
    let tpa = Ipaddr.V4.any in
    Lwt_list.iter_s (fun spa ->
        Log.info (fun f -> f "ARP: sending gratuitous from %a" Ipaddr.V4.pp_hum spa);
        output t Arpv4_packet.({ op=Arpv4_wire.Reply; tha; sha; tpa; spa })
      ) t.bound_ips

  (* Send a query for a particular IP *)
  let output_probe t tpa =
    Log.info (fun f -> f "ARP: transmitting probe -> %a" Ipaddr.V4.pp_hum tpa);
    let tha = Macaddr.broadcast in
    let sha = Ethif.mac t.ethif in
    (* Source protocol address, pick one of our IP addresses *)
    let spa = match t.bound_ips with
      | hd::_ -> hd | [] -> Ipaddr.V4.any in
    output t Arpv4_packet.({ op=Arpv4_wire.Request; tha; sha; tpa; spa })

  let answer_query t query =
    let open Arpv4_packet in
    let sha = Ethif.mac t.ethif in
    let tha = query.sha in
    let spa = query.tpa in (* the requested address *)
    let tpa = query.spa in (* the requesting host IPv4 *)
    Arpv4_wire.{ op=Reply; sha; tha; spa; tpa }

  let get_ips t = t.bound_ips

  (* Set the bound IP address list, which will xmit GARP packets also *)
  let set_ips t ips =
    t.bound_ips <- (List.sort_uniq Ipaddr.V4.compare ips);
    output_garp t

  let add_ip t ip =
    if not (List.mem ip t.bound_ips) then
      set_ips t (ip :: t.bound_ips)
    else Lwt.return_unit

  let remove_ip t ip =
    if List.mem ip t.bound_ips then
      set_ips t (List.filter ((<>) ip) t.bound_ips)
    else Lwt.return_unit

  let connect ethif =
    let cache = Hashtbl.create 7 in
    let bound_ips = [] in
    Log.info (fun f -> f "Connected arpv4 device on %s" (Macaddr.to_string @@
                                                         Ethif.mac ethif));
    let t = { ethif; cache; bound_ips } in
    t

  let to_repr t =
    let print ip entry acc =
      let key = Ipaddr.V4.to_string ip in
      match entry with
       | Pending _ -> acc ^ "\n" ^ key ^ " -> " ^ "Pending" 
       | Confirmed (time, mac) -> Printf.sprintf "%s\n%s -> Confirmed (%s) (expires %f)\n%!" 
                                    acc key (Macaddr.to_string mac) time
    in
    Lwt.return (Hashtbl.fold print t.cache "")

  let pp fmt repr =
    Format.fprintf fmt "%s" repr

end
