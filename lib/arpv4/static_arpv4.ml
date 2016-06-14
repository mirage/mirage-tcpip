let src = Logs.Src.create "static_arpv4" ~doc:"Mirage static ARP module"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (Ethif : V1_LWT.ETHIF) = struct

  module Generic_arp = Common.Make(Ethif)(Log)
  include Generic_arp
  
  let query t ip =
    match Hashtbl.mem t.cache ip with
    | false -> Lwt.return `Timeout
    | true ->
      match Hashtbl.find t.cache ip with
      | Pending _ -> Lwt.return `Timeout
      | Confirmed (_, macaddr) -> Lwt.return (`Ok macaddr)

  let (>>=?) f g =
    match f with
    | Result.Ok x -> g x
    | Result.Error _ -> Lwt.return_unit

  let input t buffer =
    let open Result in
    (* reply to queries, but disregard all other messages *)
    Arpv4_packet.Unmarshal.of_cstruct buffer >>=? fun arp ->
    match arp.op with
    | Arpv4_wire.Reply -> Lwt.return_unit
    | Arpv4_wire.Request ->
      match List.mem arp.tpa t.bound_ips with
      | false -> Lwt.return_unit
      | true ->
        output t (Generic_arp.answer_query t arp)

  let add_entry t ip mac =
    Hashtbl.add t.cache ip Generic_arp.(Confirmed (0.0, mac))

  let remove_entry t ip =
    match Hashtbl.mem t.cache ip with
    | true -> Hashtbl.remove t.cache ip; true
    | false -> false

  let connect ethif =
    Lwt.return @@ `Ok (Generic_arp.connect ethif)

  let disconnect t =
    Log.info (fun f -> f "Disconnected arpv4 device on %s" (Macaddr.to_string (
               Ethif.mac t.ethif)));
    Lwt.return_unit

end
