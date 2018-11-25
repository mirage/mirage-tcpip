open Lwt.Infix

let src = Logs.Src.create "vlan" ~doc:"Mirage VLAN"
module Log = (val Logs.src_log src : Logs.LOG)

module Make(Netif : Mirage_net_lwt.S) = struct

  module Vlan_ethernet = struct
    type 'a io = 'a Lwt.t
    type buffer = Cstruct.t
    type macaddr = Macaddr.t

    type error = Netif.error
    let pp_error = Netif.pp_error

    type callback = source:macaddr -> macaddr -> buffer -> unit io

    module M = Map.Make(Mirage_protocols.Ethernet.Proto)

    type t = {
      netif: Netif.t;
      vlan: int;
      mutable callbacks : callback M.t
    }

    let header_size _t = Vlan_packet.header_size
    let mac t = Netif.mac t.netif
    let mtu t = Netif.mtu t.netif - Vlan_packet.header_size

    let allocate_frame ?size t =
      let size = match size with None -> None | Some x -> Some (x + Vlan_packet.header_size) in
      Netif.allocate_frame ?size t.netif, Vlan_packet.header_size

    let register t proto callback =
      match M.find_opt proto t.callbacks with
      | None ->
        Log.info (fun m -> m "registering new callback for %a" Mirage_protocols.Ethernet.Proto.pp proto) ;
        t.callbacks <- M.add proto callback t.callbacks ;
        Ok ()
      | Some _ ->
        Log.err (fun m -> m "callback for %a already registered" Mirage_protocols.Ethernet.Proto.pp proto) ;
        Error `Conflict

    let receive t hdr payload =
      match M.find_opt hdr.Vlan_packet.proto t.callbacks with
      | None ->
        Log.debug (fun m -> m "received frame %a, but nobody is listening" Vlan_packet.pp hdr);
        Lwt.return_unit
      | Some f ->
        f ~source:hdr.source hdr.destination payload

    let input _t _f _frame = assert false

    let write t proto ?source destination frame =
      MProf.Trace.label "vlan.write";
      let source = match source with None -> mac t | Some s -> s in
      let hdr = Vlan_packet.{ vlan_id = t.vlan ; source ; destination ; proto } in
      Vlan_packet.marshal hdr frame;
      Netif.write t.netif frame >|= function
      | Ok () -> Ok ()
      | Error e ->
        Log.warn (fun f -> f "netif write errored %a" Netif.pp_error e) ;
        Error e

    let connect netif vlan = { netif ; vlan ; callbacks = M.empty }

    let disconnect _t =
      Log.info (fun f -> f "Disconnected vlan_ethernet interface");
      Lwt.return_unit
  end

  module M = Map.Make(struct type t = int let compare (a:int) (b:int) = compare a b end)

  type t = {
    netif: Netif.t;
    mutable callbacks: Vlan_ethernet.t M.t;
  }

  let register t vlan_id =
    match M.find_opt vlan_id t.callbacks with
    | None ->
      Log.info (fun m -> m "registering vlan id %d" vlan_id);
      let vlan_ethernet = Vlan_ethernet.connect t.netif vlan_id in
      t.callbacks <- M.add vlan_id vlan_ethernet t.callbacks;
      Ok vlan_ethernet
    | Some _ ->
      Log.err (fun m -> m "vlan id %d already registered" vlan_id);
      Error `Conflict

  let process t frame =
    MProf.Trace.label "vlan.process";
    let of_interest dest =
      Macaddr.compare dest (Netif.mac t.netif) = 0 || not (Macaddr.is_unicast dest)
    in
    match Vlan_packet.unmarshal frame with
    | None -> None
    | Some (hdr, payload) ->
      if of_interest hdr.destination then
        Some (hdr, payload)
      else begin
        Log.debug (fun m -> m "ignoring ethernet frame %a (not of interest)" Vlan_packet.pp hdr);
        None
      end

  let receive t frame =
    match process t frame with
    | None -> Lwt.return_unit
    | Some (hdr, payload) ->
      match M.find_opt hdr.vlan_id t.callbacks with
      | None ->
        Log.debug (fun m -> m "received frame %a, but nobody is listening" Vlan_packet.pp hdr);
        Lwt.return_unit
      | Some eth -> Vlan_ethernet.receive eth hdr payload

  let connect netif =
    let t = { netif ; callbacks = M.empty } in
    Log.info (fun f -> f "Connected vlan interface %s" (Macaddr.to_string (Netif.mac netif)));
    Lwt.async (fun () -> Netif.listen netif (receive t) >|= function
      | Error e -> Log.err (fun p -> p "%a" Netif.pp_error e)
      | Ok () -> ()) ;
    Lwt.return t
end
