let src = Logs.Src.create "icmpv4" ~doc:"Mirage ICMPv4"
module Log = (val Logs.src_log src : Logs.LOG)

module Make(IP : V1_LWT.IPV4) = struct
  type buffer = Cstruct.t
  type 'a io = 'a Lwt.t
  type ipaddr = Ipaddr.V4.t

  type t = {
    ip : IP.t;
    echo_reply : bool;
  }

  type error = [ `Routing | `Unknown ]

  type id = t

  let connect ip = Lwt.return (`Ok { ip; echo_reply = true; })

  let disconnect _ = Lwt.return_unit

  let pp_error formatter = function
    | `Routing -> Format.fprintf formatter "%s" "routing"
    | `Unknown -> Format.fprintf formatter "%s" "unknown!"

  let writev t ~dst bufs = 
    let frame, header_len = IP.allocate_frame t.ip ~dst ~proto:`ICMP in
    let frame = Cstruct.set_len frame header_len in
    IP.writev t.ip frame bufs

  let write t ~dst buf = writev t ~dst [buf]

  let input t ~src ~dst buf =
    let open Icmpv4_packet in
    let should_reply t dst =
      let aux found this =
        match found with
        | true -> true
        | false -> if (Ipaddr.V4.compare dst this) = 0 then true else false
      in
      List.fold_left aux false (IP.get_ip t.ip)
    in
    MProf.Trace.label "icmp_input";
    match Unmarshal.of_cstruct buf with
    | Result.Error s ->
      Log.info (fun f -> f "ICMP: error parsing message from %a: %s" Ipaddr.V4.pp_hum src s);
      Lwt.return_unit
    | Result.Ok (message, payload) ->
      let open Icmpv4_wire in
      match message.ty, message.subheader with
      | Echo_reply, _ -> Log.info (fun f -> f "ICMP: discarding echo reply from %a" Ipaddr.V4.pp_hum src);
        Lwt.return_unit
      | Destination_unreachable, _ ->
        Log.info (fun f -> f "ICMP: destination unreachable from %a" Ipaddr.V4.pp_hum src);
        Lwt.return_unit
      | Echo_request, Id_and_seq (id, seq) ->
        Log.debug (fun f -> f "ICMP echo-request received: %a (payload %a)"  Icmpv4_packet.pp message Cstruct.hexdump_pp payload);
        if t.echo_reply && should_reply t dst then begin
          let icmp = { code = 0x00;
		       ty   = Icmpv4_wire.Echo_reply;
		       subheader = Id_and_seq (id, seq);
		     } in
          writev t ~dst:src [ Marshal.make_cstruct icmp ~payload; payload ]
        end else Lwt.return_unit
      | ty, _ ->
        Log.info (fun f -> f "ICMP unknown ty %s from %a" (ty_to_string ty) Ipaddr.V4.pp_hum src);
        Lwt.return_unit

end
