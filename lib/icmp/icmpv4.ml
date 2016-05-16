open Result

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

  let input t ~src ~dst buf =
    let should_reply t dst =
      let aux found this =
        match found with
        | true -> true
        | false -> if (Ipaddr.V4.compare dst this) = 0 then true else false
      in
      List.fold_left aux false (IP.get_ip t.ip)
    in
    MProf.Trace.label "icmp_input";
    match Icmpv4_parse.input buf with
    | Result.Error s ->
      Log.info (fun f -> f "ICMP: error parsing message from %a: %s" Ipaddr.V4.pp_hum src s);
      Lwt.return_unit
    | Result.Ok message ->
      let open Icmpv4_wire in
      let open Icmpv4_parse in
      match message.ty, message.subheader with
      | Echo_reply, _ -> Log.info (fun f -> f "ICMP: discarding echo reply from %a" Ipaddr.V4.pp_hum src);
        Lwt.return_unit
      | Destination_unreachable, _ ->
        Log.info (fun f -> f "ICMP: destination unreachable from %a" Ipaddr.V4.pp_hum src);
        Lwt.return_unit
      | Echo_request, Id_and_seq (id, seq) ->
        if t.echo_reply && should_reply t dst then begin
          (* get some memory to write in *)
          let frame, header_len = IP.allocate_frame t.ip ~dst:src ~proto:`ICMP in
          let icmp_chunk = Cstruct.shift frame header_len in
          match Icmpv4_print.echo_reply ~buf:icmp_chunk ?payload:message.payload ~id ~seq with
          | Result.Ok () ->
            let frame = Cstruct.set_len frame header_len in
            IP.write t.ip frame icmp_chunk
          | Result.Error s ->
            Log.info (fun f -> f "Failed to respond to ICMP echo request from %a: %s"
                         Ipaddr.V4.pp_hum src s);
            Lwt.return_unit
        end else Lwt.return_unit
      | ty, _ ->
        Log.info (fun f -> f "ICMP unknown ty %s from %a" (ty_to_string ty) Ipaddr.V4.pp_hum src);
        Lwt.return_unit

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

end
