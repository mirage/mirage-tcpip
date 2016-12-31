open Lwt.Infix
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

  type error = [ V1.Icmp.error | `Ip of IP.error ]

  let pp_error ppf = function
    | #V1.Icmp.error as e -> Mirage_pp.pp_icmp_error ppf e
    | `Ip e -> IP.pp_error ppf e

  let connect ip =
    let t = { ip; echo_reply = true } in
    Lwt.return t

  let disconnect _ = Lwt.return_unit

  let no_route dst = `Routing (Fmt.strf "no route to %a" Ipaddr.V4.pp_hum dst)

  let writev t ~dst bufs : (unit, error) result Lwt.t =
    let frame, header_len = IP.allocate_frame t.ip ~dst ~proto:`ICMP in
    let frame = Cstruct.set_len frame header_len in
    IP.writev t.ip frame bufs >|= function
    | Ok ()           -> Ok ()
    | Error `No_route -> Error (no_route dst)
    | Error e         -> Error (`Ip e)

  let write t ~dst buf = writev t ~dst [buf]

  let input t ~src ~dst buf =
    let open Icmpv4_packet in
    let should_reply t dst = List.mem dst @@ IP.get_ip t.ip in
    MProf.Trace.label "icmp_input";
    match Unmarshal.of_cstruct buf with
    | Result.Error s ->
      Log.info (fun f ->
          f "ICMP: error parsing message from %a: %s" Ipaddr.V4.pp_hum src s);
      Lwt.return_unit
    | Result.Ok (message, payload) ->
      let open Icmpv4_wire in
      match message.ty, message.subheader with
      | Echo_reply, _ ->
        Log.info (fun f ->
            f "ICMP: discarding echo reply from %a" Ipaddr.V4.pp_hum src);
        Lwt.return_unit
      | Destination_unreachable, _ ->
        Log.info (fun f ->
            f "ICMP: destination unreachable from %a" Ipaddr.V4.pp_hum src);
        Lwt.return_unit
      | Echo_request, Id_and_seq (id, seq) ->
        Log.debug (fun f ->
            f "ICMP echo-request received: %a (payload %a)"
              Icmpv4_packet.pp message Cstruct.hexdump_pp payload);
        if t.echo_reply && should_reply t dst then begin
          let icmp = {
            code = 0x00;
            ty   = Icmpv4_wire.Echo_reply;
            subheader = Id_and_seq (id, seq);
          } in
          writev t ~dst:src [ Marshal.make_cstruct icmp ~payload; payload ]
          >|= function
            (* this handler will change when input gets a richer type
               that can return error *)
          | Ok () -> ()
          | Error e ->
            Log.warn (fun f ->
                f "Unable to send ICMP echo-reply: %a" pp_error e);
            ()
        end else Lwt.return_unit
      | ty, _ ->
        Log.info (fun f ->
            f "ICMP unknown ty %s from %a"
              (ty_to_string ty) Ipaddr.V4.pp_hum src);
        Lwt.return_unit

end
