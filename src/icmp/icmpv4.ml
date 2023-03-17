module type S = sig
  type t
  val disconnect : t -> unit Lwt.t
  type ipaddr = Ipaddr.V4.t
  type error
  val pp_error: error Fmt.t
  val input : t -> src:ipaddr -> dst:ipaddr -> Cstruct.t -> unit Lwt.t
  val write : t -> ?src:ipaddr -> dst:ipaddr -> ?ttl:int -> Cstruct.t -> (unit, error) result Lwt.t
end

open Lwt.Infix

let src = Logs.Src.create "icmpv4" ~doc:"Mirage ICMPv4"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (IP : Tcpip.Ip.S with type ipaddr = Ipaddr.V4.t) = struct

  type ipaddr = Ipaddr.V4.t

  type t = {
    ip : IP.t;
    echo_reply : bool;
  }

  type error = [ `Ip of IP.error ]
  let pp_error ppf (`Ip e) = IP.pp_error ppf e

  let connect ip =
    let t = { ip; echo_reply = true } in
    Lwt.return t

  let disconnect _ = Lwt.return_unit

  let writev t ?src ~dst ?ttl bufs =
    IP.write t.ip ?src dst ?ttl `ICMP (fun _ -> 0) bufs >|= function
    | Ok () -> Ok ()
    | Error e ->
      Log.warn (fun f -> f "Error sending IP packet: %a" IP.pp_error e);
      Error (`Ip e)

  let write t ?src ~dst ?ttl buf = writev t ?src ~dst ?ttl [buf]

  let input t ~src ~dst:_ buf =
    let open Icmpv4_packet in
    match Unmarshal.of_cstruct buf with
    | Error s ->
      Log.info (fun f ->
          f "ICMP: error parsing message from %a: %s" Ipaddr.V4.pp src s);
      Lwt.return_unit
    | Ok (message, payload) ->
      match message.ty, message.subheader with
      | Echo_reply, _ ->
        Log.info (fun f ->
            f "ICMP: discarding echo reply from %a" Ipaddr.V4.pp src);
        Lwt.return_unit
      | Destination_unreachable, _ ->
        Log.info (fun f ->
            f "ICMP: destination unreachable from %a" Ipaddr.V4.pp src);
        Lwt.return_unit
      | Echo_request, Id_and_seq (id, seq) ->
        Log.debug (fun f ->
            f "ICMP echo-request received: %a (payload %a)"
              Icmpv4_packet.pp message Cstruct.hexdump_pp payload);
        if t.echo_reply then begin
          let icmp = {
            code = 0x00;
            ty   = Echo_reply;
            subheader = Id_and_seq (id, seq);
          } in
          writev t ~dst:src [ Marshal.make_cstruct icmp ~payload; payload ]
          >|= function
          | Ok () -> ()
          | Error (`Ip e) ->
            Log.warn (fun f -> f "Unable to send ICMP echo-reply: %a" IP.pp_error e); ()
        end else Lwt.return_unit
      | ty, _ ->
        Log.info (fun f ->
            f "ICMP unknown ty %s from %a"
              (Icmpv4_wire.ty_to_string ty) Ipaddr.V4.pp src);
        Lwt.return_unit

end
