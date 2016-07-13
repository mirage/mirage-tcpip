open Lwt.Infix

type ipaddr = Ipaddr.V4.t
type buffer = Cstruct.t
type 'a io = 'a Lwt.t

type t = unit

type id = t

type error = string

let pp_error fmt err = Format.fprintf fmt "%s" err

let ipproto_icmp = 1 (* according to BSD /etc/protocols *)
let port = 0 (* port isn't meaningful in this context *)

let connect () = Lwt.return_unit
let disconnect () = Lwt.return_unit

let pp_sockaddr fmt sa =
  let open Lwt_unix in
  match sa with
  | ADDR_UNIX s -> Format.fprintf fmt "%s" s
  | ADDR_INET (ip, port) -> Format.fprintf fmt "%s, %d" (Unix.string_of_inet_addr ip) port

let src = Logs.Src.create "icmpv4_socket" ~doc:"Mirage ICMPv4 (Sockets Edition)"
module Log = (val Logs.src_log src : Logs.LOG)

let write _t ~dst buf =
  let open Lwt_unix in
  let flags = [] in
  let ipproto_icmp = 1 in (* according to BSD /etc/protocols *)
  let port = 0 in (* port isn't meaningful in this context *)
  let fd = socket PF_INET SOCK_DGRAM ipproto_icmp in
  let in_addr = Unix.inet_addr_of_string (Ipaddr.V4.to_string dst) in
  let sockaddr = ADDR_INET (in_addr, port) in
  Lwt_cstruct.sendto fd buf flags sockaddr >>= fun sent ->
          Log.debug (fun f -> f "short write: %d received vs %d expected" sent (Cstruct.len buf));
  Lwt_unix.close fd

let input t ~src ~dst:_ buf =
  (* some default logic -- respond to echo requests with echo replies *)
  match Icmpv4_packet.Unmarshal.of_cstruct buf with
  | Result.Error s -> Logs.debug (fun f -> f "Error decomposing an ICMP packet: %s" s); Lwt.return_unit
  | Result.Ok (icmp, payload) ->
    let open Icmpv4_packet in
    match icmp.ty, icmp.subheader with
    | Icmpv4_wire.Echo_request, Id_and_seq (id, seq) ->
      let response =
          { ty = Icmpv4_wire.Echo_reply;
            code = 0x00;
            subheader = Id_and_seq (id, seq); } in
      write t ~dst:src (Marshal.make_cstruct response ~payload)
    | _, _ -> Lwt.return_unit

let listen _t addr fn =
  let fd = Lwt_unix.(socket PF_INET SOCK_DGRAM) ipproto_icmp in
  let sa = Lwt_unix.ADDR_INET (Unix.inet_addr_of_string (Ipaddr.V4.to_string addr), port) in
  let () = Lwt_unix.bind fd sa in
  Log.debug (fun f -> f "Bound ICMP file descriptor to %a" pp_sockaddr sa);
  let aux fn = 
    let receive_buffer = Cstruct.create 4096 in
    Lwt_cstruct.recvfrom fd receive_buffer [] >>= fun (len, _sockaddr) ->
    (* trim the buffer to the amount of data actually received *)
    let receive_buffer = Cstruct.set_len receive_buffer len in
    fn receive_buffer
  in
  aux fn >>= fun () -> Lwt_unix.close fd

