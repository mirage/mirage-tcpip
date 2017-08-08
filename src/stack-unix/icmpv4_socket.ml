open Lwt.Infix

type ipaddr = Ipaddr.V4.t
type buffer = Cstruct.t
type 'a io = 'a Lwt.t

type t = unit

type error = [ `Ip of string ]
let pp_error ppf (`Ip s) = Fmt.string ppf s

let is_win32 = Sys.os_type = "Win32"

let sock_icmp =
  (* Windows uses SOCK_RAW protocol 1 for ICMP
     Unix uses SOCK_DGRAM protocol 1 for ICMP *)
  if is_win32 then Lwt_unix.SOCK_RAW else Lwt_unix.SOCK_DGRAM

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

let sendto' fd buf flags dst =
  if is_win32 then begin
     (* Lwt on Win32 doesn't support Lwt_bytes.sendto *)
     let bytes = Bytes.make (Cstruct.len buf) '\000' in
     Cstruct.blit_to_bytes buf 0 bytes 0 (Cstruct.len buf);
     Lwt_unix.sendto fd bytes 0 (Bytes.length bytes) flags dst
  end else Lwt_cstruct.sendto fd buf flags dst

let recvfrom' fd buf flags =
  if is_win32 then begin
    (* Lwt on Win32 doesn't support Lwt_bytes.recvfrom *)
    let bytes = Bytes.make (Cstruct.len buf) '\000' in
    Lwt_unix.recvfrom fd bytes 0 (Bytes.length bytes) flags
    >>= fun (n, sockaddr) ->
    Cstruct.blit_from_bytes bytes 0 buf 0 n;
    Lwt.return (n, sockaddr)
  end else Lwt_cstruct.recvfrom fd buf flags

let write _t ~dst buf =
  let open Lwt_unix in
  let flags = [] in
  let ipproto_icmp = 1 in (* according to BSD /etc/protocols *)
  let port = 0 in (* port isn't meaningful in this context *)
  let fd = socket PF_INET sock_icmp ipproto_icmp in
  let in_addr = Unix.inet_addr_of_string (Ipaddr.V4.to_string dst) in
  let sockaddr = ADDR_INET (in_addr, port) in
  Lwt.catch (fun () ->
    sendto' fd buf flags sockaddr >>= fun sent ->
      if (sent <> (Cstruct.len buf)) then
        Log.debug (fun f -> f "short write: %d received vs %d expected" sent (Cstruct.len buf));
    Lwt_unix.close fd |> Lwt_result.ok
  ) (fun exn -> Lwt.return @@ Error (`Ip (Printexc.to_string exn)))

let input t ~src ~dst:_ buf =
  (* some default logic -- respond to echo requests with echo replies *)
  match Icmpv4_packet.Unmarshal.of_cstruct buf with
  | Result.Error s ->
    let s = "Error decomposing an ICMP packet: " ^ s in
    Logs.debug (fun f -> f "%s" s);
    Lwt.return_unit
  | Result.Ok (icmp, payload) ->
    let open Icmpv4_packet in
    match icmp.ty, icmp.subheader with
    | Icmpv4_wire.Echo_request, Id_and_seq (id, seq) ->
      let response =
          { ty = Icmpv4_wire.Echo_reply;
            code = 0x00;
            subheader = Id_and_seq (id, seq); } in
      (* TODO: if `listen` were allowed to report problems,
       * it would be sensible not to discard the value returned here,
       * but as it is we can only return () *)
      write t ~dst:src (Marshal.make_cstruct response ~payload) >>= fun _ -> Lwt.return_unit
    | _, _ -> Lwt.return_unit

let listen _t addr fn =
  let fd = Lwt_unix.socket PF_INET sock_icmp ipproto_icmp in
  Lwt.finalize
    (fun () ->
      let sa = Lwt_unix.ADDR_INET (Unix.inet_addr_of_string (Ipaddr.V4.to_string addr), port) in
      Lwt_unix.bind fd sa >>= fun () ->
      Log.debug (fun f -> f "Bound ICMP file descriptor to %a" pp_sockaddr sa);
      let rec loop () =
        let receive_buffer = Cstruct.create 4096 in
        recvfrom' fd receive_buffer [] >>= fun (len, _sockaddr) ->
        (* trim the buffer to the amount of data actually received *)
        let receive_buffer = Cstruct.set_len receive_buffer len in
        (* On macOS the IP length field is set to a very large value (16384) which
           probably reflects some kernel datastructure size rather than the real
           on-the-wire size. This confuses our IPv4 parser so we correct the size
           here. *)
        let len = Ipv4_wire.get_ipv4_len receive_buffer in
        Ipv4_wire.set_ipv4_len receive_buffer (min len (Cstruct.len receive_buffer));
        Lwt.async (fun () -> fn receive_buffer);
        loop ()
      in
      loop ()
    ) (fun () ->
      Lwt_unix.close fd
    )