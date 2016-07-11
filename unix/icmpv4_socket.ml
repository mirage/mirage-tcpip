open Lwt.Infix

type ipaddr = Ipaddr.V4.t
type buffer = Cstruct.t
type 'a io = 'a Lwt.t

type t = unit

type id = t

type error = string

let pp_error fmt err = Format.asprintf fmt "%s" err

let ip_proto = 1 (* according to BSD /etc/protocols *)
let port = 0 (* port isn't meaningful in this context *)

let connect () = Lwt.return_unit

let pp_sockaddr fmt sa =
  let open Lwt_unix in
  match sa with
  | ADDR_UNIX s -> Format.fprintf fmt "%s" s
  | ADDR_INET (ip, port) -> Format.fprintf fmt "%s, %d" (Unix.string_of_inet_addr ip) port

let input t ~src ~dst buf =
  Printf.printf "YAY I GOT A THING";
  Lwt.return_unit

let listen t =
  let open Lwt_unix in
  let fd = socket PF_INET SOCK_DGRAM ip_proto in
  let receive_buffer = Cstruct.create 4096 in
  Lwt_cstruct.recvfrom fd receive_buffer [] >>= fun (len, sockaddr) ->
  (* trim the buffer to the amount of data actually received *)
  let receive_buffer = Cstruct.set_len receive_buffer len in
  Format.printf "received an icmp packet from %a: %s" pp_sockaddr sockaddr
    (Cstruct.to_string receive_buffer);
  close fd

let write t ~dst buf =
  let open Lwt_unix in
  let flags = [] in
  let ip_proto = 1 in (* according to BSD /etc/protocols *)
  let port = 0 in (* port isn't meaningful in this context *)
  let fd = socket PF_INET SOCK_DGRAM ip_proto in
  let sockaddr = ADDR_INET (Unix.inet_addr_of_string (Ipaddr.V4.to_bytes dst), port) in
  Lwt_cstruct.sendto fd buf flags sockaddr >>= fun _sent ->
  (* TODO: log short reads? *)
  Lwt_unix.close fd

