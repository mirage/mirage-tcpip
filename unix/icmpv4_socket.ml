open Lwt.Infix

type ipaddr = Ipaddr.V4.t
type buffer = Cstruct.t
type 'a io = 'a Lwt.t

type t = unit

type id = t

type error = string

let pp_error fmt err = Format.asprintf fmt "%s" err

let ipproto_icmp = 1 (* according to BSD /etc/protocols *)
let port = 0 (* port isn't meaningful in this context *)

let connect () = Lwt.return_unit

let pp_sockaddr fmt sa =
  let open Lwt_unix in
  match sa with
  | ADDR_UNIX s -> Format.fprintf fmt "%s" s
  | ADDR_INET (ip, port) -> Format.fprintf fmt "%s, %d" (Unix.string_of_inet_addr ip) port

let input t ~src ~dst buf =
  (* TODO: obviously, not great *)
  raise (Failure "unimplemented, sorry :(");
  Lwt.return_unit

let listen t addr fn =
  let open Lwt_unix in
  let fd = socket PF_INET SOCK_DGRAM ipproto_icmp in
  let sa = ADDR_INET (Unix.inet_addr_of_string (Ipaddr.V4.to_string addr), port) in
  let () = bind fd sa in
  let rec aux fn = 
    let receive_buffer = Cstruct.create 4096 in
    Lwt_cstruct.recvfrom fd receive_buffer [] >>= fun (len, sockaddr) ->
    (* trim the buffer to the amount of data actually received *)
    let receive_buffer = Cstruct.set_len receive_buffer len in
    fn receive_buffer
  in
  aux fn >>= fun () -> close fd

let write t ~dst buf =
  let open Lwt_unix in
  let flags = [] in
  let ipproto_icmp = 1 in (* according to BSD /etc/protocols *)
  let port = 0 in (* port isn't meaningful in this context *)
  let fd = socket PF_INET SOCK_DGRAM ipproto_icmp in
  let in_addr = Unix.inet_addr_of_string (Ipaddr.V4.to_string dst) in
  let sockaddr = ADDR_INET (in_addr, port) in
  Lwt_cstruct.sendto fd buf flags sockaddr >>= fun _sent ->
  (* TODO: log short reads? *)
  Lwt_unix.close fd

