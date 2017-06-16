open Lwt.Infix

module Make(E : Mirage_protocols_lwt.ETHIF)(Clock : Mirage_clock_lwt.MCLOCK) (Time : Mirage_time_lwt.S) = struct
  module A = Arpv4.Make(E)(Clock)(Time)
  (* generally repurpose A, but substitute input and query, and add functions
     for adding/deleting entries *)
  type error = Mirage_protocols.Arp.error
  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t
  type macaddr = Macaddr.t
  type ipaddr = Ipaddr.V4.t
  type repr = string

  type t = {
    base : A.t;
    table : (Ipaddr.V4.t, macaddr) Hashtbl.t;
  }

  let pp_error = Mirage_protocols.Arp.pp_error
  let add_ip t = A.add_ip t.base
  let remove_ip t = A.remove_ip t.base
  let set_ips t = A.set_ips t.base
  let get_ips t = A.get_ips t.base

  let to_repr t =
    let print ip entry acc =
      let key = Ipaddr.V4.to_string ip in
      let entry = Macaddr.to_string entry in
      Printf.sprintf "%sIP %s : MAC %s\n" acc key entry
    in
    Lwt.return (Hashtbl.fold print t.table "")

  let pp fmt repr =
    Format.fprintf fmt "%s" repr

  let connect e clock = A.connect e clock >>= fun base ->
    Lwt.return ({ base; table = (Hashtbl.create 7) })

  let disconnect t = A.disconnect t.base

  let query t ip =
    match Hashtbl.mem t.table ip with
    | false -> Lwt.return @@ Error `Timeout
    | true -> Lwt.return (Ok (Hashtbl.find t.table ip))

  let input t buffer =
    (* disregard responses, but reply to queries *)
    try
    match Arpv4_wire.get_arp_op buffer with
    | 1 -> A.input t.base buffer
    | 2 | _ -> Lwt.return_unit
    with
    | Invalid_argument s -> Printf.printf "Arpv4_wire failed on buffer: %s" s;
      Lwt.return_unit

  let add_entry t ip mac =
    Hashtbl.add t.table ip mac
end
