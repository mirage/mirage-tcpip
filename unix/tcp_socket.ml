open Lwt
open Result

type error = [ Mirage_protocols.Tcp.error | `Exn of exn ]
type write_error = Mirage_protocols.Tcp.write_error

let pp_error ppf = function
  | #Mirage_protocols.Tcp.error as e -> Mirage_protocols.Tcp.pp_error ppf e
  | `Exn e -> Fmt.pf ppf "%a" Fmt.exn e

let pp_write_error = Mirage_protocols.Tcp.pp_write_error

let disconnect _ =
  return_unit

let read fd =
  let buflen = 4096 in
  let buf = Cstruct.create buflen in
  Lwt.catch (fun () ->
      Lwt_cstruct.read fd buf
      >>= function
      | 0 -> return (Ok `Eof)
      | n when n = buflen -> return (Ok (`Data buf))
      | n -> return @@ Ok (`Data (Cstruct.sub buf 0 n))
    )
    (fun exn -> return (Error (`Exn exn)))

let rec write fd buf =
  Lwt.catch
    (fun () ->
      Lwt_cstruct.write fd buf
      >>= function
      | n when n = Cstruct.len buf -> return @@ Ok ()
      | 0 -> return @@ Error `Closed
      | n -> write fd (Cstruct.sub buf n (Cstruct.len buf - n))
    ) (function
      | Unix.Unix_error(Unix.EPIPE, _, _) -> return @@ Error `Closed
      | e -> Lwt.fail e)

let writev fd bufs =
  Lwt_list.fold_left_s
    (fun res buf ->
       match res with
       | Error _ as e -> return e
       | Ok () -> write fd buf
    ) (Ok ()) bufs

(* TODO make nodelay a flow option *)
let write_nodelay fd buf =
  write fd buf

(* TODO make nodelay a flow option *)
let writev_nodelay fd bufs =
  writev fd bufs

let close fd =
  Lwt_unix.close fd

(* FIXME: how does this work at all ?? *)
let input _t ~listeners:_ =
  (* TODO terminate when signalled by disconnect *)
  let t, _ = Lwt.task () in
  t
