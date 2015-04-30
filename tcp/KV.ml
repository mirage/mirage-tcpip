(*
 * Copyright (c) 2015 Thomas Gazagnaire <thomas@gazagnaire.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

module type S = sig
  type step = string
  type key = step list
  type value = string
  val read: key -> value option Lwt.t
  val writev: (key * value) list -> unit Lwt.t
  val remove: key -> unit Lwt.t
  val dirs: key -> step list Lwt.t
end

module Memory = struct

  type step = string
  type key = step list
  type value = string

  let t = Hashtbl.create 1024
  let read k = Lwt.return (try Some (Hashtbl.find t k) with Not_found -> None)
  let remove k = Hashtbl.remove t k; Lwt.return_unit

  let writev vs =
    List.iter (fun (k, v) -> Hashtbl.replace t k v) vs;
    Lwt.return_unit

  let starts_with ~prefix t =
    let rec aux p t = match p, t with
      | [], [x] -> Some x
      | a::b, c::d -> if a = c then aux b d else None
      | _ -> None
    in
    aux prefix t

  (* XXX: crap *)
  let dirs k =
    Hashtbl.fold (fun x _ acc ->
        match starts_with ~prefix:k x with None  -> acc | Some e -> e :: acc
      ) t []
    |> Lwt.return

end

let (>>=) = Lwt.bind

module Global = struct

  type step = string
  type key = step list
  type value = string

  let t = ref (module Memory: S) (* FIXME: should be [None] maybe *)
  let set s = t := s

  let read x = let (module M) = !t in M.read x
  let writev x = let (module M) = !t in M.writev x
  let remove x = let (module M) = !t in M.remove x
  let dirs x = let (module M) = !t in M.dirs x

end
