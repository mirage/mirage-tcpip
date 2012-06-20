(*
 * Copyright (c) 2011 Anil Madhavapeddy <anil@recoil.org>
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

(* TCP options parsing *)

type t =
  |Noop
  |MSS of int                    (* RFC793 *)
  |Window_size_shift of int      (* RFC1323 2.2 *)
  |SACK_ok                       (* RFC2018 *)
  |SACK of (int32 * int32) list  (* RFC2018 *)
  |Timestamp of int32 * int32    (* RFC1323 3.2 *)
  |Unknown of int * string       (* RFC793 *)

type ts = t list

let unmarshal buf =
  let open Cstruct in
  let i = iter 
    (fun buf -> 
      match get_uint8 buf 0 with
      |0 -> None   (* EOF *)
      |1 -> Some 1 (* NOP *)
      |n -> Some (get_uint8 buf 1)
    )
    (fun buf ->
      match get_uint8 buf 0 with
      |0 -> assert false
      |1 -> Noop
      |2 -> MSS (BE.get_uint16 buf 2)
      |3 -> Window_size_shift (get_uint8 buf 2)
      |4 -> SACK_ok
      |5 -> 
        let num = ((get_uint8 buf 1) - 2) / 8 in
        let rec to_int32_list off acc = function
          |0 -> acc
          |n ->
            let x = (BE.get_uint32 buf off), (BE.get_uint32 buf (off+4)) in
            to_int32_list (off+8) (x::acc) (n-1)
        in SACK (to_int32_list 2 [] num)
      |8 -> Timestamp ((BE.get_uint32 buf 2), (BE.get_uint32 buf 6))
      |n -> Unknown (n, (copy_buffer buf 2 (len buf - 2)))
    ) buf in
  fold (fun a b -> b :: a) i []

let write_iter buf = 
  let open Cstruct in
  let set_tlen t l = set_uint8 buf 0 t; set_uint8 buf 1 l in
  function
  |Noop ->
    set_uint8 buf 0 1;
    1
  |MSS sz ->
    set_tlen 2 4;
    BE.set_uint16 buf 2 sz;
    4
  |Window_size_shift shift ->
    set_tlen 3 3;
    set_uint8 buf 2 shift;
    3
  |SACK_ok ->
    set_tlen 4 2;
    2
  |SACK acks ->
    let tlen = (List.length acks * 8) + 2 in
    set_tlen 5 tlen;
    let rec fn off = function
     |(le,re)::tl ->
        BE.set_uint32 buf off le;
        BE.set_uint32 buf (off+4) re;
        fn (off+8) tl
     |[] -> () in
    fn 2 acks;
    tlen
  |Timestamp (tsval,tsecr) ->
    set_tlen 8 10;
    BE.set_uint32 buf 2 tsval;
    BE.set_uint32 buf 6 tsecr;
    10
  |Unknown (kind,contents) ->
    let tlen = String.length contents in
    set_tlen kind tlen;
    set_buffer contents 0 buf 0 tlen;
    tlen

let marshal buf ts =
  let open Cstruct in
  (* Apply the write iterator on each stamp *)
  let rec write fn off buf =
    function
    |hd::tl ->
      let wlen = fn buf hd in
      let buf = shift buf wlen in
      write fn (off+wlen) buf tl
    |[] -> off
  in
  let tlen = write write_iter 0 buf ts in
  (* add padding to word length *)
  match (4 - (tlen mod 4)) mod 4 with
  |0 -> tlen
  |1 -> set_uint8 buf tlen 0; tlen+1
  |2 -> set_uint8 buf tlen 0; set_uint8 buf (tlen+1) 0; tlen+2
  |3 -> set_uint8 buf tlen 0; set_uint8 buf (tlen+1) 0; set_uint8 buf (tlen+2) 0; tlen+3
  |_ -> assert false

let to_string = function
  |Noop -> "Noop"
  |MSS m -> Printf.sprintf "MSS=%d" m
  |Window_size_shift b -> Printf.sprintf "Window>>%d" b
  |SACK_ok -> "SACK_ok"
  |SACK x -> Printf.(sprintf "SACK=(%s)" (String.concat ","
    (List.map (fun (l,r) -> sprintf "%lu,%lu" l r) x)))
  |Timestamp (a,b) -> Printf.sprintf "Timestamp(%lu,%lu)" a b
  |Unknown (t,_) -> Printf.sprintf "%d?" t

let prettyprint s =
  Printf.sprintf "[ %s ]" (String.concat "; " (List.map to_string s))
