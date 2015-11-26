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

exception Bad_option of string

type t =
  | Noop
  | MSS of int                    (* RFC793 *)
  | Window_size_shift of int      (* RFC1323 2.2 *)
  | SACK_ok                       (* RFC2018 *)
  | SACK of (int32 * int32) list  (* RFC2018 *)
  | Timestamp of int32 * int32    (* RFC1323 3.2 *)
  | Unknown of int * string       (* RFC793 *)

let report_error n =
  let error = Printf.sprintf "Invalid option %d presented" n in
  raise (Bad_option error)

let check_mss buf =
  let min_mss_size = 88 in
  let mss_size = Cstruct.BE.get_uint16 buf 2 in
  if mss_size < min_mss_size then
    let err = (Printf.sprintf "Invalid MSS %d received" mss_size) in
    raise (Bad_option err)
  else
    MSS mss_size

let unmarshal buf =
  let i = Cstruct.iter
      (fun buf ->
         match Cstruct.get_uint8 buf 0 with
         | 0 -> None   (* EOF *)
         | 1 -> Some 1 (* NOP *)
         | n ->
           match Cstruct.len buf with
           | 0 | 1 -> report_error n
           | buffer_size ->
             let option_size = Cstruct.get_uint8 buf 1 in
             if option_size <= buffer_size && option_size >= 2 then
               Some option_size
             else report_error n
      )
      (fun buf ->
         match Cstruct.get_uint8 buf 0 with
         | 0 -> assert false
         | 1 -> Noop
         | option_number ->
           let option_length = Cstruct.get_uint8 buf 1 in
           if Cstruct.len buf < option_length then
             report_error option_number
           else begin
             match option_number, option_length with
             (* error out for lengths that are always nonsensible when option
              * number >1 *)
             | _, 0 | _, 1 -> report_error option_number
             | 2, 4 -> check_mss buf
             | 3, 3 -> Window_size_shift (Cstruct.get_uint8 buf 2)
             | 4, 2 -> SACK_ok
             | 5, _ ->
               let num = (option_length - 2) / 8 in
               let rec to_int32_list off acc = function
                 |0 -> acc
                 |n ->
                   let x =
                     Cstruct.BE.get_uint32 buf off,
                     Cstruct.BE.get_uint32 buf (off+4)
                   in
                   to_int32_list (off+8) (x::acc) (n-1)
               in SACK (to_int32_list 2 [] num)
             | 8, 10 -> Timestamp (Cstruct.BE.get_uint32 buf 2,
                                   Cstruct.BE.get_uint32 buf 6)
             (* error out for lengths that don't match the spec's
                fixed length for a given, recognized option number *)
             | 2, _ | 3, _ | 4, _ | 8, _ -> report_error option_number
             (* Parse apparently well-formed but unrecognized
                options *)
             | n, _ ->
               Unknown (n, Cstruct.copy buf 2 (Cstruct.len buf - 2))
           end
      ) buf in
  Cstruct.fold (fun a b -> b :: a) i []

let write_iter buf =
  let set_tlen t l =
    Cstruct.set_uint8 buf 0 t;
    Cstruct.set_uint8 buf 1 l
  in
  function
  | Noop ->
    Cstruct.set_uint8 buf 0 1;
    1
  | MSS sz ->
    set_tlen 2 4;
    Cstruct.BE.set_uint16 buf 2 sz;
    4
  | Window_size_shift shift ->
    set_tlen 3 3;
    Cstruct.set_uint8 buf 2 shift;
    3
  | SACK_ok ->
    set_tlen 4 2;
    2
  | SACK acks ->
    let tlen = (List.length acks * 8) + 2 in
    set_tlen 5 tlen;
    let rec fn off = function
      | (le,re)::tl ->
        Cstruct.BE.set_uint32 buf off le;
        Cstruct.BE.set_uint32 buf (off+4) re;
        fn (off+8) tl
      | [] -> () in
    fn 2 acks;
    tlen
  | Timestamp (tsval,tsecr) ->
    set_tlen 8 10;
    Cstruct.BE.set_uint32 buf 2 tsval;
    Cstruct.BE.set_uint32 buf 6 tsecr;
    10
  | Unknown (kind, contents) ->
    let content_len = String.length contents in
    let tlen = content_len + 2 in
    set_tlen kind tlen;
    Cstruct.blit_from_string contents 0 buf 2 content_len;
    tlen

let marshal buf ts =
  (* Apply the write iterator on each stamp *)
  let rec write fn off buf =
    function
    | hd::tl ->
      let wlen = fn buf hd in
      let buf = Cstruct.shift buf wlen in
      write fn (off+wlen) buf tl
    | [] -> off
  in
  let tlen = write write_iter 0 buf ts in
  (* add padding to word length *)
  match (4 - (tlen mod 4)) mod 4 with
  | 0 -> tlen
  | 1 ->
    Cstruct.set_uint8 buf tlen 0;
    tlen+1
  | 2 ->
    Cstruct.set_uint8 buf tlen 0;
    Cstruct.set_uint8 buf (tlen+1) 0;
    tlen+2
  | 3 ->
    Cstruct.set_uint8 buf tlen 0;
    Cstruct.set_uint8 buf (tlen+1) 0;
    Cstruct.set_uint8 buf (tlen+2) 0;
    tlen+3
  | _ -> assert false

let pp_sack fmt x =
  let pp_v fmt (l, r) = Log.pf fmt "[%lu,%lu]" l r in
  Log.pp_print_list pp_v fmt x

let pp fmt = function
  | Noop                -> Log.ps fmt "Noop"
  | MSS m               -> Log.pf fmt "MSS=%d" m
  | Window_size_shift b -> Log.pf fmt "Window>> %d" b
  | SACK_ok             -> Log.ps fmt "SACK_ok"
  | SACK x              -> Log.pf fmt "SACK[%a]" pp_sack x
  | Timestamp (a,b)     -> Log.pf fmt "Timestamp(%lu,%lu)" a b
  | Unknown (t,_)       -> Log.pf fmt "%d?" t

let pps fmt = function
  | [] -> Log.ps fmt "[]"
  | x  ->
    let ppl fmt x = Log.pp_print_list pp fmt x in
    Log.pf fmt "[ %a ]" ppl x
