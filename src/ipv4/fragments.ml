(*
 * Copyright (c) 2018 Hannes Mehnert <hannes@mehnert.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS l SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

let src = Logs.Src.create "ipv4-fragments" ~doc:"IPv4 fragmentation"
module Log = (val Logs.src_log src : Logs.LOG)

open Rresult.R.Infix

(* TODO:
current state:

    lifetime is 10s max between first and last fragment
    size is 1MB hardcoded
    max 16 fragments for each "flow" (source ip, destrination ip, protocol, ipv4 identifier)
    inserted into sorted list, checks overlaps and holes on reassembly (triggered once a fragment without "more fragments" has been received)

this has some issues:

    anyone can spam (with a constant stream of fragmented packets - needs to fill 1MB in 10s) the fragment cache, leading to resource exhaustion of the cache ("valid" fragments are dropped if they're incoming too slowly)
    insertion into linked list is O(n) (with n is maximal 16)
    ping -s 65535 isn't answered with MTU=1500 (doesn't fit into 16 fragments)

what we could do instead

    maximum storage per source ip
    use a bitmask or tree data structure for the segments (offset is on 8byte boundaries)
    may lead to verification of overlaps at insertion time --> can drop immediately
*)

(* IP Fragmentation using a LRU cache:

   The key of our cache is source ip * destination ip * protocol * identifier.
   The value is a quintuple consisting of first segment received. IP options
   (which are usually sent only in the first IP segment), "last segment
   received" (i.e. an IPv4 segment without the more fragment bit set), a counter
   of the length of items, and a list of pairs, which contain an offset and
   payload.  The list is sorted by offset in descending order. *)

module V = struct
  type t = int64 * Cstruct.t * bool * int * (int * Cstruct.t) list

  let weight (_, _, _, _, v) = Cstruct.lenv (List.map snd v)
end

module K = struct
  type t = Ipaddr.V4.t * Ipaddr.V4.t * int * int

  let compare (src, dst, proto, id) (src', dst', proto', id') =
    let (&&&) a b = match a with 0 -> b | x -> x in
    let int_cmp : int -> int -> int = compare in
    Ipaddr.V4.compare src src' &&&
    Ipaddr.V4.compare dst dst' &&&
    int_cmp proto proto' &&&
    int_cmp id id'
end

module Cache = Lru.F.Make(K)(V)

(* insert_sorted inserts a fragment in a list, sort is by frag_start, descending *)
let rec insert_sorted ((frag_start, _) as frag) = function
  | [] -> [ frag ]
  | ((frag'_start, _) as frag')::tl ->
    if frag'_start <= frag_start
    then frag::frag'::tl
    else frag'::insert_sorted frag tl

(* attempt_reassemble takes a list of fragments, and returns either
   - Ok payload when the payload was completed
   - Error Hole if some fragment is still missing
   - Error Bad if the list of fragments was bad: it contains overlapping
     segments.  This is an indication for malicious activity, and we drop the
     IP fragment

There are various attacks (and DoS) on IP reassembly, most prominent use
overlapping segments (and selection thereof), we just drop overlapping segments
(similar as Linux does since https://git.kernel.org/pub/scm/linux/kernel/git/davem/net-next.git/commit/?id=c30f1fc041b74ecdb072dd44f858750414b8b19f).
*)

type r = Bad | Hole

let attempt_reassemble fragments =
  Log.debug (fun m -> m "reassemble %a"
                Fmt.(list ~sep:(unit "; ") (pair ~sep:(unit ", len ") int int))
                (List.map (fun (off, data) -> off, Cstruct.len data) fragments)) ;
  (* input: list of (offset, fragment) with decreasing offset *)
  (* output: maybe a cstruct.t if there are no gaps *)
  let len =
    (* List.hd is safe here, since we are never called with an empty list *)
    let off, data = List.hd fragments in
    off + Cstruct.len data
  in
  let rec check until = function
    | [] -> if until = 0 then Ok () else Error Hole
    | (start, d)::tl ->
      let until' = start + (Cstruct.len d) in
      if until = until'
      then check start tl
      else if until' > until
      then Error Bad
      else Error Hole
  in
  check len fragments >>= fun () ->
  let buf = Cstruct.create_unsafe len in
  List.iter (fun (off, data) ->
      Cstruct.blit data 0 buf off (Cstruct.len data))
    fragments ;
  Ok buf

let max_number_of_fragments = 16

let max_duration = Duration.of_sec 10

let process cache ts (packet : Ipv4_packet.t) payload =
  let add_trim key value cache =
    let cache' = Cache.add key value cache in
    Cache.trim cache'
  in
  if packet.off land 0x3FFF = 0 then (* ignore reserved and don't fragment *)
    (* fastpath *)
    cache, Some (packet, payload)
  else
    let offset, more =
      (packet.off land 0x1FFF) lsl 3, (* of 8 byte blocks *)
      packet.off land 0x2000 = 0x2000
    and key = (packet.src, packet.dst, packet.proto, packet.id)
    in
    let v = (ts, packet.options, not more, 1, [(offset, payload)]) in
    match Cache.find key cache with
    | None ->
      Log.debug (fun m -> m "%a none found, inserting into cache" Ipv4_packet.pp packet) ;
      add_trim key v cache, None
    | Some (ts', options, finished, cnt, frags) ->
      if Int64.sub ts ts' >= max_duration then begin
        Log.warn (fun m -> m "%a found some, but timestamp exceeded duration %a, dropping old segments and inserting new segment into cache" Ipv4_packet.pp packet Duration.pp max_duration) ;
        add_trim key v cache, None
      end else
        let cache' = Cache.promote key cache in
        let all_frags = insert_sorted (offset, payload) frags
        and try_reassemble = finished || not more
        and options' = if offset = 0 then packet.options else options
        in
        Log.debug (fun m -> m "%d found, finished %b more %b try_reassemble %b"
                      cnt finished more try_reassemble) ;
        let maybe_add_to_cache c =
          if cnt < max_number_of_fragments then
            add_trim key (ts', options', try_reassemble, succ cnt, all_frags) c
          else
            (Log.warn (fun m -> m "%a dropping from cache, maximum number of fragments exceeded"
                          Ipv4_packet.pp packet) ;
             Cache.remove key c)
        in
        if try_reassemble then
          match attempt_reassemble all_frags with
          | Ok p ->
            Log.debug (fun m -> m "%a reassembled to payload %d" Ipv4_packet.pp packet (Cstruct.len p)) ;
            let packet' = { packet with options = options' ; off = 0 } in
            Cache.remove key cache', Some (packet', p)
          | Error Bad ->
            Log.warn (fun m -> m "%a dropping from cache, bad fragments (%a)"
                         Ipv4_packet.pp packet
                         Fmt.(list ~sep:(unit "; ") (pair ~sep:(unit ", ") int int))
                         (List.map (fun (s, d) -> (s, Cstruct.len d)) all_frags)) ;
            Log.debug (fun m -> m "full fragments: %a"
                          Fmt.(list ~sep:(unit "@.") Cstruct.hexdump_pp)
                          (List.map snd all_frags)) ;
            Cache.remove key cache', None
          | Error Hole -> maybe_add_to_cache cache', None
        else
          maybe_add_to_cache cache', None

(* TODO hdr.options is a Cstruct.t atm, but instead we need to parse all the
   options, and distinguish based on the first bit -- only these with the bit
   set should be copied into all fragments (see RFC 791, 3.1, page 15) *)
let fragment ~mtu hdr payload =
  let rec frag1 acc hdr hdr_buf offset data_size payload =
    let more = Cstruct.len payload > data_size in
    let hdr' =
      (* off is 16 bit of IPv4 header, 0x2000 sets the more fragments bit *)
      let off = (offset / 8) lor (if more then 0x2000 else 0) in
      { hdr with Ipv4_packet.off }
    in
    let this_payload, rest =
      if more then Cstruct.split payload data_size else payload, Cstruct.empty
    in
    let payload_len = Cstruct.len this_payload in
    Ipv4_wire.set_ipv4_csum hdr_buf 0;
    (match Ipv4_packet.Marshal.into_cstruct ~payload_len hdr' hdr_buf with
     (* hdr_buf is allocated with hdr_size (computed below) bytes, thus
        into_cstruct will never return an error! *)
     | Error msg -> invalid_arg msg
     | Ok () -> ());
    let acc' = Cstruct.append hdr_buf this_payload :: acc in
    if more then
      let offset = offset + data_size in
      (frag1[@tailcall]) acc' hdr hdr_buf offset data_size rest
    else
      acc'
  in
  let hdr_size =
    (* padded to 4 byte boundary *)
    let opt_size = (Cstruct.len hdr.Ipv4_packet.options + 3) / 4 * 4 in
    opt_size + Ipv4_wire.sizeof_ipv4
  in
  let data_size =
    let full = mtu - hdr_size in
    (full / 8) * 8
  in
  if data_size <= 0 then
    []
  else
    List.rev (frag1 [] hdr (Cstruct.create hdr_size) data_size data_size payload)
