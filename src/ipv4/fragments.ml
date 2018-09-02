let src = Logs.Src.create "ipv4-fragments" ~doc:"IPv4 fragmentation"
module Log = (val Logs.src_log src : Logs.LOG)

open Rresult.R.Infix

(* IP Fragmentation using a LRU cache:
   The key of our cache is source ip * destination ip * protocol * identifier.
   The value is a quadruple consisting of IP options (which are usually sent
   only in the first IP segment), "last segment received" (i.e. an IPv4 segment
   without the more fragment bit set), a counter of the length of items, and a
   list of pairs, which contain an offset and payload.  The list is sorted by
   offset in descending order. *)

module V = struct
  type t = Cstruct.t * bool * int * (int * Cstruct.t) list

  let weight (_, _, _, v) = Cstruct.lenv (List.map snd v)
end

let rec insert_sorted (off, data) = function
  | [] -> [ (off, data) ]
  | (off', data')::tl ->
    if off > off'
    then (off, data)::(off', data')::tl
    else (off', data')::insert_sorted (off, data) tl

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

(* attempt_reassemble takes a list of fragments, and returns either
   - Ok payload when the payload was completed
   - Error Hole if some fragment is still missing
   - Error Bad when the list of fragments was bad: it contains overlapping
     segments.  This is an indication for malicious activity, and we drop
     the IP fragment

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
    | (off, d)::tl ->
      let until' = off + (Cstruct.len d) in
      if until = until'
      then check off tl
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

let process cache (packet : Ipv4_packet.t) payload =
  Log.debug (fun m -> m "process called with off %x" packet.off) ;
  if packet.off land 0x3FFF = 0 then (* ignore reserved and don't fragment *)
    (* fastpath *)
    cache, Some (packet, payload)
  else
    let offset, more =
      (packet.off land 0x1FFF) lsl 3, (* of 8 byte blocks *)
      packet.off land 0x2000 = 0x2000
    and key = (packet.src, packet.dst, packet.proto, packet.id)
    in
    Log.debug (fun m -> m "dealing with fragmented frame %a off %d more %b len %d"
                  Ipv4_packet.pp packet offset more (Cstruct.len payload)) ;
    match Cache.find key cache with
    | None ->
      Log.debug (fun m -> m "none found, inserting into cache") ;
      Cache.add key (packet.options, not more, 1, [(offset, payload)]) cache, None
    | Some ((options, finished, cnt, frags), cache') ->
      let all_frags = insert_sorted (offset, payload) frags
      and try_reassemble = finished || not more
      and options' = if offset = 0 then packet.options else options
      in
      Log.debug (fun m -> m "%d found, finished %b more %b try_reassemble %b"
                    cnt finished more try_reassemble) ;
      let maybe_add_to_cache c =
        if cnt < max_number_of_fragments then
          Cache.add key (options', try_reassemble, succ cnt, all_frags) c
        else
          (Log.warn (fun m -> m "dropping %a from cache, maximum number of fragments exceeded"
                       Ipv4_packet.pp packet) ;
           Cache.remove key c)
      in
      if try_reassemble then
        match attempt_reassemble all_frags with
        | Ok p ->
          Log.debug (fun m -> m "reassembled to payload %d" (Cstruct.len p)) ;
          let packet' = { packet with options = options' ; off = 0 } in
          Cache.remove key cache', Some (packet', p)
        | Error Bad ->
          Log.warn (fun m -> m "dropping %a from cache, bad fragments (%a)"
                       Ipv4_packet.pp packet
                       Fmt.(list ~sep:(unit ", ") (pair int Cstruct.hexdump_pp))
                       all_frags) ;
          Cache.remove key cache', None
        | Error Hole -> maybe_add_to_cache cache', None
      else
        maybe_add_to_cache cache', None
