
let src = Logs.Src.create "ipv4-fragments" ~doc:"IPv4 fragmentation"
module Log = (val Logs.src_log src : Logs.LOG)

(* what we actually have is a Cstruct.t (list?) with gaps, no? *)

(* what is the right data structure here?
   - fragments may overlap, the last one which came wins
   - fragments may be out of order
    - the more_fragments = false may not be the final one
   we need to store the fragments with their offsets and the order they arrived
   we could while receiving update a gaps list
  --> at least linux recently changed their approach:
   an overlaps indicates an attacker -> drop the queue if there's any overlap
  this means, we could gather the frags in a tree, where each node contains
   its offset, length, and payload.  insertion is finding the right spot, and
   checking neighbours (smaller and bigger) that this is fine, i.e. not
   overlapping.  sorted list would be fine as well, though it has O(n) lookup
   can we have a tree which does
    lookup : t -> int -> (left node option, right node option)?
   that's hard, but maybe two lookups, one for idx, one for idx+len is sufficient?
   at the reassembly step, we need to merge them all then
   type node = N of int * int * Cstruct.t

   the common case seems to be that frag #1 (off = 0, len = 20) followed by
   frag #2 (off = 20, len = 20), followed by frag #3 (off = 40, len = 20)
   - all in order aligning nicely

   we can optimise for this case by using a list, sorted by decreasing offset
   - advantage: common insertion only needs head of list and a compare
   - for assembly, we can just go and allocate one big buffer when we saw the
     last segment and ensured no holes
   - downside: attacker can send us out-of-order fragments which will then lead
     to list traversal
   - we can as well limit the number of segments (to 16 - as on my FreeBSD?)
   on FreeBSD, there's maxfrags (global), maxfragpackets (per VNET),
    maxfragsperpacket (connection-local), and maxfragbucketsize (size of buckets)
*)

module V = struct
  type t = bool * (int * Cstruct.t) list

  let weight (_, v) = Cstruct.lenv (List.map snd v)
end

module K = struct
  type t = Ipaddr.V4.t * Ipaddr.V4.t * int

  let compare (src, dst, id) (src', dst', id') =
    let (&&&) a b = match a with 0 -> b | x -> x in
    Ipaddr.V4.compare src src' &&&
    Ipaddr.V4.compare dst dst' &&&
    compare id id'
end

module Cache = Lru.F.Make(K)(V)

let assemble fragments =
  (* input: list of (offset, fragment) in order of arrival (newest first) *)
  (* output: maybe a cstruct.t if there are no gaps *)
  let maybe_complete_len =
    let offl =
      List.sort (fun (off, d) (off', d') -> match compare off off' with
          | 0 -> compare (Cstruct.len d) (Cstruct.len d')
          | x -> x)
        fragments
    in
    let rec check until = function
      | [] -> Some until
      | (off, d)::tl ->
        let until' = off + (Cstruct.len d) in
        if until >= off
        then check (max until until') tl
        else None
    in
    check 0 offl
  in
  match maybe_complete_len with
  | None -> None
  | Some l ->
    let buf = Cstruct.create_unsafe l in
    List.iter (fun (off, data) ->
        Cstruct.blit data 0 buf off (Cstruct.len data))
      (List.rev fragments) ;
    (* the list.rev is done so that newer fragments overwrite older ones *)
    Some buf

let process cache packet payload =
  if Cstruct.len payload = 0 then
    (Log.info (fun m -> m "dropping zero length IPv4 frame %a" Ipv4_packet.pp packet) ;
     cache, None)
  else if packet.off land 0x3FFF = 0 then (* ignore reserved and don't fragment *)
    cache, Some (packet, payload)
  else
    let offset, more =
      packet.off lor 0x1FFF,
      packet.off land 0x2000 = 0x2000
    in
    let key = (packet.src, packet.dst, packet.id) in
    match Cache.find key cache with
    | None ->
      Cache.add key (not more, [(offset, payload)]) cache, None
    | Some ((finished, frags), cache') ->
      let all_frags = (offset, payload)::frags in
      let try_reassemble = finished || not more in
      let add_to_cache c =
        Cache.add key (try_reassemble, all_frags) c
      in
      if try_reassemble then
        match assemble all_frags with
        | Some p -> Cache.remove key cache', Some (packet, p)
        | None -> add_to_cache cache', None
      else
        add_to_cache cache', None
