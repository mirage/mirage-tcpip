
let src = Logs.Src.create "ipv4-fragments" ~doc:"IPv4 fragmentation"
module Log = (val Logs.src_log src : Logs.LOG)

(* what we actually have is a Cstruct.t (list?) with gaps, no? *)
module V = struct
  type t = (int * Cstruct.t) list

  let weight v = Cstruct.lenv (List.map snd v)
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

let assemble packet offset payload fragments =
  (* got last fragment, what to do now?
     - allocate offset
     - until i is 0, go through fragments, stitch fragment
     - if some bytes are missing (or out-of-order), we give up
  *)
  let plen = Cstruct.len payload in
  let res = Cstruct.create_unsafe (offset + plen) in
  Cstruct.blit payload 0 res offset plen ;
  let rec fwd idx fs =
    if idx = 0 then
      true
    else
      match fs with
      | [] ->
        Log.info (fun m -> m "no more segments, but still at %d" idx) ;
        false
      | (off, p)::tl ->
        let len = idx - off in
        if len > 0 && len <= Cstruct.len p then
          (Cstruct.blit p off res off len ;
           fwd off tl)
        else
          (Log.info (fun m -> m "len %d (off %d idx %d), p %d" len off idx (Cstruct.len p)) ;
           false)
  in
  if fwd offset fragments then
    Some (packet, res)
  else
    None

let process cache buf =
  match Ipv4_packet.Unmarshal.of_cstruct buf with
  | Error s ->
    Log.info (fun m -> m "error %s while parsing IPv4 frame %a" s Cstruct.hexdump_pp buf);
    cache, None
  | Ok (packet, payload) ->
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
      (* logic: if more_fragment then add to cache, else retrieve and (maybe) return *)
      match Cache.find key cache with
      | None ->
        if more && offset = 0 then
          Cache.add key [(offset, payload)] cache, None
        else if offset > 0 then
          (Logs.info (fun m -> m "offset > 0 without any fragments %a"
                         Ipv4_packet.pp packet) ;
           cache, None)
        else
          (Logs.info (fun m -> m "no more fragments, but we don't have any in cache %a"
                         Ipv4_packet.pp packet) ;
           cache, None)
      | Some ((off, p)::tl, cache') ->
        if more && offset > off then
          Cache.add key ((offset, payload)::(off, p)::tl) cache', None
        else if offset <= off then
          (Log.info (fun m -> m "dropping fragment (offset %d <= off %d) %a"
                        offset off Ipv4_packet.pp packet) ;
           cache', None)
        else
          Cache.remove key cache', assemble packet offset payload ((off, p)::tl)
      | Some ([], _) -> assert false
