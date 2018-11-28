(*
 * Copyright (c) 2010-2011 Anil Madhavapeddy <anil@recoil.org>
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

open Lwt.Infix

let src = Logs.Src.create "ipv4" ~doc:"Mirage IPv4"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (R: Mirage_random.C) (C: Mirage_clock.MCLOCK) (Ethif: Mirage_protocols_lwt.ETHIF) (Arpv4 : Mirage_protocols_lwt.ARP) = struct
  module Routing = Routing.Make(Log)(Arpv4)

  (** IO operation errors *)
  type error = [ Mirage_protocols.Ip.error | `Would_fragment | `Ethif of Ethif.error ]
  let pp_error ppf = function
    | #Mirage_protocols.Ip.error as e -> Mirage_protocols.Ip.pp_error ppf e
    | `Would_fragment -> Fmt.string ppf "would fragment, but fragmentation is disabled"
    | `Ethif e -> Ethif.pp_error ppf e

  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t
  type ipaddr = Ipaddr.V4.t
  type callback = src:ipaddr -> dst:ipaddr -> buffer -> unit Lwt.t

  type t = {
    ethif : Ethif.t;
    arp : Arpv4.t;
    clock : C.t;
    mutable ip: Ipaddr.V4.t;
    network: Ipaddr.V4.Prefix.t;
    mutable gateway: Ipaddr.V4.t option;
    mutable cache: Fragments.Cache.t;
  }

  let write t ?(fragment = true) ?(ttl = 38) ?src dst proto ?(size = 0) headerf bufs =
    Routing.destination_mac t.network t.gateway t.arp dst >>= function
    | Error `Local ->
      Log.warn (fun f -> f "Could not find %a on the local network" Ipaddr.V4.pp dst);
      Lwt.return @@ Error (`No_route "no response for IP on local network")
    | Error `Gateway when t.gateway = None ->
      Log.warn (fun f -> f "Write to %a would require an external route, which was not provided" Ipaddr.V4.pp dst);
      Lwt.return @@ Ok ()
    | Error `Gateway ->
      Log.warn (fun f -> f "Write to %a requires an external route, and the provided %a was not reachable" Ipaddr.V4.pp dst (Fmt.option Ipaddr.V4.pp) t.gateway);
      (* when a gateway is specified the user likely expects their traffic to be passed to it *)
      Lwt.return @@ Error (`No_route "no route to default gateway to outside world")
    | Ok mac ->
      (* need first to deal with fragmentation decision - find out mtu *)
      let mtu = Ethif.mtu t.ethif in
      (* no options here, always 20 bytes! *)
      let hdr_len = Ipv4_wire.sizeof_ipv4 in
      let needed_bytes = Cstruct.lenv bufs + hdr_len + size in
      (* construct the header (will be reused across fragments) *)
      let hdr =
        let src = match src with None -> t.ip | Some x -> x in
        let off = if fragment then 0x0000 else 0x4000 in
        Ipv4_packet.{
          options = Cstruct.empty ;
          src ; dst ;
          ttl ; off ; id = 0 ;
          proto = Ipv4_packet.Marshal.protocol_to_int proto }
      in
      let writeout size fill =
        Ethif.write t.ethif mac `IPv4 ~size fill >|= function
        | Error e ->
          Log.warn (fun f -> f "Error sending Ethernet frame: %a" Ethif.pp_error e);
          Error (`Ethif e)
        | Ok () -> Ok ()
      in
      Log.debug (fun m -> m "ip write: mtu is %d, hdr_len is %d, size %d payload len %d, needed_bytes %d"
                   mtu hdr_len size (Cstruct.lenv bufs) needed_bytes) ;
      if mtu >= needed_bytes then begin
        (* single fragment *)
        let fill buf =
          let hdr_buf, payload_buf = Cstruct.split buf hdr_len in
          let header_len = headerf payload_buf in
          if header_len > size then begin
            Log.err (fun m -> m "headers returned length exceeding size") ;
            invalid_arg "headerf exceeds size"
          end ;
          (* need to copy the given payload *)
          let len, leftover =
            Cstruct.fillv ~src:bufs ~dst:(Cstruct.shift payload_buf header_len)
          in
          if leftover <> [] then begin
            Log.err (fun m -> m "there's some leftover data") ;
            invalid_arg "leftover data"
          end ;
          let payload_len = header_len + len in
          match Ipv4_packet.Marshal.into_cstruct ~payload_len hdr buf with
          | Ok () -> Ipv4_common.set_checksum hdr_buf ; payload_len + hdr_len
          | Error msg ->
            Log.err (fun m -> m "failure while assembling ip frame: %s" msg) ;
            invalid_arg msg
        in
        writeout needed_bytes fill
      end else if fragment then begin
        (* where are we? -- need to allocate size, execute fillf
           --> if size + hdr_len > mtu, we need this allocated here *)
        let proto_header = Cstruct.create size in
        let header_len = headerf proto_header in
        if header_len > size then begin
            Log.err (fun m -> m "(frag) headers returned length exceeding size") ;
            invalid_arg "(frag) headerf exceeds size"
          end ;
        let proto_header = Cstruct.sub proto_header 0 header_len in
        let bufs = ref (proto_header :: bufs) in
        let hdr = { hdr with id = Randomconv.int16 R.generate } in
        let rec send off =
          match !bufs with
          | [] -> Lwt.return (Ok ())
          | to_send ->
            let pay_len = min (mtu - hdr_len) (Cstruct.lenv to_send) in
            let fill buf =
              let hdr_buf, payload_buf = Cstruct.split buf hdr_len in
              let len, leftover = Cstruct.fillv ~src:!bufs ~dst:payload_buf in
              bufs := leftover ;
              let last = match leftover with [] -> true | _ -> false in
              let off = if last then off else off lor 0x2000 in
              let hdr = { hdr with off } in
              match Ipv4_packet.Marshal.into_cstruct ~payload_len:len hdr buf with
              | Ok () -> Ipv4_common.set_checksum hdr_buf ; pay_len
              | Error msg ->
                Log.err (fun m -> m "failure while assembling ip frame: %s" msg) ;
                invalid_arg msg
            in
            writeout (hdr_len + pay_len) fill >>= function
            | Error e -> Lwt.return (Error e)
            | Ok () -> send (off + pay_len lsr 3)
        in
        send 0
      end else (* error out, as described in the semantics *)
        Lwt.return (Error `Would_fragment)

  (* TODO: ought we to check to make sure the destination is relevant here?  currently we'll process all incoming packets, regardless of destination address *)
  let input t ~tcp ~udp ~default buf =
    match Ipv4_packet.Unmarshal.of_cstruct buf with
    | Error s ->
      Log.info (fun m -> m "error %s while parsing IPv4 frame %a" s Cstruct.hexdump_pp buf);
      Lwt.return_unit
    | Ok (packet, payload) ->
      if Cstruct.len payload = 0 then
        (Log.info (fun m -> m "dropping zero length IPv4 frame %a" Ipv4_packet.pp packet) ;
         Lwt.return_unit)
      else
        let ts = C.elapsed_ns t.clock in
        let cache, res = Fragments.process t.cache ts packet payload in
        t.cache <- cache ;
        match res with
        | None -> Lwt.return_unit
        | Some (packet, payload) ->
          let src, dst = packet.src, packet.dst in
          match Ipv4_packet.Unmarshal.int_to_protocol packet.proto with
          | Some `TCP -> tcp ~src ~dst payload
          | Some `UDP -> udp ~src ~dst payload
          | Some `ICMP | None -> default ~proto:packet.proto ~src ~dst payload

  let connect
      ?(ip=Ipaddr.V4.any)
      ?(network=Ipaddr.V4.Prefix.make 0 Ipaddr.V4.any)
      ?(gateway=None) clock ethif arp =
    match Ipaddr.V4.Prefix.mem ip network with
    | false ->
      Log.warn (fun f -> f "IPv4: ip %a is not in the prefix %a"
                   Ipaddr.V4.pp ip Ipaddr.V4.Prefix.pp network);
      Lwt.fail_with "given IP is not in the network provided"
    | true ->
      Arpv4.set_ips arp [ip] >>= fun () ->
      (* TODO currently hardcoded to 256KB, should be configurable
         and maybe limited per-src/dst-ip as well? *)
      let cache = Fragments.Cache.empty (1024 * 256) in
      let t = { ethif; arp; ip; clock; network; gateway ; cache } in
      Lwt.return t

  let disconnect _ = Lwt.return_unit

  let set_ip t ip =
    t.ip <- ip;
    (* Inform ARP layer of new IP *)
    Arpv4.set_ips t.arp [ip]

  let get_ip t = [t.ip]

  let pseudoheader t ?src dst proto len =
    let src = match src with None -> t.ip | Some x -> x in
    Ipv4_packet.Marshal.pseudoheader ~src ~dst ~proto len

  let src t ~dst:_ = t.ip

  type uipaddr = Ipaddr.t
  let to_uipaddr ip = Ipaddr.V4 ip
  let of_uipaddr = Ipaddr.to_v4

  let mtu t = Ethif.mtu t.ethif - Ipv4_wire.sizeof_ipv4

end
