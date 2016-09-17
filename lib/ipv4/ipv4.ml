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
open Result

let src = Logs.Src.create "ipv4" ~doc:"Mirage IPv4"
module Log = (val Logs.src_log src : Logs.LOG)


(* TODO: maybe with some care this could be reused for tcp window as well,
 * to resolve overlapping segments.
 * Probably should hide the type instead of leak it to the caller?*)
module Data_interval = struct
  type t = (Cstruct.uint16 * Cstruct.uint16 * Cstruct.t) list



  (* intervals is an already orderered list of (start, end, data)
   * Add the new interval to the list, resolving overlapping data.
   * returns the amount of data really added (can be less than original
   * payload if there was overlaping) and the new list
   *
   * New fragments override data already received that overlaps with it.
   * See http://www.cs.bu.edu/~goldbe/papers/NTPattack.pdf for a discussion
   * 'Exploiting overlapping IPv4 fragments'
   * *)
  let rec merge_interval intervals i_offset i_end i_payload =
      match intervals with
      | [] ->
           Cstruct.len i_payload, [(i_offset, i_end, i_payload )]

           (*   [(10,20)|_]   (20,30) *)
      | (offset, eend, payload) :: rest when i_offset >= eend ->
          let incr, rest2 = merge_interval rest i_offset i_end i_payload in
          incr, (offset, eend, payload) :: rest2

           (*   [(10,20)|_]   (5,10) *)
      | (offset, _eend, _payload) :: _rest when i_end <= offset  ->
           Cstruct.len i_payload, (i_offset, i_end, i_payload) :: intervals

           (*   [(10,20)|_]   (15,40) *)
           (*   [(10,20)|_]   (15,18) *)
      | (offset, eend, payload) :: rest when offset < i_offset ->
              let to_keep = i_offset - offset in
              let cut_before,cut_after = Cstruct.split payload to_keep in
              let incr, rest2 = merge_interval ((i_offset, eend, cut_after) ::rest) i_offset i_end i_payload in
              incr ,  (offset, i_offset, cut_before) :: rest2

           (*   [(10,20)|_]   (10,18) *)
      | (_offset, eend, payload) :: rest when eend > i_end ->
              let to_keep = eend - i_end in
              let cutoff = Cstruct.len payload - to_keep in
              let cut_after = Cstruct.sub payload  cutoff to_keep in
              Cstruct.len i_payload - cutoff,  (i_offset, i_end, i_payload) :: (i_end, i_end + cutoff, cut_after) :: rest

              (*old fragment completely overlap into new one, discard the old *)
      | (_offset, _eend, payload) :: rest ->
              let incr, rest2 = merge_interval rest i_offset i_end i_payload in
              incr - (Cstruct.len payload),  rest2


    (* Split given buffer list into N buffer list of capped size*)
    let split_in length bufs =
        let rec split_aux max_frag_size left current_frag frags = function
            | [] ->
                    if Cstruct.lenv current_frag == 0 then
                        List.rev frags
                    else
                        List.rev ((List.rev current_frag)  :: frags)
            | buf :: rest when Cstruct.len buf <= left ->
                split_aux max_frag_size (left - Cstruct.len buf) (buf :: current_frag) frags rest
            | buf :: rest ->
                let buf1,buf2 = Cstruct.split buf left in
                let frags2 = (List.rev (buf1 :: current_frag)) :: frags in
                split_aux max_frag_size max_frag_size [] frags2 (buf2 :: rest) in
        split_aux length length [] [] bufs
end


module Make(Ethif: V1_LWT.ETHIF) (Arpv4 : V1_LWT.ARP) (Time:V1_LWT.TIME) = struct

  (** IO operation errors *)
  type error = [
    | `Unknown of string (** an undiagnosed error *)
    | `Unimplemented     (** operation not yet implemented in the code *)
  ]

  type ethif = Ethif.t
  type 'a io = 'a Lwt.t
  type buffer = Cstruct.t
  type ipaddr = Ipaddr.V4.t
  type prefix = Ipaddr.V4.t
  type callback = src:ipaddr -> dst:ipaddr -> buffer -> unit Lwt.t

  type packet_frag_acc =   {ip_header : Ipv4_packet.t;
                     mutable last_fragment_received : bool;
                     mutable last_offset : Cstruct.uint16;
                     mutable received : Cstruct.uint16;
                     mutable fragments : Data_interval.t
                    }

                (*packet id * src * dst * proto*)
  type frag_key = Cstruct.uint16 * Ipaddr.V4.t * Ipaddr.V4.t * Cstruct.uint8

  type t = {
    ethif : Ethif.t;
    arp : Arpv4.t;
    mutable ip: Ipaddr.V4.t;
    mutable netmask: Ipaddr.V4.t;
    mutable gateways: Ipaddr.V4.t list;
    frag_table : (frag_key, packet_frag_acc) Hashtbl.t
  }

  module Routing = struct

    exception No_route_to_destination_address of Ipaddr.V4.t

    let is_local t ip =
      let ipand a b = Int32.logand (Ipaddr.V4.to_int32 a) (Ipaddr.V4.to_int32 b) in
      (ipand t.ip t.netmask) = (ipand ip t.netmask)

    (* RFC 1112: 01-00-5E-00-00-00 ORed with lower 23 bits of the ip address *)
    let mac_of_multicast ip =
      let ipb = Ipaddr.V4.to_bytes ip in
      let macb = Bytes.create 6 in
      Bytes.set macb 0 (Char.chr 0x01);
      Bytes.set macb 1 (Char.chr 0x00);
      Bytes.set macb 2 (Char.chr 0x5E);
      Bytes.set macb 3 (Char.chr ((Char.code ipb.[1]) land 0x7F));
      Bytes.set macb 4 (Bytes.get ipb 2);
      Bytes.set macb 5 (Bytes.get ipb 3);
      Macaddr.of_bytes_exn macb

    let destination_mac t =
      function
      |ip when ip = Ipaddr.V4.broadcast || ip = Ipaddr.V4.any -> (* Broadcast *)
        Lwt.return Macaddr.broadcast
      |ip when is_local t ip -> (* Local *)
        Arpv4.query t.arp ip >>= begin function
          | `Ok mac -> Lwt.return mac
          | `Timeout -> Lwt.fail (No_route_to_destination_address ip)
        end
      |ip when Ipaddr.V4.is_multicast ip ->
        Lwt.return (mac_of_multicast ip)
      |ip -> begin (* Gateway *)
          match t.gateways with
          |hd::_ ->
            Arpv4.query t.arp hd >>= begin function
              | `Ok mac -> Lwt.return mac
              | `Timeout ->
                Log.info (fun f -> f "IP.output: could not send to %a: failed to contact gateway %a"
                             Ipaddr.V4.pp_hum ip Ipaddr.V4.pp_hum hd);
                Lwt.fail (No_route_to_destination_address ip)
            end
          |[] ->
            Log.info (fun f -> f "IP.output: no route to %a (no default gateway is configured)" Ipaddr.V4.pp_hum ip);
            Lwt.fail (No_route_to_destination_address ip)
        end
  end


  let set_dst_dmac_and_id ~dmac frame =
    let open Ipv4_wire in
    Ethif_wire.set_ethernet_dst dmac 0 frame;
    let buf = Cstruct.shift frame Ethif_wire.sizeof_ethernet in
    (* Set the mutable values in the ipv4 header *)
    set_ipv4_id buf (Random.int 65535) (* TODO *)

  let complete_len_and_checksum frame ~tlen =
    let open Ipv4_wire in
    let buf = Cstruct.shift frame Ethif_wire.sizeof_ethernet in
    set_ipv4_len buf tlen;
    set_ipv4_csum buf 0;
    let checksum = Tcpip_checksum.ones_complement buf in
    set_ipv4_csum buf checksum

  let adjust_output_header ~dmac ~tlen frame =
    set_dst_dmac_and_id ~dmac frame;
    complete_len_and_checksum ~tlen frame


  let allocate_frame t ~(dst:ipaddr) ~(proto : [`ICMP | `TCP | `UDP]) : (buffer * int) =
    let open Ipv4_wire in
    let ethernet_frame = Io_page.to_cstruct (Io_page.get 1) in
    let len = Ethif_wire.sizeof_ethernet + sizeof_ipv4 in
    let eth_header = Ethif_packet.({ethertype = Ethif_wire.IPv4;
                                    source = Ethif.mac t.ethif;
                                    destination = Macaddr.broadcast}) in
    match Ethif_packet.Marshal.into_cstruct eth_header ethernet_frame with
    | Error s -> 
      Log.info (fun f -> f "IP.allocate_frame: could not print ethernet header: %s" s);
      raise (Invalid_argument "writing ethif header to ipv4.allocate_frame failed")
    | Ok () ->
      let buf = Cstruct.shift ethernet_frame Ethif_wire.sizeof_ethernet in
      (* TODO: why 38 for TTL? *)
      let ipv4_header = Ipv4_packet.({options = Cstruct.create 0;
                                      src = t.ip; dst; ttl = 38; 
                                      id = 1000; (* TODO: random? *)
                                      more_frags = false; frag_offset = 0;
                                      proto = Ipv4_packet.Marshal.protocol_to_int proto; }) in
      (* set the payload to 0, since we don't know what it'll be yet *)
      (* the caller needs to then use [writev] or [write] to output the buffer;
         otherwise length, id, and checksum won't be set properly *)
      match Ipv4_packet.Marshal.into_cstruct ~payload:(Cstruct.create 0) ipv4_header buf with
      | Error s ->
        Log.info (fun f -> f "IP.allocate_frame: could not print IPv4 header: %s" s);
        raise (Invalid_argument "writing ipv4 header to ipv4.allocate_frame failed")
      | Ok () ->
        (ethernet_frame, len)

  let ethif_mtu (_network:ethif) =
      (* TODO:  network layer should expose this *)
      1500


  (* For each fragment to send, prepend with corresponding ip header *)
  let build_fragment_packets orig_frame effective_mtu bufs =
    let open Ipv4_wire in
    let rec build_fragment_packets_aux offset orig_frame = function
      | frag :: rest ->
          (* copy the base ip header, then modify it with fragment-specific bits *)
          let frag_len = Cstruct.lenv frag in 
          let h = Cstruct.create (Cstruct.len orig_frame) in
          Cstruct.blit orig_frame 0 h 0 (Cstruct.len orig_frame);
          let ip_header = Cstruct.shift h Ethif_wire.sizeof_ethernet in
          let tlen = Cstruct.len orig_frame + frag_len - Ethif_wire.sizeof_ethernet in
          if rest == [] then
            set_ipv4_off ip_header offset
           else (
            (* more fragments flag *)
            set_ipv4_off ip_header (offset lor (1 lsl 13))
           );
        complete_len_and_checksum ~tlen h;
        let noffset = (frag_len lsr 3) + offset in
        (h :: frag) :: build_fragment_packets_aux noffset orig_frame rest
      | [] ->
          [] in
    build_fragment_packets_aux 0 orig_frame (Data_interval.split_in effective_mtu bufs)

  let writev t frame bufs =
    let v4_frame = Cstruct.shift frame Ethif_wire.sizeof_ethernet in
    let dst = Ipaddr.V4.of_int32 (Ipv4_wire.get_ipv4_dst v4_frame) in
    (* Something of a layer violation here, but ARP is awkward *)
    Routing.destination_mac t dst >|= Macaddr.to_bytes >>= fun dmac ->
    let mtu = (ethif_mtu t.ethif) - Ipv4_wire.sizeof_ipv4 in
    let payload_size = Cstruct.lenv bufs in
    if payload_size > mtu then (
        set_dst_dmac_and_id ~dmac frame;
        let effective_mtu = mtu land (lnot 7) in
        let fragments = build_fragment_packets frame effective_mtu bufs in
        Lwt_list.iter_s (fun complete_frag -> Ethif.writev t.ethif complete_frag) fragments
    ) else (
        let tlen = Cstruct.len frame + payload_size - Ethif_wire.sizeof_ethernet in
        adjust_output_header ~dmac ~tlen frame;
        Ethif.writev t.ethif (frame :: bufs)
    )

  let write t frame buf =
    writev t frame [buf]

  let upcall ~tcp ~udp ~default packet payload =
      let open Ipv4_packet in
      match Unmarshal.int_to_protocol packet.proto, Cstruct.len payload with
      | Some _, 0 ->
        (* Don't pass on empty buffers as payloads to known protocols, as they have no relevant headers *)
        Lwt.return_unit
      | None, 0 -> (* we don't know anything about the protocol; an empty
                      payload may be meaningful somehow? *)
        default ~proto:packet.proto ~src:packet.src ~dst:packet.dst payload
      | Some `TCP, _ -> tcp ~src:packet.src ~dst:packet.dst payload
      | Some `UDP, _ -> udp ~src:packet.src ~dst:packet.dst payload
      | Some `ICMP, _ | None, _ ->
        default ~proto:packet.proto ~src:packet.src ~dst:packet.dst payload


  let input_fragmented frag_table ~tcp ~udp ~default packet payload =
      let open Ipv4_packet in
      let frag_offset = packet.frag_offset lsl 3 in
      let key = (packet.id, packet.src, packet.dst, packet.proto) in
      let received = Cstruct.len payload in
      let frag_end = frag_offset + received in
      let is_last_frag = not packet.more_frags in
      if (received land 7 == 0 || is_last_frag) && frag_end <= 65535 - Ipv4_wire.sizeof_ipv4 then (
          match try Some(Hashtbl.find frag_table key) with |Not_found -> None  with
          | None  ->
              let fragments = [frag_offset, frag_end, payload] in
              Hashtbl.add frag_table key 
                {ip_header=packet; 
                 last_fragment_received = is_last_frag;
                 last_offset = frag_end;
                 received; fragments};
              Lwt.async (fun () -> Time.sleep_ns (Duration.of_sec 15) >>= fun () -> 
                         Hashtbl.remove frag_table key; Lwt.return_unit);
              Lwt.return_unit

          (* If last fragment already received, new one can't be after it. 
           * If this is the last fragment, it can't end before the last one received. *)
          | Some(f) when ((not f.last_fragment_received && not is_last_frag) ||
                         (f.last_fragment_received && frag_end <= f.last_offset) ||
                         (is_last_frag && frag_end >= f.last_offset)) ->
              let incr,new_list = Data_interval.merge_interval f.fragments frag_offset frag_end payload in
              f.last_fragment_received <- f.last_fragment_received || is_last_frag;
              f.last_offset <- max frag_end f.last_offset;
              let new_size = f.received + incr in
              if f.last_fragment_received && new_size == f.last_offset then (
                Hashtbl.remove frag_table key;
                let payload = Cstruct.concat (List.map (fun (_, _, payload) -> payload) new_list) in
                upcall ~tcp ~udp ~default packet payload
              ) else (
                f.fragments <- new_list;
                f.received <- new_size;
                Lwt.return_unit
              )
          | _ ->
                Lwt.return_unit
      ) else
        Lwt.return_unit

    

  (* TODO: ought we to check to make sure the destination is relevant here?  currently we'll process all incoming packets, regardless of destination address *)
  let input t ~tcp ~udp ~default buf =
    let open Ipv4_packet in
    match Unmarshal.of_cstruct buf with
    | Error s ->
      Log.info (fun f -> f "IP.input: unparseable header (%s): %S" s (Cstruct.to_string buf));
      Lwt.return_unit
    | Ok (packet, payload) when packet.more_frags || packet.frag_offset > 0 ->
      input_fragmented t.frag_table ~tcp ~udp ~default packet payload
    | Ok (packet, payload) ->
      upcall ~tcp ~udp ~default packet payload


  let connect
      ?(ip=Ipaddr.V4.any)
      ?(netmask=Ipaddr.V4.any)
      ?(gateways=[]) ethif arp =
    let frag_table = Hashtbl.create 7 in
    let t = { ethif; arp; ip; netmask; gateways ; frag_table} in
    Lwt.return (`Ok t)

  let disconnect _ = Lwt.return_unit

  let set_ip t ip =
    t.ip <- ip;
    (* Inform ARP layer of new IP *)
    Arpv4.add_ip t.arp ip

  let get_ip t = [t.ip]

  let set_ip_netmask t netmask =
    t.netmask <- netmask;
    Lwt.return_unit

  let get_ip_netmasks t = [t.netmask]

  let set_ip_gateways t gateways =
    t.gateways <- gateways;
    Lwt.return_unit

  let get_ip_gateways { gateways; _ } = gateways

  let pseudoheader t ~dst ~proto len =
    Ipv4_packet.Marshal.pseudoheader ~src:t.ip ~dst ~proto len

  let checksum frame bufs =
    let packet = Cstruct.shift frame Ethif_wire.sizeof_ethernet in
    Ipv4_wire.set_ipv4_csum packet 0;
    Tcpip_checksum.ones_complement_list (packet :: bufs)

  let src t ~dst:_ =
    t.ip

  type uipaddr = Ipaddr.t
  let to_uipaddr ip = Ipaddr.V4 ip
  let of_uipaddr = Ipaddr.to_v4

end
