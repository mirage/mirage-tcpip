(*
 * Copyright (c) 2016 Pablo Polvorin <pablo@polvorin.com.ar>
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


module VNETIF_STACK = Vnetif_common.VNETIF_STACK(Vnetif_backends.Basic)
module Time = Vnetif_common.Time
module V = Vnetif.Make(Vnetif_backends.Basic)
module E = Ethif.Make(V)
module A = Static_arp.Make(E)(Mclock)(Time) 
module I = Ipv4.Make(E)(A)(Time)
module UDP =  Udp.Make(I)


open Lwt.Infix
let or_error = Common.or_error
let cstruct = Common.cstruct


(* addresses used by test cases *)
let receiver_address = Ipaddr.V4.of_string_exn "10.0.0.101"
let sender_address = Ipaddr.V4.of_string_exn "10.0.0.100"
let gw = Ipaddr.V4.of_string_exn "10.0.0.1"
let netmask = Ipaddr.V4.of_string_exn "255.255.255.0"

let create_ip_stack backend address netmask gw=
  or_error "clock" Mclock.connect () >>= fun clock -> 
  or_error "backend" V.connect backend >>= fun netif ->
  or_error "ethif" E.connect netif >>= fun ethif ->
  or_error "arpv4" (A.connect ethif) clock >>= fun arpv4 ->
  or_error "ipv4" (I.connect ethif) arpv4 >>= fun ip ->
  I.set_ip ip address >>= fun () ->
  I.set_ip_netmask ip netmask >>= fun () ->
  I.set_ip_gateways ip gw >>= fun () ->
  Lwt.return (netif, ethif, arpv4, ip)


let ipaddr =
  let module M = struct
    type t = Ipaddr.V4.t
    let pp fmt t = Format.fprintf fmt "%s" (Ipaddr.V4.to_string t)
    let equal p q = (Ipaddr.V4.compare p q) = 0
  end in
  (module M : Alcotest.TESTABLE with type t = M.t)


(* Sends a udp packet of the given size, check that it is received *)
let test_udp_packet n () =
    let backend = VNETIF_STACK.create_backend () in
    VNETIF_STACK.create_stack backend sender_address netmask [gw] >>= fun sender_stackv4 ->
    VNETIF_STACK.create_stack backend receiver_address netmask [gw] >>= fun receiver_stackv4 ->
    let sender_udpv4 = (VNETIF_STACK.Stackv4.udpv4 sender_stackv4) in

    let recv_stream, pushf = Lwt_stream.create () in
   
    VNETIF_STACK.Stackv4.listen_udpv4 receiver_stackv4 ~port:2000  (fun ~src ~dst ~src_port buf -> 
                pushf (Some(src,dst,src_port,buf));
                Lwt.return_unit
    );
   
    let data = Cstruct.create_unsafe n in
    VNETIF_STACK.Stackv4.UDPV4.write  ~src_port:1000 ~dst:receiver_address ~dst_port:2000 sender_udpv4 data >>= fun () ->
    Lwt_stream.next recv_stream >>= fun (src,dst,port,buf) ->
    Alcotest.(check ipaddr) "Sender address is wrong" sender_address src;
    Alcotest.(check ipaddr) "Receiver address is wrong" receiver_address dst;
    Alcotest.(check int) "Source port is not the expecting one" 1000 port;
    Alcotest.(check cstruct) "Assambled packet is not the expected one" data buf;
    Lwt.return_unit



(* 
 * Manually craft fragments, as if it was done by some IP stack. Used to test specific
 * fragment convinations (different ordering, weird overlaps, etc
 * This is somewhat repeated and really hacky, there is similar code on the IPV4 module itself.
 *)
let build_packets ipv4 dst dmac fragments =
    let open Ipv4_wire in
    let id = Random.int 65535 in
    List.map (fun (offset, data, is_last) ->
            let frame,len = I.allocate_frame ipv4 ~dst ~proto:`UDP in
            let header = Cstruct.set_len frame len in
            Ethif_wire.set_ethernet_dst (Macaddr.to_bytes dmac) 0 header;
            let ip_header = Cstruct.sub header Ethif_wire.sizeof_ethernet sizeof_ipv4 in
            let tlen = len + Cstruct.len data - Ethif_wire.sizeof_ethernet in
            set_ipv4_len ip_header tlen;
            set_ipv4_proto ip_header 123; (* not UDP, I want it to reach the default callback *)
            if is_last then (
                set_ipv4_off ip_header (offset lsr 3);
            ) else (
                set_ipv4_off ip_header ((offset lsr 3) lor (1 lsl 13))
            );
            set_ipv4_id ip_header id;
            set_ipv4_csum ip_header (Tcpip_checksum.ones_complement ip_header);
            [header ; data]) fragments

(* Listen for default packets.  So we don't need to bother on generating/parsing correct udp headers *)
let default_listen netif ethif arpv4 ip fn =
  let noop = fun ~src:_ ~dst:_ _buf -> Lwt.return_unit in
  Lwt.async (fun() -> V.listen netif
                    ( E.input ethif ~arpv4:(A.input arpv4)
                     ~ipv6:(fun _ -> Lwt.return_unit)
                     ~ipv4: (I.input ip 
                                ~tcp:noop 
                                ~udp:noop
                                ~default:fn)) )

(* from rosettacode *)
let rec permutations l =
   let n = List.length l in
   if n = 1 then [l] else
   let rec sub e = function
      | [] -> failwith "sub"
      | h :: t -> if h = e then t else h :: sub e t in
   let rec aux k =
      let e = List.nth l k in
      let subperms = permutations (sub e l) in
      let t = List.map (fun a -> e::a) subperms in
      if k < n-1 then List.rev_append t (aux (k+1)) else t in
   aux 0




(* Test a list of fragments, in different permutations. Checks that the complete packet
 * is assembled, acording to is_complete true|false *)
let test_frags is_complete expected_packet cases () =
    let test_fragments fragments is_complete =
        let backend = VNETIF_STACK.create_backend () in
        create_ip_stack backend receiver_address netmask [gw] >>= fun (receiver_netif, receiver_ethif, receiver_arpv4, receiver_ip) ->
        create_ip_stack backend sender_address netmask [gw] >>= fun (_sender_netif, sender_ethif, sender_arpv4, sender_ip) ->
            (* This sender IP stack is really only used to allocate frames,  on these tests
             * packets are injected directly to the network bypassing it *)

        A.add_entry sender_arpv4 receiver_address (E.mac receiver_ethif);
        A.add_entry receiver_arpv4 sender_address (E.mac sender_ethif);
        let recv_stream, pushf = Lwt_stream.create () in
        default_listen receiver_netif receiver_ethif receiver_arpv4 receiver_ip 
                (fun ~proto ~src ~dst payload ->  pushf(Some(proto,src,dst,payload)); Lwt.return_unit );

        let packets = build_packets sender_ip receiver_address (E.mac receiver_ethif) fragments in
        Lwt_list.iter_s (E.writev sender_ethif) packets >>= fun () ->

        Lwt.pick [
            (
            Lwt_stream.next recv_stream >>= fun (_proto,src,dst,buf) ->
            Alcotest.(check ipaddr) "Sender address is wrong" sender_address src;
            Alcotest.(check ipaddr) "Receiver address is wrong" receiver_address dst;
            Alcotest.(check cstruct) "Assambled packet is not the expected one" expected_packet buf;
            Lwt.return_true
            ) ;

            Time.sleep_ns (Duration.of_ms 100) >>= fun () -> Lwt.return_false
        ] >>= fun r ->
        Alcotest.(check bool) "Packet assembly failed" is_complete r;
        Lwt.return_unit in


    (* actually do the test on each case *)
    Lwt_list.iter_s (fun permutation ->
                test_fragments permutation is_complete
    ) cases

let rec process_defs = function
    | [] -> []
    | (start,eend, base_packet) :: rest ->
            let data = Cstruct.sub base_packet start (eend - start) in
            (start,data, rest == []) :: process_defs rest


let suite =
    (* Two buffers.  Buffer s is the correct, expected one.  buffer a (attacker) are fragments injected
     * that must be latter overriden by newly arriving fragments *)
    let s = Cstruct.create_unsafe 1500 in
    let a = Cstruct.create_unsafe 1500 in
    Cstruct.memset s 0;
    Cstruct.memset a 1;
    [
        "udp len 10", `Quick, test_udp_packet 10;
        "udp len 1000", `Quick, test_udp_packet 1000;
        "udp len 1500", `Quick, test_udp_packet 1500;
        "udp len 1501", `Quick, test_udp_packet 1501;
        "udp len 2501", `Quick, test_udp_packet 2501;
        "udp len 52501", `Quick, test_udp_packet 52501;

        (* test do the fragment just as requested here, so must be sure that all but the last one
         * had a length that is multiple of 8 bytes *)
        "frag normal", `Quick, test_frags true s (permutations (process_defs [(0,200,s); (200,504,s); (504,1500,s)]));
        "frag included", `Quick, test_frags true s (permutations (process_defs [(0,504,s); (16,504,s); (504,1500,s)]));
        "frag included 2", `Quick, test_frags true s (permutations (process_defs [(0,504,s); (800,1000,s); (504,1500,s)]));
        "frag repeated", `Quick, test_frags true s (permutations (process_defs [(0,504,s); (504,1500,s); (504,1500,s)]));
        "empty frag", `Quick, test_frags true s (permutations (process_defs [(0,504,s); (504,504,s); (504,1500,s)]));
        "frag overlaping", `Quick, test_frags true s (permutations (process_defs [(0,504,s); (200,600,s); (504,1500,s)]));
        "frag overlaping 2", `Quick, test_frags true s (permutations (process_defs [(0,504,s); (200,600,s); (600,1500,s)]));
        "frag overlaping 3", `Quick, test_frags true s (permutations (process_defs [(0,504,s); (504,1000,s); (600,1500,s)]));

        (* New fragments must override already receiced ones *)
        "frag overlap exploiting(ntp attack)", `Quick, test_frags true s [ process_defs [(0,504,a); (600,608,a); (0,600,s); (504, 1500,s)] ] ;
        "frag overlap exploiting(ntp attack) 2", `Quick, test_frags true s [ process_defs [(0,504,a); (600,608,a); (64,128,s); (0, 800,s); (504, 1500,s)] ] ;
        "frag overlap exploiting(ntp attack) 3", `Quick, test_frags true s [ process_defs [(0,64,a); (600,608,a); (0, 128,s); (24,504,s); (504, 1500,s)] ] ;

        "missing fragment", `Quick, test_frags false s (permutations (process_defs [(0,200,s); (600,1500,s)]));
]
