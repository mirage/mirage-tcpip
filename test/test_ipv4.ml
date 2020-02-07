open Common

let test_unmarshal_with_options () =
  let datagram = Cstruct.create 40 in
  Cstruct.blit_from_string ("\x46\xc0\x00\x28\x00\x00\x40\x00\x01\x02" ^
                            "\x42\x49\xc0\xa8\x01\x08\xe0\x00\x00\x16\x94\x04\x00\x00\x22" ^
                            "\x00\xfa\x02\x00\x00\x00\x01\x03\x00\x00\x00\xe0\x00\x00\xfb") 0 datagram 0 40;
  match Ipv4_packet.Unmarshal.of_cstruct datagram with
  | Ok ({Ipv4_packet.options ; _}, payload) ->
      Alcotest.(check int) "options" (Cstruct.len options) 4;
      Alcotest.(check int) "payload" (Cstruct.len payload) 16;
      Lwt.return_unit
  | _ ->
      Alcotest.fail "Fail to parse ip packet with options"


let test_unmarshal_without_options () =
  let datagram = Cstruct.create 40 in
  Cstruct.blit_from_string ("\x45\x00\x00\x28\x19\x29\x40\x00\x34\x06\x98\x75\x36\xb7" ^
                            "\x9c\xca\xc0\xa8\x01\x08\x00\x50\xca\xa6\x6f\x19\xf4\x76" ^
                            "\x00\x00\x00\x00\x50\x04\x00\x00\xec\x27\x00\x00") 0 datagram 0 40;
  match Ipv4_packet.Unmarshal.of_cstruct datagram with
  | Ok ({Ipv4_packet.options ; _}, payload) ->
      Alcotest.(check int) "options" (Cstruct.len options) 0;
      Alcotest.(check int) "payload" (Cstruct.len payload) 20;
      Lwt.return_unit
  | _ ->
      Alcotest.fail "Fail to parse ip packet with options"

let test_unmarshal_regression () =
  let p = Cstruct.of_string "\x49\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30" in
  Alcotest.(check (result reject pass))
    "correctly return error for bad packet"
    (Error "any") (Ipv4_packet.Unmarshal.of_cstruct p);
  Lwt.return_unit

let test_size () =
  let src = Ipaddr.V4.of_string_exn "127.0.0.1" in
  let dst = Ipaddr.V4.of_string_exn "127.0.0.2" in
  let ttl = 64 in
  let ip = { Ipv4_packet.src; dst; proto = 17; ttl; id = 0 ; off = 0 ; options = (Cstruct.of_string "aaaa") } in
  let payload = Cstruct.of_string "abcdefgh" in
  let tmp = Ipv4_packet.Marshal.make_cstruct ~payload_len:(Cstruct.len payload) ip in
  let tmp = Cstruct.concat [tmp; payload] in
  Ipv4_packet.Unmarshal.of_cstruct tmp
  |> Alcotest.(check (result (pair ipv4_packet cstruct) string)) "Loading an IP packet with IP options" (Ok (ip, payload));
  Lwt.return_unit

let test_packet =
  let src = Ipaddr.V4.of_string_exn "127.0.0.1" in
  let dst = Ipaddr.V4.of_string_exn "127.0.0.2" in
  let ttl = 64 in
  { Ipv4_packet.src; dst; proto = 17; ttl; id = 0 ; off = 0 ; options = (Cstruct.of_string "aaaa") }

let mf = 0x2000

let white = Cstruct.create 16
let black =
  let buf = Cstruct.create 16 in
  Cstruct.memset buf 0xFF ;
  buf
let gray =
  let buf = Cstruct.create 16 in
  Cstruct.memset buf 0x55 ;
  buf

let empty_cache = Fragments.Cache.empty 1000

let basic_fragments payload () =
  Alcotest.(check (option (pair ipv4_packet cstruct)) __LOC__
              (Some (test_packet, payload))
              (snd @@ Fragments.process empty_cache 0L test_packet payload)) ;
  let off_packet = { test_packet with off = 1 } in
  Alcotest.(check (option (pair ipv4_packet cstruct)) __LOC__
              None
              (snd @@ Fragments.process empty_cache 0L off_packet payload)) ;
  Lwt.return_unit

let basic_reassembly () =
  let more_frags = { test_packet with off = mf } in
  let cache, res = Fragments.process empty_cache 0L more_frags black in
  Alcotest.(check (option (pair ipv4_packet cstruct)) __LOC__ None res) ;
  let off_packet = { test_packet with off = 2 } in
  Alcotest.(check (option (pair ipv4_packet cstruct)) "reassembly of two segments works"
              (Some (test_packet, Cstruct.append black white))
              (snd @@ Fragments.process cache 0L off_packet white)) ;
  Lwt.return_unit

let basic_reassembly_timeout () =
  let more_frags = { test_packet with off = mf } in
  let cache, res = Fragments.process empty_cache 0L more_frags black in
  Alcotest.(check (option (pair ipv4_packet cstruct)) __LOC__ None res) ;
  let off_packet = { test_packet with off = 2 } in
  let below_max = Int64.sub Fragments.max_duration 1L in
  Alcotest.(check (option (pair ipv4_packet cstruct)) "even after just before max duration"
              (Some (test_packet, Cstruct.append black white))
              (snd @@ Fragments.process cache below_max off_packet white)) ;
  Alcotest.(check (option (pair ipv4_packet cstruct)) "none after max duration"
              None
              (snd @@ Fragments.process cache Fragments.max_duration off_packet white)) ;
  let more_off_packet = { test_packet with off = mf lor 2 } in
  let cache, res = Fragments.process cache below_max more_off_packet gray in
  Alcotest.(check (option (pair ipv4_packet cstruct)) __LOC__ None res) ;
  let final_packet = { test_packet with off = 4 } in
  Alcotest.(check (option (pair ipv4_packet cstruct)) __LOC__
              (Some (test_packet, Cstruct.concat [ black; gray; white]))
              (snd @@ Fragments.process cache below_max final_packet white)) ;
  Alcotest.(check (option (pair ipv4_packet cstruct)) __LOC__
              None
              (snd @@ Fragments.process cache Fragments.max_duration off_packet white)) ;
  Alcotest.(check (option (pair ipv4_packet cstruct)) __LOC__ None res) ;
  Lwt.return_unit

let reassembly_out_of_order () =
  let more_frags = { test_packet with off = mf } in
  let off_packet = { test_packet with off = 2 } in
  let cache, res = Fragments.process empty_cache 0L off_packet gray in
  Alcotest.(check (option (pair ipv4_packet cstruct)) __LOC__ None res) ;
  Alcotest.(check (option (pair ipv4_packet cstruct)) "reassembly of two segments works"
              (Some (test_packet, Cstruct.append black gray))
              (snd @@ Fragments.process cache 0L more_frags black)) ;
  Lwt.return_unit

let reassembly_multiple_out_of_order packets final_payload () =
  let _, res = List.fold_left (fun (cache, res) (off, payload) ->
      Alcotest.(check (option (pair ipv4_packet cstruct)) __LOC__ None res) ;
      let packet = { test_packet with off } in
      Fragments.process cache 0L packet payload)
      (empty_cache, None) packets
  in
  Alcotest.(check (option (pair ipv4_packet cstruct)) __LOC__
              (Some (test_packet, final_payload))
              res) ;
  Lwt.return_unit

let basic_overlaps () =
  let more_frags = { test_packet with off = mf } in
  let off_packet = { test_packet with off = 1 } in
  let cache, res = Fragments.process empty_cache 0L off_packet black in
  Alcotest.(check (option (pair ipv4_packet cstruct)) __LOC__ None res) ;
  Alcotest.(check (option (pair ipv4_packet cstruct)) __LOC__ None
              (snd @@ Fragments.process cache 0L more_frags white)) ;
  Lwt.return_unit

let basic_other_ip_flow () =
  let more_frags = { test_packet with off = mf } in
  let cache, res = Fragments.process empty_cache 0L more_frags black in
  let off_packet = { test_packet with off = 2 ; src = Ipaddr.V4.of_string_exn "127.0.0.2" } in
  Alcotest.(check (option (pair ipv4_packet cstruct)) __LOC__ None res) ;
  Alcotest.(check (option (pair ipv4_packet cstruct)) __LOC__ None
              (snd @@ Fragments.process cache 0L off_packet white)) ;
  let off_packet' = { test_packet with off = 2 ; proto = 25 } in
  Alcotest.(check (option (pair ipv4_packet cstruct)) __LOC__ None
              (snd @@ Fragments.process cache 0L off_packet' white)) ;
  Lwt.return_unit

let max_fragment () =
  let all_16 = [ white; gray; black; white;
                 white; gray; black; white;
                 white; gray; black; white;
                 white; gray; black ; gray ]
  in
  let (cache, res), off =
    List.fold_left (fun ((cache, res), off) payload ->
        Alcotest.(check (option (pair ipv4_packet cstruct)) __LOC__ None res) ;
        let r = Fragments.process cache 0L { test_packet with off = off lor mf } payload in
        (r, Cstruct.len payload / 8 + off))
      ((empty_cache, None), 0)
      all_16
  in
  Alcotest.(check (option (pair ipv4_packet cstruct)) __LOC__ None res) ;
  Alcotest.(check (option (pair ipv4_packet cstruct)) __LOC__
              (Some (test_packet, Cstruct.concat (all_16 @ [white ])))
              (snd @@ Fragments.process cache 0L { test_packet with off } white)) ;
  let cache, res = Fragments.process cache 0L { test_packet with off = off lor mf } white in
  Alcotest.(check (option (pair ipv4_packet cstruct)) __LOC__ None res) ;
  Alcotest.(check (option (pair ipv4_packet cstruct)) __LOC__
              None
              (snd @@ Fragments.process cache 0L { test_packet with off = off + 2 } black)) ;
  Lwt.return_unit

let none_returned packets () =
  let _, res = List.fold_left (fun (cache, res) (off, payload) ->
      Alcotest.(check (option (pair ipv4_packet cstruct)) __LOC__ None res) ;
      let packet = { test_packet with off } in
      Fragments.process cache 0L packet payload)
      (empty_cache, None) packets
  in
  Alcotest.(check (option (pair ipv4_packet cstruct)) __LOC__ None res) ;
  Lwt.return_unit

let ins_all_positions x l =
  let rec aux prev acc = function
    | [] -> List.rev ((prev @ [x]) :: acc)
    | hd::tl as l -> aux (prev @ [hd]) ((prev @ [x] @ l) :: acc) tl
  in
  aux [] [] l

let rec permutations = function
  | [] -> []
  | [x] -> [[x]]
  | x::xs -> List.fold_left (fun acc p -> acc @ ins_all_positions x p ) []
               (permutations xs)

let fragment_simple () =
  let hdr =
    { Ipv4_packet.src = Ipaddr.V4.localhost ; dst = Ipaddr.V4.localhost ;
      id = 0x42 ; off = 0 ; ttl = 10 ; proto = 10 ; options = Cstruct.empty }
  in
  let payload = Cstruct.create 1030 in
  let fs = Fragments.fragment ~mtu:36 hdr payload in
  (* 16 byte per packet -> 64 fragments (a 16 byte) + 1 (6 byte) *)
  Alcotest.(check int __LOC__ 65 (List.length fs));
  let second, last = List.hd fs, List.(hd (rev fs)) in
  Alcotest.(check int __LOC__ 26 (Cstruct.len last));
  match
    Ipv4_packet.Unmarshal.of_cstruct second,
    Ipv4_packet.Unmarshal.of_cstruct last
  with
  | Error e, _ -> Alcotest.fail ("failed to decode second fragment " ^ e)
  | _, Error e -> Alcotest.fail ("failed to decode last fragment " ^ e)
  | Ok (hdr, _payload), Ok (hdr', _payload') ->
    Alcotest.(check int __LOC__ (0x2000 lor 2) hdr.Ipv4_packet.off);
    Alcotest.(check int __LOC__ 0x42 hdr.Ipv4_packet.id);
    Alcotest.(check int __LOC__ 130 hdr'.Ipv4_packet.off);
    Alcotest.(check int __LOC__ 0x42 hdr'.Ipv4_packet.id);
    let fs' = Fragments.fragment ~mtu:36 hdr (Cstruct.sub payload 0 1024) in
    (* 16 byte per packet -> 64 fragments (a 16 byte) *)
    Alcotest.(check int __LOC__ 64 (List.length fs'));
    let second', last' = List.hd fs', List.(hd (rev fs')) in
    Alcotest.(check int __LOC__ 36 (Cstruct.len last'));
    match
      Ipv4_packet.Unmarshal.of_cstruct second',
      Ipv4_packet.Unmarshal.of_cstruct last'
    with
    | Error e, _ -> Alcotest.fail ("failed to decode second fragment' " ^ e)
    | _, Error e -> Alcotest.fail ("failed to decode last fragment' " ^ e)
    | Ok (hdr'', _payload''), Ok (hdr''', _payload''') ->
      Alcotest.(check int __LOC__ (0x2000 lor 2) hdr''.Ipv4_packet.off);
      Alcotest.(check int __LOC__ 0x42 hdr''.Ipv4_packet.id);
      Alcotest.(check int __LOC__ 128 hdr'''.Ipv4_packet.off);
      Alcotest.(check int __LOC__ 0x42 hdr'''.Ipv4_packet.id)

let suite = [
  "unmarshal ip datagram with options", `Quick, test_unmarshal_with_options;
  "unmarshal ip datagram without options", `Quick, test_unmarshal_without_options;
  "unmarshal ip datagram with no payload & hlen > 5", `Quick, test_unmarshal_regression;
  "size", `Quick, test_size ] @
  List.mapi (fun i size ->
      Printf.sprintf "basic fragment %d: payload %d" i size, `Quick, basic_fragments (Cstruct.create size))
    [ 0 ; 1 ; 2 ; 10 ; 100 ; 1000 ; 5000 ; 10000 ] @ [
    "basic reassembly", `Quick, basic_reassembly;
    "basic reassembly timeout", `Quick, basic_reassembly_timeout;
    "reassembly out of order", `Quick, reassembly_out_of_order ;
    "other ip flow", `Quick, basic_other_ip_flow ;
    "maximum amount of fragments", `Quick, max_fragment ] @
    List.mapi (fun i (packets, final) ->
      Printf.sprintf "ressembly multiple %d" i, `Quick,
      reassembly_multiple_out_of_order packets final)
    ([
      ([ (mf, white); (2, black) ], Cstruct.concat [white;black]);
      ([ (mf, black); (2, white) ], Cstruct.concat [black;white]);
      ([ (2, black); (mf, white) ], Cstruct.concat [white;black]);
      ([ (2, white); (mf, black) ], Cstruct.concat [black;white]);
      ([ (mf, Cstruct.create 984); (123, black)], Cstruct.concat [Cstruct.create 984;black]);
      ([ (mf, Cstruct.create 984); (123 lor mf, black); (125, gray)],
       Cstruct.concat [Cstruct.create 984;black;gray]);
      ([ (mf, Cstruct.create 1000); (125, (Cstruct.concat [black;black;black]))],
       Cstruct.concat [Cstruct.create 1000;black;black;black]);
    ]@
      List.map (fun x -> (x, Cstruct.concat [gray;white;black]))
        (permutations [ (mf, gray); (2 lor mf, white); (4, black)]) @
      List.map (fun x -> (x, Cstruct.concat [gray;white;black;Cstruct.create 10]))
        (permutations [ (mf, gray); (2 lor mf, white); (4 lor mf, black); (6, Cstruct.create 10)]) @
      List.map (fun x -> (x, Cstruct.concat [black;gray;white;black;gray]))
        (permutations [ (mf, black); (2 lor mf, gray); (4 lor mf, white); (6 lor mf, black); (8, gray)])
    ) @
  [ "nothing returned", `Quick, basic_overlaps ] @
  List.mapi (fun i packets ->
      Printf.sprintf "nothing returned %d" i, `Quick,
      none_returned packets)
    ([
      [ (mf, white); (1, black) ];
      [ (mf, black); (3, white) ];
      [ (mf, Cstruct.create 992); (124 lor mf, black);(126, gray)];
      [ (mf, Cstruct.create 1024); (128, black)];
    ] @
      permutations [ (mf, gray); (2 lor mf, white); (3, black)] @
      permutations [ (mf, gray); (2 lor mf, white); (5, black)] @
      permutations [ (mf, gray); (3 lor mf, white); (4, black)] @
      permutations [ (mf, gray); (3 lor mf, white); (5, black)] @
      permutations [ (mf, gray); (1 lor mf, white); (3, black)] @
      permutations [ (mf, gray); (1 lor mf, white); (4, black)] @
      permutations [ (mf, (Cstruct.append gray gray)); (3 lor mf, white)] @
      permutations [ (mf, (Cstruct.append gray gray)); (2 lor mf, white)] @
      permutations [ (mf, gray); (2 lor mf, white); (4 lor mf, black); (6 lor mf, gray)] @
      permutations [ (mf, gray); (2 lor mf, white); (4 lor mf, black); (5, gray)] @
      permutations [ (mf, gray); (4 lor mf, white); (4 lor mf, black); (6, gray)] @
      permutations [ (mf, gray); (1 lor mf, white); (3 lor mf, black); (5, gray)] @
      permutations [ (mf, gray); (2 lor mf, white); (4 lor mf, black); (7, gray)]
    ) @ [
    "simple fragment", `Quick, (fun () -> Lwt.return (fragment_simple ()))
  ]
