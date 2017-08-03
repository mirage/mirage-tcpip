open Common

let test_unmarshal_with_options () =
  let datagram = Cstruct.create 40 in
  Cstruct.blit_from_string ("\x46\xc0\x00\x28\x00\x00\x40\x00\x01\x02" ^
                            "\x42\x49\xc0\xa8\x01\x08\xe0\x00\x00\x16\x94\x04\x00\x00\x22" ^
                            "\x00\xfa\x02\x00\x00\x00\x01\x03\x00\x00\x00\xe0\x00\x00\xfb") 0 datagram 0 40;
  match Ipv4_packet.Unmarshal.of_cstruct datagram with
  | Result.Ok ({Ipv4_packet.options ; _}, payload) ->
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
  | Result.Ok ({Ipv4_packet.options ; _}, payload) ->
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
  let ip = { Ipv4_packet.src; dst; proto = 17; ttl; options = (Cstruct.of_string "aaaa") } in
  let payload = Cstruct.of_string "abcdefgh" in
  let tmp = Ipv4_packet.Marshal.make_cstruct ~payload_len:(Cstruct.len payload) ip in
  let tmp = Cstruct.concat [tmp; payload] in
  Ipv4_packet.Unmarshal.of_cstruct tmp
  |> Alcotest.(check (result (pair ipv4_packet cstruct) string)) "Loading an IP packet with IP options" (Ok (ip, payload));
  Lwt.return_unit

let suite = [
  "unmarshal ip datagram with options", `Quick, test_unmarshal_with_options;
  "unmarshal ip datagram without options", `Quick, test_unmarshal_without_options;
  "unmarshal ip datagram with no payload & hlen > 5", `Quick, test_unmarshal_regression;
  "size", `Quick, test_size;
]
