open Lwt.Infix

let failf fmt = Fmt.kstrf Alcotest.fail fmt

let or_error name fn t =
  fn t >>= function
  | Error _ -> failf "or_error starting %s" name
  | Ok t    -> Lwt.return t

let expect_error error name fn t =
  fn t >>= function
  | Error error2 when error2 = error -> Lwt.return t
  | _  -> failf "expected error on %s" name

let ipv4_packet = Alcotest.testable Ipv4_packet.pp Ipv4_packet.equal
let udp_packet = Alcotest.testable Udp_packet.pp Udp_packet.equal
let tcp_packet = Alcotest.testable Tcp.Tcp_packet.pp Tcp.Tcp_packet.equal
let cstruct = Alcotest.testable Cstruct.hexdump_pp Cstruct.equal

let sequence =
  let eq x y = Tcp.Sequence.compare x y = 0 in
  Alcotest.testable Tcp.Sequence.pp eq

let options = Alcotest.testable Tcp.Options.pp Tcp.Options.equal
