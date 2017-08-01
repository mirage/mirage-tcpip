let (>>=) = Lwt.(>>=)

let fail fmt = Fmt.kstrf Alcotest.fail fmt

let or_error name fn t =
  fn t >>= function
  | Error _ -> fail "or_error starting %s" name
  | Ok t    -> Lwt.return t

let expect_error error name fn t =
  fn t >>= function
  | Error error2 when error2 = error -> Lwt.return t
  | _    -> fail "expected error on %s" name

let cstruct =
  let module M = struct
    type t = Cstruct.t
    let pp = Cstruct.hexdump_pp
    let equal = Cstruct.equal
  end in
  (module M : Alcotest.TESTABLE with type t = M.t)

let ipv4_packet = (module Ipv4_packet : Alcotest.TESTABLE with type t = Ipv4_packet.t)
let udp_packet = (module Udp_packet : Alcotest.TESTABLE with type t = Udp_packet.t)
let tcp_packet = (module Tcp.Tcp_packet : Alcotest.TESTABLE with type t = Tcp.Tcp_packet.t)

let sequence =
  let module M = struct
    type t = Tcp.Sequence.t
    let pp = Tcp.Sequence.pp
    let equal x y = (=) 0 @@ Tcp.Sequence.compare x y
  end in
  (module M : Alcotest.TESTABLE with type t = M.t)
