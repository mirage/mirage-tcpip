module W = Tcp.Window.Make(Vnetif_common.Clock) (* not sure whether we really need this *)

let default_window () =
  Tcp.Window.t ~tx_wnd_scale:2 ~rx_wnd_scale:2 ~rx_wnd:65535 ~tx_wnd:65535 ~rx_isn:Tcp.Sequence.zero ~tx_mss:(Some 1460) ~tx_isn:Tcp.Sequence.zero

let fresh_window () =
  let window = default_window () in
  Alcotest.(check bool) "should be no data in flight" false @@ Tcp.Window.tx_inflight window;
  Alcotest.(check bool) "no rexmits yet" false @@ Tcp.Window.max_rexmits_done window;
  Alcotest.(check int) "no traffic transferred yet" 0 @@ Tcp.Window.tx_totalbytes window;
  Alcotest.(check int) "no traffic received yet" 0 @@ Tcp.Window.rx_totalbytes window;
  Alcotest.(check int32) "should be able to send 65535 <<= 2 bytes" Int32.(mul 65535l 4l) @@ Tcp.Window.tx_wnd window;
  Alcotest.(check int32) "should be able to receive 65535 <<= 2 bytes" Int32.(mul 65535l 4l) @@ Tcp.Window.rx_wnd window;
  Lwt.return_unit


let suite = [
  "fresh window is sensible", `Quick, fresh_window;
]
