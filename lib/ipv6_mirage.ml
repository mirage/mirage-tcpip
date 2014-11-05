let (>>=) = Lwt.(>>=)
let (>|=) = Lwt.(>|=)

module Make (E : V2_LWT.ETHIF) (T : V2_LWT.TIME) (C : V2.CLOCK) = struct
  type ethif    = E.t
  type 'a io    = 'a Lwt.t
  type buffer   = Cstruct.t
  type ipv6addr = Ipaddr.V6.t
  type callback = src:ipv6addr -> dst:ipv6addr -> buffer -> unit Lwt.t

  type t =
    { ethif : E.t;
      mutable state : Ipv6.state;
      mutable nc : Ipv6.nb_info Ipv6.IpMap.t }

  let id { ethif } = ethif

  let rec tick state =
    Printf.printf "Ticking...\n%!";
    run state @@ Ipv6.tick ~st:state.state ~nc:state.nc ~now:(Ipv6.Time.of_float @@ C.time ())

  and run state (st, nc, pkts, timers) =
    state.state <- st;
    state.nc <- nc;
    List.iter (fun dt ->
        let dt = Ipv6.Time.Span.to_float dt in
        Printf.printf "Setting up a timer in %.1fs\n%!" dt;
        Lwt.ignore_result (T.sleep @@ dt >>= fun () -> tick state)) timers;
    Lwt_list.iter_s (E.writev state.ethif) pkts

  let input state ~tcp ~udp ~default buf =
    let r, pkts_timers =
      Ipv6.handle_packet ~now:(Ipv6.Time.of_float @@ C.time ()) ~st:state.state ~nc:state.nc buf
    in
    run state pkts_timers >>= fun () ->
    match r with
    | `None -> Lwt.return_unit
    | `Tcp (src, dst, pkt) -> tcp ~src ~dst pkt
    | `Udp (src, dst, pkt) -> udp ~src ~dst pkt
    | `Default (proto, src, dst, pkt) -> default ~proto ~src ~dst pkt

  let connect ethif =
    let state = {state = Ipv6.create (E.mac ethif); nc = Ipv6.IpMap.empty; ethif} in
    T.sleep 10.0 >>= fun () ->
    Printf.printf "Starting\n%!";
    run state @@
    Ipv6.add_ip ~now:(Ipv6.Time.of_float @@ C.time ()) ~st:state.state ~nc:state.nc
      (Ipv6.Macaddr.link_local_addr (E.mac ethif)) >>= fun () ->
    Lwt.return (`Ok state)
end
