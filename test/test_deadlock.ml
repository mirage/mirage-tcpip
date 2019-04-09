open Lwt.Infix

let mtu = 4000

let server_log = Logs.Src.create "test_deadlock_server" ~doc:"tcp deadlock tests: server"
module Server_log = (val Logs.src_log server_log : Logs.LOG)

let client_log = Logs.Src.create "test_deadlock_client" ~doc:"tcp deadlock tests: client"
module Client_log = (val Logs.src_log client_log : Logs.LOG)

module TCPIP =
struct
  module RANDOM = Mirage_random_test

  module TIME =
  struct
    type 'a io = 'a Lwt.t
    let sleep_ns nanos = Lwt_unix.sleep (Int64.to_float nanos /. 1e9)
  end

  module MCLOCK = Mclock

  module M =
  struct
    module B      = Basic_backend.Make
    module NETIF  = Vnetif.Make(B)
    module ETHIF  = Ethernet.Make(NETIF)
    module ARPV4  = Arp.Make(ETHIF)(TIME)
    module IPV4   = Static_ipv4.Make(RANDOM)(MCLOCK)(ETHIF)(ARPV4)
    module ICMPV4 = Icmpv4.Make(IPV4)
    module UDPV4  = Udp.Make(IPV4)(RANDOM)
    module TCPV4  = Tcp.Flow.Make(IPV4)(TIME)(MCLOCK)(RANDOM)
    module TCPIP  = Tcpip_stack_direct.Make(TIME)(RANDOM)(NETIF)(ETHIF)(ARPV4)(IPV4)(ICMPV4)(UDPV4)(TCPV4)
  end
  open M

  type stack = TCPIP.t

  let server_ip = Ipaddr.V4.of_string_exn "192.168.10.10"
  let client_ip = Ipaddr.V4.of_string_exn "192.168.10.20"
  let network   = Ipaddr.V4.Prefix.of_string_exn "192.168.10.255/24"

  let make ~ip ~network ?gateway netif =
    MCLOCK.connect () >>= fun clock ->
    ETHIF.connect netif >>= fun ethif ->
    ARPV4.connect ethif >>= fun arpv4 ->
    IPV4.connect ~ip ~network ?gateway clock ethif arpv4 >>= fun ipv4 ->
    ICMPV4.connect ipv4 >>= fun icmpv4 ->
    UDPV4.connect ipv4 >>= fun udpv4 ->
    TCPV4.connect ipv4 clock >>= fun tcpv4 ->
    TCPIP.connect netif ethif arpv4 ipv4 icmpv4 udpv4 tcpv4 >>= fun tcpip ->
    Lwt.return tcpip

  include TCPIP

  let tcpip t = t

  let make role netif = match role with
    | `Server -> make ~ip:server_ip ~network netif
    | `Client -> make ~ip:client_ip ~network netif

  type conn = M.NETIF.t

  let get_stats _t =
    { Mirage_net.rx_pkts = 0l; rx_bytes = 0L;
      tx_pkts = 0l; tx_bytes = 0L;
    }

  let reset_stats _t = ()
end

let port = 10000

let test_digest netif1 netif2 =
  TCPIP.make `Client netif1 >>= fun client_stack ->
  TCPIP.make `Server netif2 >>= fun server_stack ->

  let send_data () =
    let data = Mirage_random_test.generate 100_000_000 |> Cstruct.to_string in
    let t0   = Unix.gettimeofday () in
    TCPIP.TCPV4.create_connection
      TCPIP.(tcpv4 @@ tcpip server_stack) (TCPIP.client_ip, port) >>= function
    | Error _ -> failwith "could not establish tunneled connection"
    | Ok flow ->
      Server_log.debug (fun f -> f "established conn");
      let rec read_digest chunks =
        TCPIP.TCPV4.read flow >>= function
        | Error _ -> failwith "read error"
        | Ok (`Data data) -> read_digest (data :: chunks)
        | Ok `Eof ->
          Server_log.debug (fun f -> f "EOF");
          let dt = Unix.gettimeofday () -. t0 in
          Server_log.warn (fun f -> f "!!!!!!!!!! XXXX  needed %.2fs (%.1f MB/s)"
            dt (float (String.length data) /. dt /. 1024. ** 2.));
          Lwt.return_unit
      in
      Lwt.pick
        [ read_digest [];
          begin
            let rec send_data data =
              if Cstruct.len data < mtu then
                (TCPIP.TCPV4.write flow data >>= fun _ -> Lwt.return_unit)
              else
                let sub, data = Cstruct.split data mtu in
                Lwt.pick
                  [
                    (TCPIP.TCPV4.write flow sub >>= fun _ -> Lwt.return_unit);
                    (Lwt_unix.sleep 5. >>= fun () ->
                     Common.failf "=========== DEADLOCK!!! =============");
                  ]
                >>= fun () ->
                send_data data in
            send_data @@ Cstruct.of_string data >>= fun () ->
            Server_log.debug (fun f -> f "wrote data");
            TCPIP.TCPV4.close flow
          end
        ]
  in
  TCPIP.listen_tcpv4 (TCPIP.tcpip client_stack) ~port
    (fun flow ->
       Client_log.debug (fun f -> f "client got conn");
       let rec consume () =
         TCPIP.TCPV4.read flow >>= function
         | Error _ ->
           Client_log.debug (fun f -> f "XXXX client read error");
           TCPIP.TCPV4.close flow
         | Ok `Eof ->
           TCPIP.TCPV4.write flow @@ Cstruct.of_string "thanks for all the fish"
           >>= fun _ ->
           TCPIP.TCPV4.close flow
         | Ok (`Data _data) ->
           (if Random.float 1.0 < 0.01 then Lwt_unix.sleep 0.01
           else Lwt.return_unit) >>= fun () ->
           consume ()
       in
       consume ());
  Lwt.pick
    [
      send_data ();
      TCPIP.listen @@ TCPIP.tcpip server_stack;
      TCPIP.listen @@ TCPIP.tcpip client_stack;
    ]

let run_vnetif () =
  let backend = Basic_backend.Make.create
      ~use_async_readers:true ~yield:Lwt_unix.yield () in
  TCPIP.M.NETIF.connect ~size_limit:mtu backend >>= fun c1 ->
  TCPIP.M.NETIF.connect ~size_limit:mtu backend >>= fun c2 ->
  test_digest c1 c2

let suite = [
  "test tcp deadlock with slow receiver", `Slow, run_vnetif
]
