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
    module IPV6   = Ipv6.Make(NETIF)(ETHIF)(RANDOM)(TIME)(MCLOCK)
    module IP     = Tcpip_stack_direct.IPV4V6(IPV4)(IPV6)
    module ICMPV4 = Icmpv4.Make(IPV4)
    module UDP    = Udp.Make(IP)(RANDOM)
    module TCP    = Tcp.Flow.Make(IP)(TIME)(MCLOCK)(RANDOM)
    module TCPIP  = Tcpip_stack_direct.MakeV4V6(TIME)(RANDOM)(NETIF)(ETHIF)(ARPV4)(IP)(ICMPV4)(UDP)(TCP)
  end
  open M

  type stack = TCPIP.t

  let server_ip = Ipaddr.V4.of_string_exn "192.168.10.10"
  let server_cidr = Ipaddr.V4.Prefix.make 24 server_ip
  let client_ip = Ipaddr.V4.of_string_exn "192.168.10.20"
  let client_cidr = Ipaddr.V4.Prefix.make 24 client_ip

  let make ~cidr ?gateway netif =
    ETHIF.connect netif >>= fun ethif ->
    ARPV4.connect ethif >>= fun arpv4 ->
    IPV4.connect ~cidr ?gateway ethif arpv4 >>= fun ipv4 ->
    IPV6.connect netif ethif >>= fun ipv6 ->
    IP.connect ~ipv4_only:false ~ipv6_only:false ipv4 ipv6 >>= fun ip ->
    ICMPV4.connect ipv4 >>= fun icmpv4 ->
    UDP.connect ip >>= fun udp ->
    TCP.connect ip >>= fun tcp ->
    TCPIP.connect netif ethif arpv4 ip icmpv4 udp tcp >>= fun tcpip ->
    Lwt.return tcpip

  include TCPIP

  let tcpip t = t

  let make role netif = match role with
    | `Server -> make ~cidr:server_cidr netif
    | `Client -> make ~cidr:client_cidr netif

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
    TCPIP.TCP.create_connection
      TCPIP.(tcp @@ tcpip server_stack) (Ipaddr.V4 TCPIP.client_ip, port) >>= function
    | Error _ -> failwith "could not establish tunneled connection"
    | Ok flow ->
      Server_log.debug (fun f -> f "established conn");
      let rec read_digest chunks =
        TCPIP.TCP.read flow >>= function
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
              if Cstruct.length data < mtu then
                (TCPIP.TCP.write flow data >>= fun _ -> Lwt.return_unit)
              else
                let sub, data = Cstruct.split data mtu in
                Lwt.pick
                  [
                    (TCPIP.TCP.write flow sub >>= fun _ -> Lwt.return_unit);
                    (Lwt_unix.sleep 5. >>= fun () ->
                     Common.failf "=========== DEADLOCK!!! =============");
                  ]
                >>= fun () ->
                send_data data in
            send_data @@ Cstruct.of_string data >>= fun () ->
            Server_log.debug (fun f -> f "wrote data");
            TCPIP.TCP.close flow
          end
        ]
  in
  TCPIP.TCP.listen TCPIP.(tcp (tcpip client_stack)) ~port
    (fun flow ->
       Client_log.debug (fun f -> f "client got conn");
       let rec consume () =
         TCPIP.TCP.read flow >>= function
         | Error _ ->
           Client_log.debug (fun f -> f "XXXX client read error");
           TCPIP.TCP.close flow
         | Ok `Eof ->
           TCPIP.TCP.write flow @@ Cstruct.of_string "thanks for all the fish"
           >>= fun _ ->
           TCPIP.TCP.close flow
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
      ~use_async_readers:true ~yield:Lwt.pause () in
  TCPIP.M.NETIF.connect ~size_limit:mtu backend >>= fun c1 ->
  TCPIP.M.NETIF.connect ~size_limit:mtu backend >>= fun c2 ->
  test_digest c1 c2

let suite = [
  "test tcp deadlock with slow receiver", `Slow, run_vnetif
]
