(*
 * Compile with
    ocamlfind ocamlopt -package cryptokit,tcpip.tcp,lwt.ppx,mirage-clock-unix,mirage-vnetif,mirage-net-lwt,tcpip.ethif,tcpip.arpv4,tcpip.icmpv4,tcpip.ipv4,tcpip.stack-direct,logs,lwt.unix,logs.fmt,io-page.unix  -thread -o tcpip_bug tcpip_bug.ml -linkpkg

 * *)

open Lwt.Infix

let mtu = 4000

module TCPIP =
struct
  module RANDOM = Stdlibrandom

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
    module ETHIF  = Ethif.Make(NETIF)
    module ARPV4  = Arpv4.Make(ETHIF)(MCLOCK)(TIME)
    module IPV4   = Static_ipv4.Make(ETHIF)(ARPV4)
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
    let%lwt clock  = MCLOCK.connect () in
    let%lwt ethif  = ETHIF.connect ~mtu netif in
    let%lwt arpv4  = ARPV4.connect ethif clock in
    let%lwt ipv4   = IPV4.connect ~ip ~network ?gateway ethif arpv4 in
    let%lwt icmpv4 = ICMPV4.connect ipv4 in
    let%lwt udpv4  = UDPV4.connect ipv4 in
    let%lwt tcpv4  = TCPV4.connect ipv4 clock in
    let%lwt tcpip  = TCPIP.connect
                       { Mirage_stack_lwt.name = "genTCPIP"; interface = netif }
                       ethif arpv4 ipv4 icmpv4 udpv4 tcpv4
    in
      Lwt.return tcpip

  include TCPIP

  let tcpip t = t

  let make role netif = match role with
    | `Server -> make ~ip:server_ip ~network netif
    | `Client -> make ~ip:client_ip ~network netif

  type conn = M.NETIF.t

  let get_stats t =
    { Mirage_net.rx_pkts = 0l; rx_bytes = 0L;
      tx_pkts = 0l; tx_bytes = 0L;
    }

  let reset_stats t = ()
end

let port = 10000

let rnd = Cryptokit.(Random.pseudo_rng @@ hash_string (Hash.sha256 ()) "42")

let test_digest netif1 netif2 =
  let%lwt client_stack = TCPIP.make `Client netif1
  and     server_stack = TCPIP.make `Server netif2 in

  let send_data () =
    let data = Cryptokit.Random.string rnd 100_000_000 in
    let t0   = Unix.gettimeofday () in
      match%lwt
        TCPIP.TCPV4.create_connection
          TCPIP.(tcpv4 @@ tcpip server_stack) (TCPIP.client_ip, port)
      with
        | Error _ -> failwith "could not establish tunneled connection"
        | Ok flow ->
            print_endline "established conn";
            let rec read_digest chunks =
              match%lwt TCPIP.TCPV4.read flow with
                | Error _ -> failwith "read error"
                | Ok (`Data data) -> read_digest (data :: chunks)
                | Ok `Eof ->
                    print_endline "EOF";
                    let dt = Unix.gettimeofday () -. t0 in
                      Printf.printf "!!!!!!!!!! XXXX  needed %.2fs (%.1f MB/s)\n"
                        dt (float (String.length data) /. dt /. 1024. ** 2.);

                    let expected = Cryptokit.(hash_string (Hash.sha256 ()) data) in
                    let actual   = String.concat "" @@ List.rev_map Cstruct.to_string chunks in
                      if expected <> actual then begin
                        failwith "bad digest"
                      end else begin
                        print_endline "OK";
                      end;

                      Lwt.return_unit
            in
              Lwt.join
                [ read_digest [];

                  begin
                    let rec send_data data =
                      if Cstruct.len data < mtu then
                        let%lwt _ = TCPIP.TCPV4.write flow data in
                          Lwt.return_unit
                      else
                        let sub, data = Cstruct.split data mtu in

                        let%lwt () =
                          Lwt.pick
                            [
                              (let%lwt _ = TCPIP.TCPV4.write flow sub in
                                 Lwt.return_unit);

                              (let%lwt () = Lwt_unix.sleep 5. in
                                 print_endline "=========== DEADLOCK!!! =============";
                                 Lwt.return_unit);
                            ]
                        in
                          send_data data in

                    let%lwt () = send_data @@ Cstruct.of_bytes data in
                      print_endline "wrote data";
                      TCPIP.TCPV4.close flow
                  end
                ]
  in
    TCPIP.listen_tcpv4 (TCPIP.tcpip client_stack) port
      (fun flow ->
         print_endline "client got conn";

         let h = Cryptokit.Hash.sha256 () in

         let rec consume () =
           match%lwt TCPIP.TCPV4.read flow with
             | Error _ ->
                 print_endline "XXXX client read error";
                 TCPIP.TCPV4.close flow
             | Ok `Eof ->
                 let%lwt _ = TCPIP.TCPV4.write flow @@ Cstruct.of_string @@ h#result in
                   TCPIP.TCPV4.close flow
             | Ok (`Data data) ->
                 h#add_string @@ Cstruct.to_string data;
                 let%lwt () =
                   if Random.float 1.0 < 0.01 then Lwt_unix.sleep 0.01
                   else Lwt.return_unit
                 in
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
  let%lwt c1  = TCPIP.M.NETIF.connect backend in
  let%lwt c2  = TCPIP.M.NETIF.connect backend in
    test_digest c1 c2

let suite () =
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs.set_level ~all:true (Some Logs.Debug);
  Lwt_main.run @@ run_vnetif ();
