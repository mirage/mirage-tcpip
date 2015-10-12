open Lwt.Infix

let time_reduction_factor = 60.

module Fast_clock = struct

  let last_read = ref (Clock.time ())

  (* from mirage/types/V1.mli module type CLOCK *)
  type tm =
    { tm_sec: int;               (** Seconds 0..60 *)
      tm_min: int;               (** Minutes 0..59 *)
      tm_hour: int;              (** Hours 0..23 *)
      tm_mday: int;              (** Day of month 1..31 *)
      tm_mon: int;               (** Month of year 0..11 *)
      tm_year: int;              (** Year - 1900 *)
      tm_wday: int;              (** Day of week (Sunday is 0) *)
      tm_yday: int;              (** Day of year 0..365 *)
      tm_isdst: bool;            (** Daylight time savings in effect *)
    }

  let gmtime time = 
    let tm = Clock.gmtime time in
    { 
      tm_sec = tm.Clock.tm_sec;
      tm_min = tm.Clock.tm_min;
      tm_hour = tm.Clock.tm_hour;
      tm_mday = tm.Clock.tm_mday;
      tm_mon = tm.Clock.tm_mon;
      tm_year = tm.Clock.tm_year;
      tm_wday = tm.Clock.tm_wday;
      tm_yday = tm.Clock.tm_yday;
      tm_isdst = tm.Clock.tm_isdst;
    }

  let time () = 
    let this_time = Clock.time () in
    let clock_diff = ((this_time -. !last_read) *. time_reduction_factor) in
    last_read := this_time;
    this_time +. clock_diff

end
module Fast_time = struct
  type 'a io = 'a Lwt.t
  let sleep time = OS.Time.sleep (time /. time_reduction_factor)
end

module B = Basic_backend.Make
module V = Vnetif.Make(B)
module E = Ethif.Make(V)
module A = Arpv4.Make(E)(Fast_clock)(Fast_time)

type arp_stack = {
  backend : B.t;
  netif: V.t;
  ethif: E.t;
  arp: A.t;
}

(* TODO: this code should be in tcpip proper for common use *)
module Parse = struct
  type arp = {
    op: [ `Request |`Reply |`Unknown of int ];
    sha: Macaddr.t;
    spa: Ipaddr.V4.t;
    tha: Macaddr.t;
    tpa: Ipaddr.V4.t;
  }
  let garp src_mac src_ip =
    { op = `Reply;
      sha = src_mac;
      tha = Macaddr.broadcast;
      spa = src_ip;
      tpa = Ipaddr.V4.any;
    }

  let cstruct_of_arp arp =
    let open Arpv4_wire in
    (* Obtain a buffer to write into *)
    (* note that sizeof_arp includes sizeof_ethernet by what's currently in
         arpv4_wire.ml *)
    let buf = Cstruct.create (Arpv4_wire.sizeof_arp + Wire_structs.sizeof_ethernet) in

    (* Write the ARP packet *)
    let dmac = Macaddr.to_bytes arp.tha in
    let smac = Macaddr.to_bytes arp.sha in
    let spa = Ipaddr.V4.to_int32 arp.spa in
    let tpa = Ipaddr.V4.to_int32 arp.tpa in
    let op =
      match arp.op with
      |`Request -> 1
      |`Reply -> 2
      |`Unknown n -> n
    in
    Wire_structs.set_ethernet_dst dmac 0 buf;
    Wire_structs.set_ethernet_src smac 0 buf;
    Wire_structs.set_ethernet_ethertype buf 0x0806; (* ARP *)
    let arpbuf = Cstruct.shift buf 14 in
    set_arp_htype arpbuf 1;
    set_arp_ptype arpbuf 0x0800; (* IPv4 *)
    set_arp_hlen arpbuf 6; (* ethernet mac size *)
    set_arp_plen arpbuf 4; (* ipv4 size *)
    set_arp_op arpbuf op;
    set_arp_sha smac 0 arpbuf;
    set_arp_spa arpbuf spa;
    set_arp_tha dmac 0 arpbuf;
    set_arp_tpa arpbuf tpa;
    buf

  let arp_of_cstruct buf = 
    let open Arpv4_wire in
    let buf = Cstruct.shift buf 14 in
    let unusable buf =
      (* we only know how to deal with ethernet <-> IPv4 *)
      get_arp_htype buf <> 1 || get_arp_ptype buf <> 0x0800 
      || get_arp_hlen buf <> 6 || get_arp_plen buf <> 4
    in
    if (Cstruct.len buf) < sizeof_arp then `Too_short else begin
      if (unusable buf) then `Unusable else begin
        let op = match get_arp_op buf with
          | 1 -> `Request
          | 2 -> `Reply
          | n -> `Unknown n
        in
        let src_mac = copy_arp_sha buf in
        let target_mac = copy_arp_tha buf in
        match (Macaddr.of_bytes src_mac, Macaddr.of_bytes target_mac) with
        | None, Some _ -> `Bad_mac [ src_mac ]
        | Some _, None -> `Bad_mac [ target_mac ]
        | None, None -> `Bad_mac [ src_mac ; target_mac ]
        | Some src_mac, Some target_mac ->
          let src_ip = Ipaddr.V4.of_int32 (get_arp_spa buf) in
          let target_ip = Ipaddr.V4.of_int32 (get_arp_tpa buf) in
          `Ok { op; 
                sha = src_mac; spa = src_ip; 
                tha = target_mac; tpa = target_ip
              }
      end
    end
  let is_garp_for ip buf = match arp_of_cstruct buf with
    | `Ok arp -> arp.op = `Reply && arp.tha = Macaddr.broadcast
    | _ -> false

  let to_string arp = 
    let ip_str = Ipaddr.V4.to_string in
    let mac_str = Macaddr.to_string in
    let op = match arp.op with
      | `Request -> "request"
      | `Reply -> "reply"
      | `Unknown n -> Printf.sprintf "unknown message type (%d)" n
    in
    Printf.sprintf "%s from mac %s (ip %s) to mac %s (ip %s)" 
      op (mac_str arp.sha) (ip_str arp.spa) (mac_str arp.tha) (ip_str arp.tpa)

end

let first_ip = Ipaddr.V4.of_string_exn "192.168.3.1"
let second_ip = Ipaddr.V4.of_string_exn "192.168.3.10"
let sample_mac = Macaddr.of_string_exn "10:9a:dd:c0:ff:ee"

let or_error = Common.or_error
let equals = OUnit.assert_equal
let fail = OUnit.assert_failure

let timeout ~time t =
  let msg = "timed out" in
  Lwt.pick [ t; OS.Time.sleep time >>= fun () -> fail msg; ]

let check_response expected buf =
  let printer buf =
    match Parse.arp_of_cstruct buf with
    | `Ok arp -> Parse.to_string arp
    | `Unusable -> "Reasonable ARP message for a protocol we don't understand"
    | `Bad_mac _ -> "Unparseable MAC in message"
    | `Too_short -> "Too short to parse"
  in
  equals ~printer expected buf

let fail_on_receipt netif buf = 
  fail "received traffic when none was expected"

let single_check netif expected =
  V.listen netif (fun buf -> check_response expected buf; V.disconnect netif)

let arp_reply ~from_netif ~to_netif ~from_ip ~to_ip =
  Parse.cstruct_of_arp
      { Parse.op = `Reply; 
        sha = (V.mac from_netif); 
        tha = (V.mac to_netif);
        spa = from_ip;
        tpa = to_ip} 

let arp_request ~from_netif ~to_mac ~from_ip ~to_ip =
  Parse.cstruct_of_arp
      { Parse.op = `Request; 
        sha = (V.mac from_netif); 
        tha = to_mac;
        spa = from_ip;
        tpa = to_ip} 

let get_arp ?(backend = B.create ~use_async_readers:true 
                ~yield:(fun() -> Lwt_main.yield ()) ()) () =
  or_error "backend" V.connect backend >>= fun netif ->
  or_error "ethif" E.connect netif >>= fun ethif ->
  or_error "arp" A.connect ethif >>= fun arp ->
  Lwt.return { backend; netif; ethif; arp }

(* we almost always want two stacks on the same backend *)
let two_arp () =
  get_arp () >>= fun first ->
  get_arp ~backend:first.backend () >>= fun second ->
  Lwt.return (first, second)

(* ...but sometimes we want three *)
let three_arp () =
  get_arp () >>= fun first ->
  get_arp ~backend:first.backend () >>= fun second ->
  get_arp ~backend:first.backend () >>= fun third ->
  Lwt.return (first, second, third)

let query_or_die ~arp ~ip ~expected_mac = 
  A.query arp ip >>= function
  | `Timeout ->
    let pp_ip = Ipaddr.V4.to_string ip in
    Format.printf "Timeout querying %s." pp_ip;
    A.to_repr arp >>= fun repr ->
    A.pp Format.std_formatter repr;
    fail "ARP query failed when success was mandatory";
    Lwt.return_unit
  | `Ok mac -> 
    equals ~printer:Macaddr.to_string expected_mac mac;
    Lwt.return_unit

let set_and_check listener claimant ip =
  A.set_ips claimant.arp [ ip ] >>= fun () ->
  query_or_die listener ip (V.mac claimant.netif)

let start_arp_listener stack () =
  let noop = (fun buf -> Lwt.return_unit) in
  E.input ~arpv4:(A.input stack.arp) ~ipv4:noop ~ipv6:noop stack.ethif

let output_then_disconnect ~speak:speak_netif ~disconnect:listen_netif bufs =
  Lwt.join (List.map (V.write speak_netif) bufs) >>= fun () ->
  Lwt_unix.sleep 0.1 >>= fun () ->
  V.disconnect listen_netif

let not_in_cache ~listen probe arp ip =
  Lwt.pick [
    single_check listen probe;
    OS.Time.sleep 0.1 >>= fun () ->
    A.query arp ip >>= function
    | `Ok mac -> fail "entry in cache when it shouldn't be"
    | `Timeout -> Lwt.return_unit
  ]

let set_ip_sends_garp () =
  two_arp () >>= fun (speak, listen) ->
  let emit_garp =
    OS.Time.sleep 0.1 >>= fun () ->
    A.set_ips speak.arp [ first_ip ] >>= fun () ->
    equals [ first_ip ] (A.get_ips speak.arp);
    Lwt.return_unit
  in
  let expected_garp = Parse.(cstruct_of_arp (garp (V.mac speak.netif) first_ip)) in
  timeout ~time:0.5 (
  Lwt.join [
    single_check listen.netif expected_garp;
    emit_garp;
  ]) >>= fun () ->
  (* now make sure we have consistency when setting *)
  A.set_ips speak.arp [] >>= fun () ->
  equals [] (A.get_ips speak.arp);
  A.set_ips speak.arp [ first_ip; second_ip ] >>= fun () ->
  equals [ first_ip; second_ip ] (A.get_ips speak.arp);
  Lwt.return_unit

let add_get_remove_ips () =
  get_arp () >>= fun stack ->
  equals [] (A.get_ips stack.arp);
  A.set_ips stack.arp [ first_ip; first_ip ] >>= fun () ->
  let ips = A.get_ips stack.arp in
  equals true (List.mem first_ip ips);
  equals true (List.for_all (fun a -> a = first_ip) ips);
  equals true (List.length ips >= 1 && List.length ips <= 2);
  A.remove_ip stack.arp first_ip >>= fun () ->
  equals [] (A.get_ips stack.arp);
  A.remove_ip stack.arp first_ip >>= fun () ->
  equals [] (A.get_ips stack.arp);
  A.add_ip stack.arp first_ip >>= fun () ->
  equals [ first_ip ] (A.get_ips stack.arp);
  A.add_ip stack.arp first_ip >>= fun () ->
  equals [ first_ip ] (A.get_ips stack.arp);
  Lwt.return_unit

let input_single_garp () =
  two_arp () >>= fun (listen, speak) ->
  (* set the IP on speak_arp, which should cause a GARP to be emitted which
     listen_arp will hear and cache. *)
  let one_and_done buf =
    let arpbuf = Cstruct.shift buf 14 in
    A.input listen.arp arpbuf >>= fun () ->
    V.disconnect listen.netif 
  in
  timeout ~time:0.5 (
  Lwt.join [
    V.listen listen.netif one_and_done;
    OS.Time.sleep 0.1 >>= fun () ->
    A.set_ips speak.arp [ first_ip ];
  ])
  >>= fun () ->
  (* try a lookup of the IP set by speak.arp, and fail if this causes listen_arp
     to block or send an ARP query -- listen_arp should answer immediately from
     the cache.  An attempt to resolve via query will result in a timeout, since
     speak.arp has no listener running and therefore won't answer any arp
     who-has requests. *)
  timeout ~time:0.5 (query_or_die listen.arp first_ip (V.mac speak.netif))

let input_single_unicast () =
  two_arp () >>= fun (listen, speak) ->
  (* contrive to make a reply packet for the listener to hear *)
  let for_listener = arp_reply 
     ~from_netif:speak.netif ~to_netif:listen.netif ~from_ip:first_ip ~to_ip:second_ip
  in
  let listener = start_arp_listener listen () in
  timeout ~time:0.5 (
  Lwt.choose [
    V.listen listen.netif listener;
    OS.Time.sleep 0.1 >>= fun () ->
    V.write speak.netif for_listener >>= fun () ->
    query_or_die listen.arp first_ip (V.mac speak.netif)
  ])

let input_resolves_wait () =
  two_arp () >>= fun (listen, speak) ->
  (* contrive to make a reply packet for the listener to hear *)
  let for_listener = arp_reply ~from_netif:speak.netif ~to_netif:listen.netif
                         ~from_ip:first_ip ~to_ip:second_ip in
  (* initiate query when the cache is empty.  On resolution, fail for a timeout
     and test the MAC if resolution was successful, then disconnect the
     listening interface to ensure the test terminates.  
     Fail with a timeout message if the whole thing takes more than 5s. *)
  let listener = start_arp_listener listen () in
  let query_then_disconnect = 
    query_or_die listen.arp first_ip (V.mac speak.netif) >>= fun () ->
    V.disconnect listen.netif
  in
  timeout ~time:5.0 (
    Lwt.join [
      V.listen listen.netif listener;
      query_then_disconnect;
      OS.Time.sleep 0.1 >>= fun () -> E.write speak.ethif for_listener;
    ]
  )

let unreachable_times_out () =
  get_arp () >>= fun speak ->
  A.query speak.arp first_ip >>= function
  | `Ok mac -> fail "query claimed success when impossible"
  | `Timeout -> Lwt.return_unit

let input_replaces_old () =
  three_arp () >>= fun (listen, claimant_1, claimant_2) ->
  let listener = start_arp_listener listen () in
  timeout ~time:2.0 (
    Lwt.join [
      V.listen listen.netif listener;
      OS.Time.sleep 0.1 >>= fun () ->
      set_and_check listen.arp claimant_1 first_ip >>= fun () ->
      set_and_check listen.arp claimant_2 first_ip >>= fun () ->
      V.disconnect listen.netif
    ])

let entries_expire () =
  two_arp () >>= fun (listen, speak) ->
  A.set_ips listen.arp [ second_ip ] >>= fun () ->
  (* here's what we expect listener to emit once its cache entry has expired *)
  let expected_arp_query = arp_request ~from_netif:listen.netif
      ~to_mac:Macaddr.broadcast ~from_ip:second_ip ~to_ip:first_ip
  in
  Lwt.async (fun () -> 
      V.listen listen.netif (start_arp_listener listen ()));
  let test =
    OS.Time.sleep 0.1 >>= fun () ->
    set_and_check listen.arp speak first_ip >>= fun () ->
    OS.Time.sleep 1.0 >>= fun () ->
    (* asking now should generate a query *)
    not_in_cache ~listen:speak.netif expected_arp_query listen.arp first_ip;
  in
  timeout ~time:5.0 test

(* RFC isn't strict on how many times to try, so we'll just say any number
   greater than 1 is fine *)
let query_retries () =
  two_arp () >>= fun (listen, speak) ->
  let expected_query = arp_request ~from_netif:speak.netif
      ~to_mac:Macaddr.broadcast ~from_ip:Ipaddr.V4.any ~to_ip:first_ip
  in
  let how_many = ref 0 in
  let rec listener buf =
    check_response expected_query buf;
    if !how_many = 0 then begin
      how_many := !how_many + 1;
      Lwt.return_unit
    end else V.disconnect listen.netif
  in
  let ask () = 
    A.query speak.arp first_ip >>= function
    | `Timeout -> fail "Received `Timeout before >1 query";
      Lwt.return_unit
    | `Ok mac -> fail "got result from query, erroneously";
      Lwt.return_unit
  in
  Lwt.pick [
    V.listen listen.netif listener;
    OS.Time.sleep 0.1 >>= ask;
    OS.Time.sleep 6.0 >>= fun () -> fail "query didn't succeed or fail within 6s"
  ]

(* requests for us elicit a reply *)
let requests_are_responded_to () =
  let (answerer_ip, inquirer_ip) = (first_ip, second_ip) in
  two_arp () >>= fun (inquirer, answerer) ->
  (* neither has a listener set up when we set IPs, so no GARPs in the cache *)
  A.add_ip answerer.arp answerer_ip >>= fun () ->
  A.add_ip inquirer.arp inquirer_ip >>= fun () ->
  let request =
    Parse.cstruct_of_arp
      { Parse.op = `Request; sha = (V.mac inquirer.netif); tha = Macaddr.broadcast;
       spa = inquirer_ip; tpa = answerer_ip }
  in
  let expected_reply = 
    arp_reply ~from_netif:answerer.netif ~to_netif:inquirer.netif
      ~from_ip:answerer_ip ~to_ip:inquirer_ip
  in
  let listener close_netif buf =
    equals ~printer:(Printf.sprintf "%S") 
      (Cstruct.to_string expected_reply) (Cstruct.to_string buf);
    V.disconnect close_netif
  in
  let arp_listener =
      V.listen answerer.netif (start_arp_listener answerer ())
  in
  Lwt.pick [
    Lwt.join [
      (* listen for responses and check them against an expected result *)
      V.listen inquirer.netif (listener inquirer.netif);
      (* start the usual ARP listener, which should respond to requests *)
      arp_listener;
      (* send a request for the ARP listener to respond to *)
      OS.Time.sleep 0.1 >>= fun () -> V.write inquirer.netif request
      >>= fun () -> OS.Time.sleep 0.1 >>= fun () -> V.disconnect answerer.netif
    ];
    OS.Time.sleep 3.0 >>= fun () -> fail "timed out"
  ]

let requests_not_us () =
  let (answerer_ip, inquirer_ip) = (first_ip, second_ip) in
  two_arp () >>= fun (answerer, inquirer) ->
  A.add_ip answerer.arp answerer_ip >>= fun () ->
  A.add_ip inquirer.arp inquirer_ip >>= fun () ->
  let ask ip =
    Parse.cstruct_of_arp
      { Parse.op = `Request; sha = (V.mac inquirer.netif); tha = Macaddr.broadcast;
        spa = inquirer_ip; tpa = ip }
  in
  let requests = List.map ask [ inquirer_ip; Ipaddr.V4.any;
                                Ipaddr.V4.of_string_exn "255.255.255.255" ] in
  let make_requests = Lwt_list.iter_s (V.write inquirer.netif) requests in
  let disconnect_listeners () = 
    Lwt_list.iter_s (V.disconnect) [answerer.netif; inquirer.netif]
  in
  Lwt.join [
    V.listen answerer.netif (start_arp_listener answerer ());
    V.listen inquirer.netif (fail_on_receipt inquirer.netif);
    make_requests >>= fun () -> OS.Time.sleep 0.1 >>= disconnect_listeners
  ]

let nonsense_requests () =
  let (answerer_ip, inquirer_ip) = (first_ip, second_ip) in
  three_arp () >>= fun (answerer, inquirer, checker) ->
  A.set_ips answerer.arp [ answerer_ip ] >>= fun () ->
  let request number =
    Parse.cstruct_of_arp
      { Parse.op = (`Unknown number); sha = (V.mac inquirer.netif); tha = Macaddr.broadcast;
        spa = inquirer_ip; tpa = answerer_ip }
  in
  let requests = List.map request [0; 3; -1; 255; 256; 257; 65536] in
  let make_requests = Lwt_list.iter_s (V.write inquirer.netif) requests in
  let expected_probe = arp_request ~from_netif:answerer.netif
      ~to_mac:Macaddr.broadcast ~from_ip:answerer_ip ~to_ip:inquirer_ip
  in
  Lwt.async (fun () -> 
      V.listen answerer.netif (start_arp_listener answerer ()));
  timeout ~time:5.0 (
    Lwt.join [
      V.listen inquirer.netif (fail_on_receipt inquirer.netif);
      make_requests >>= fun () ->
      V.disconnect inquirer.netif >>= fun () ->
      (* not sufficient to just check to see whether we've replied; it's equally
         possible that we erroneously make a cache entry.  Make sure querying
         inquirer_ip results in an outgoing request. *)
      not_in_cache ~listen:checker.netif expected_probe answerer.arp inquirer_ip
    ] )

let suite =
  [
    "nonsense requests are ignored", `Quick, nonsense_requests;
    "requests are responded to", `Quick, requests_are_responded_to;
    "irrelevant requests are ignored", `Quick, requests_not_us;
    "set_ip sets ip, sends GARP", `Quick, set_ip_sends_garp;
    "add_ip, get_ip and remove_ip as advertised", `Quick, add_get_remove_ips;
    "GARPs are heard and cached", `Quick, input_single_garp;
    "unsolicited unicast replies are heard and cached", `Quick, input_single_unicast;
    "solicited unicast replies resolve pending threads", `Quick, input_resolves_wait;
    "entries are replaced with new information", `Quick, input_replaces_old;
    "unreachable IPs time out", `Quick, unreachable_times_out;
    "queries are tried repeatedly before timing out", `Quick, query_retries;
    "entries expire", `Quick, entries_expire;
  ]
