open Lwt.Infix

module Main (S: Tcpip.Stack.V4V6) = struct
  let report_and_close flow pp e message =
    let ip, port = S.TCP.dst flow in
    Logs.warn
      (fun m -> m "closing connection from %a:%d due to error %a while %s"
          Ipaddr.pp ip port pp e message);
    S.TCP.close flow

  let rec chargen flow how_many start_at =
    let charpool =
      "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ "
    in
    let make_chars how_many start_at =
      let output = (String.sub (charpool ^ charpool) start_at how_many) ^ "\n" in
      Cstruct.of_string output
    in

    S.TCP.write flow (make_chars how_many start_at) >>= function
    | Ok () ->
      chargen flow how_many ((start_at + 1) mod (String.length charpool))
    | Error e -> report_and_close flow S.TCP.pp_write_error e "writing in Chargen"

  let rec discard flow =
    S.TCP.read flow >>= fun result -> (
    match result with
    | Error e -> report_and_close flow S.TCP.pp_error e "reading in Discard"
    | Ok `Eof -> report_and_close flow Fmt.string "end of file" "reading in Discard"
    | Ok (`Data _) -> discard flow
  )


  let rec echo flow =
    S.TCP.read flow >>= function
    | Error e -> report_and_close flow S.TCP.pp_error e "reading in Echo"
    | Ok `Eof -> report_and_close flow Fmt.string "end of file" "reading in Echo"
    | Ok (`Data buf) ->
      S.TCP.write flow buf >>= function
      | Ok () -> echo flow
      | Error e -> report_and_close flow S.TCP.pp_write_error e "writing in Echo"

  let start s =
    (* RFC 862 - read payloads and repeat them back *)
    S.TCP.listen (S.tcp s) ~port:7 echo;

    (* RFC 863 - discard all incoming data and never write a payload *)
    S.TCP.listen (S.tcp s) ~port:9 discard;

    (* RFC 864 - write data without regard for input *)
    S.TCP.listen (S.tcp s) ~port:19 (fun flow -> chargen flow 75 0);

    S.listen s

end
