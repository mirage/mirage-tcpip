open Lwt.Infix

module Main (S: Mirage_types_lwt.STACKV4) = struct
  let report_and_close flow pp e message =
    let ip, port = S.TCPV4.dst flow in
    Logs.warn
      (fun m -> m "closing connection from %a:%d due to error %a while %s"
          Ipaddr.V4.pp_hum ip port pp e message);
    S.TCPV4.close flow

  let rec chargen flow how_many start_at =
    let charpool =
      "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ "
    in
    let make_chars how_many start_at =
      let buf = Io_page.(to_cstruct (get 1)) in
      let output = (String.sub (charpool ^ charpool) start_at how_many) ^ "\n" in
      Cstruct.blit_from_string output 0 buf 0 (String.length output);
      Cstruct.set_len buf (String.length output)
    in

    S.TCPV4.write flow (make_chars how_many start_at) >>= function
    | Ok () ->
      chargen flow how_many ((start_at + 1) mod (String.length charpool))
    | Error e -> report_and_close flow S.TCPV4.pp_write_error e "writing in Chargen"

  let rec discard flow =
    S.TCPV4.read flow >>= fun result -> (
    match result with
    | Error e -> report_and_close flow S.TCPV4.pp_error e "reading in Discard"
    | Ok `Eof -> report_and_close flow Fmt.string "end of file" "reading in Discard"
    | Ok (`Data _) -> discard flow
  )


  let rec echo flow =
    S.TCPV4.read flow >>= function
    | Error e -> report_and_close flow S.TCPV4.pp_error e "reading in Echo"
    | Ok `Eof -> report_and_close flow Fmt.string "end of file" "reading in Echo"
    | Ok (`Data buf) ->
      S.TCPV4.write flow buf >>= function
      | Ok () -> echo flow
      | Error e -> report_and_close flow S.TCPV4.pp_write_error e "writing in Echo"

  let start s =
    (* RFC 862 - read payloads and repeat them back *)
    S.listen_tcpv4 s ~port:7 echo;

    (* RFC 863 - discard all incoming data and never write a payload *)
    S.listen_tcpv4 s ~port:9 discard;

    (* RFC 864 - write data without regard for input *)
    S.listen_tcpv4 s ~port:19 (fun flow -> chargen flow 75 0);

    S.listen s

end
