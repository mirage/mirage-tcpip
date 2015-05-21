open Lwt
open V1_LWT

module Main (C: V1_LWT.CONSOLE) (S: V1_LWT.STACKV4) = struct
  let report_and_close c flow message =
    C.log c message;
    S.TCPV4.close flow

  let rec chargen c flow how_many start_at =
    let charpool =
      "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~ "
    in
    let make_chars how_many start_at =
      let output = (String.sub (charpool ^ charpool) start_at how_many) ^ "\n" in
      Cstruct.of_string output
    in

    S.TCPV4.write flow (make_chars how_many start_at) >>= function
    | `Ok () ->
      chargen c flow how_many ((start_at + 1) mod (String.length charpool))
    | `Eof ->
      report_and_close c flow "Chargen connection closing normally."
    | `Error _ ->
      report_and_close c flow "Chargen connection read error; closing."

  let rec discard c flow =
    S.TCPV4.read flow >>= fun result -> (
    match result with
    | `Eof -> report_and_close c flow "Discard connection closing normally."
    | `Error _ -> report_and_close c flow "Discard connection read error;
      closing."
    | _ -> discard c flow
  )


  let rec echo c flow =
    S.TCPV4.read flow >>= fun result -> (
    match result with
    | `Eof -> report_and_close c flow "Echo connection closure initiated."
    | `Error e ->
      let message =
        match e with
        | `Timeout -> "Echo connection timed out; closing.\n"
        | `Refused -> "Echo connection refused; closing.\n"
        | `Unknown s -> (Printf.sprintf "Echo connection error: %s\n" s)
      in
      report_and_close c flow message
    | `Ok buf ->
      S.TCPV4.write flow buf >>= function
      | `Ok () -> echo c flow
      | `Eof -> report_and_close c flow "Echo connection closure initated."
      | `Error _ -> report_and_close c flow "Echo connection error during writing; closing."
  )

  let start c s =
    (* RFC 862 - read payloads and repeat them back *)
    S.listen_tcpv4 s ~port:7 (echo c);

    (* RFC 863 - discard all incoming data and never write a payload *)
    S.listen_tcpv4 s ~port:9 (discard c);

    (* RFC 864 - write data without regard for input *)
    S.listen_tcpv4 s ~port:19 (fun flow -> chargen c flow 75 0);

    S.listen s

end
