open State
open Lwt

module Make(Time:T.LWT_TIME) = struct

  let fin_wait_2_time = (* 60. *) 10.
  let time_wait_time = (* 30. *) 2.

  let rec finwait2timer t count timeout =
    Time.sleep timeout
    >>= fun () ->
    match t.state with
    | Fin_wait_2 i ->
      if i = count then begin
        t.state <- Closed;
        t.on_close ();
        return ()
      end else begin
        finwait2timer t i timeout
      end
    | _ ->
      return ()


  let timewait t twomsl =
    Time.sleep twomsl
    >>= fun () ->
    t.state <- Closed;
    t.on_close ();
    return ()

  let tick t (i:action) =
    (* printf "%s  - %s ->  " (to_string t) (action_to_string i); *)
    let diffone x y = Sequence.incr y = x in
    let tstr s (i:action) =
      match s, i with
      | Closed, Passive_open -> Listen
      | Closed, Send_syn a -> Syn_sent a
      | Listen, Send_synack a -> Syn_rcvd a
      | Syn_rcvd a, Timeout -> t.on_close (); Closed
      | Syn_rcvd a, Recv_rst -> Closed
      | Syn_sent a, Timeout -> t.on_close (); Closed
      | Syn_sent a, Recv_synack b-> if diffone b a then Established else Syn_sent a
      | Syn_rcvd a, Recv_ack b -> if diffone b a then Established else Syn_rcvd a
      | Established, Recv_ack a -> Established
      | Established, Send_fin a -> Fin_wait_1 a
      | Established, Recv_fin -> Close_wait
      | Established, Timeout -> t.on_close (); Closed
      | Fin_wait_1 a, Recv_ack b ->
        if diffone b a then
          let count = 0 in
          let _ = finwait2timer t count fin_wait_2_time in
          Fin_wait_2 count
        else
          Fin_wait_1 a
      | Fin_wait_1 a, Recv_fin -> Closing a
      | Fin_wait_1 a, Recv_finack b -> if diffone b a then Time_wait else Fin_wait_1 a
      | Fin_wait_1 a, Timeout -> t.on_close (); Closed
      | Fin_wait_2 i, Recv_ack _ -> Fin_wait_2 (i + 1)
      | Fin_wait_2 i, Recv_fin -> let _ = timewait t time_wait_time in Time_wait
      | Closing a, Recv_ack b -> if diffone b a then Time_wait else Closing a
      | Time_wait, Timeout -> t.on_close (); Closed
      | Close_wait,  Send_fin a -> Last_ack a
      | Close_wait,  Timeout -> t.on_close (); Closed
      | Last_ack a, Recv_ack b -> if diffone b a then (t.on_close (); Closed) else Last_ack a
      | Last_ack a, Timeout -> t.on_close (); Closed
      | x, _ -> x
    in
    t.state <- tstr t.state i
    (* ;  printf "%s\n%!" (to_string t) *)
end
