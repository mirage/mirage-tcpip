(*
 * Copyright (c) 2011 Richard Mortier <mort@cantab.net>
 * Copyright (c) 2012 Balraj Singh <balraj.singh@cl.cam.ac.uk>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

open Lwt 
open Printf
open OS.Clock
open Gc
open String


let start_port = 5001
let num_ports = 10
let conn_per_port = 1000
let spread_time = 3.


type stats = {
  mutable openconn_client: int64;
  mutable openconn_server: int64;
  mutable tot_server_conn: int64;
  mutable txbytes_client: int64;
  mutable rxbytes_client: int64;
  mutable txbytes_server: int64;
  mutable rxbytes_server: int64;
  mutable last_time: float;
}

let st = {openconn_client=0L; openconn_server=0L;
	  tot_server_conn=0L;
	  txbytes_client=0L; rxbytes_client=0L;
	  txbytes_server=0L; rxbytes_server=0L;
	  last_time=(OS.Clock.time ())}

let get = function Some x -> x | None -> failwith "Bad IP!"

let ip1 = `IPv4 (
  get (Ipaddr.V4.of_string "10.0.0.2"),
  get (Ipaddr.V4.of_string "255.255.255.0"),
  [get (Ipaddr.V4.of_string "10.0.0.1")]
)

let ip2 = `IPv4 (
  get (Ipaddr.V4.of_string "10.0.0.1"),
  get (Ipaddr.V4.of_string "255.255.255.0"),
  [get (Ipaddr.V4.of_string "10.0.0.1")]
)

let msg = "01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyzA"

let mlen = String.length msg

let server_ready, server_ready_u = Lwt.wait ()
let clients_done, clients_done_u = Lwt.wait ()
let test_completed, test_completed_u = Lwt.wait ()

let print_data ts_now = 
  printf "Servers: open = %Ld, done = %Ld, rx = %Ld bytes, tx = %Ld bytes;   Clients: open = %Ld, rx = %Ld bytes, tx = %Ld bytes, live_words = %d\n%!"
    st.openconn_server
    st.tot_server_conn
    st.rxbytes_server
    st.txbytes_server
    st.openconn_client
    st.rxbytes_client
    st.txbytes_client
    Gc.((stat()).live_words); 
  st.last_time <- ts_now


let print_data_persec ts_now = 
  if ((ts_now -. st.last_time) >= 1.0) then begin
    print_data ts_now;
  end


let iperfclient_p mgr src_ip dest_ip dport =
  let iperftxrx chan =
    st.openconn_client <- (Int64.add st.openconn_client 1L);
    OS.Time.sleep (spread_time +. Random.float spread_time) >>
    let a = Cstruct.sub (OS.Io_page.(to_cstruct (get 1))) 0 mlen in
    Cstruct.blit_from_string msg 0 a 0 mlen;
    let amt = mlen in
    Net.Flow.write chan a >>
    (st.txbytes_client <- (Int64.add st.txbytes_client (Int64.of_int amt));
     print_data_persec (OS.Clock.time ());
     let rec iperf_h chan amt_toget =
       match_lwt Net.Flow.read chan with
       | None ->
	   return ()
       | Some data -> begin
	   let l = Cstruct.len data in
	   st.rxbytes_client <- (Int64.add st.rxbytes_client (Int64.of_int l));
	   print_data_persec (OS.Clock.time ());
	   if (l < amt_toget) then begin
	     iperf_h chan (amt_toget - l)
	   end else begin
	     return ()
	   end
       end
     in
     iperf_h chan amt) >>
    Net.Flow.close chan >>
    (st.openconn_client <- (Int64.sub st.openconn_client 1L);
     print_data_persec (OS.Clock.time ());
     return ())
  in
  OS.Time.sleep (Random.float spread_time) >>
  Net.Flow.connect mgr (`TCPv4 (Some (Some src_ip, 0),
				(dest_ip, dport), iperftxrx))


let iperf (dip,dpt) chan =
  let rec iperf_h chan =
    match_lwt Net.Flow.read chan with
    | None ->
	Net.Flow.close chan >>
	(st.openconn_server <- (Int64.sub st.openconn_server 1L);
	 st.tot_server_conn <- (Int64.add st.tot_server_conn 1L);
	 print_data_persec (OS.Clock.time ());
	 return ())
    | Some data -> begin
	let l = Cstruct.len data in
	st.rxbytes_server <- (Int64.add st.rxbytes_server (Int64.of_int l));
	print_data_persec (OS.Clock.time ());
	Net.Flow.write chan data >>
	(st.txbytes_server <- (Int64.add st.txbytes_server (Int64.of_int l));
	 print_data_persec (OS.Clock.time ());
	 iperf_h chan)
    end
  in
  st.openconn_server <- (Int64.add st.openconn_server 1L);
  iperf_h chan


let main () =
  let mgr_th = Net.Manager.create (fun mgr interface id ->
    let first, second = match Net.Manager.get_intfs mgr with
    | [] | [_] -> failwith "iperf_self requires at least 2 network interfaces, exiting."
    | h::t  -> fst h, fst (List.hd t) in
    match id with
    | id when id = second -> (* client *)
	server_ready >>
	(printf "Setting up iperf clients on interface %s\n%!" (OS.Netif.string_of_id id);
	 Net.Manager.configure interface ip1 >>
	 let src_ip = Net.Manager.get_intf_ipv4addr mgr first in
	 let dest_ip = Net.Manager.get_intf_ipv4addr mgr second in
	 let src_ip_str = Ipaddr.V4.to_string src_ip in
	 let dest_ip_str = Ipaddr.V4.to_string dest_ip in
	 let rec startmultipleclients ths n num =
	   let num = num - 1 in
           let thsplus = (iperfclient_p mgr src_ip dest_ip (start_port + n)) :: ths in
	   match num with
	   | 0 -> thsplus
	   | _ -> startmultipleclients thsplus n num
	 in
	 let rec startclients ths n =
	   let n = n - 1 in
	   let thsplus = startmultipleclients ths n conn_per_port in
	   match n with
	   | 0 -> thsplus
	   | _ -> startclients thsplus n
	 in
	 let clientthreads = startclients [] num_ports in
	 printf "number of threads = %d\n%!" (List.length clientthreads);
	 join clientthreads >>
	 (let rec printstats n = 
	   Gc.compact ();
	   print_data (OS.Clock.time ());
	   match n with
	   | 0 -> return ()
	   | _ -> OS.Time.sleep 1. >> printstats (n -1)
	  in
	  printf "All Clients Done\n%!";
	  Lwt.wakeup clients_done_u ();
	  printstats 15 >>
	  (printf "Test completed.\n%!";
	   Lwt.wakeup test_completed_u ();
	   return ())
	 )

	)
    | id when id = first -> (* server *)
	OS.Time.sleep 1. >>
	(printf "Setting up iperf server on interface %s\n%!" (OS.Netif.string_of_id id);
	 Net.Manager.configure interface ip2 >>
	 let rec openlisteners listeners p_off fn =
	   let p_off = p_off - 1 in
	   let l_plus = (Net.Flow.listen mgr (`TCPv4 ((None, (start_port + p_off)), fn))) :: listeners in
	   match p_off with
	   | 0 -> l_plus
	   | _ -> openlisteners l_plus p_off fn
	 in
	 let all_listeners = openlisteners [] num_ports iperf in
	 printf "Done setting up servers \n%!";
	 Lwt.wakeup server_ready_u ();
	 print_data (OS.Clock.time ());
	 let rec closelisteners all = 
	   if st.openconn_server = 0L then begin
	     printf "All Servers Done\n%!";
	     printf "Closing all listen ports \n%!";
	     List.iter Lwt.cancel all;
	     return ()
	   end else begin
	     OS.Time.sleep 1. >>
	     closelisteners all_listeners 
	   end
	 in
	 clients_done >>
         closelisteners all_listeners
	)
    | _ ->
	(printf "interface %s not used\n%!" (OS.Netif.string_of_id id); return ())
  ) in
  test_completed >>
  (Lwt.cancel mgr_th;
   return ()
  )

