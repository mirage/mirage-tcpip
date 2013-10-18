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

type stats = {
  mutable bytes: int64;
  mutable packets: int64;
  mutable bin_bytes:int64;
  mutable bin_packets: int64;
  mutable start_time: float;
  mutable last_time: float;
}

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

let port = 5001

let msg = "x"

let mlen = String.length msg

let server_ready, server_ready_u = Lwt.wait ()
let server_done, server_done_u = Lwt.wait ()

let iperfclient mgr src_ip dest_ip dport =
  let iperftx chan =
    printf "Iperf client: Made connection to server. \n%!";
    let a = Cstruct.sub (OS.Io_page.(to_cstruct (get 1))) 0 mlen in
    Cstruct.blit_from_string msg 0 a 0 mlen;
    let amt = 1000000 in
    for_lwt i = (amt / mlen) downto 1 do
      Net.Flow.write_nodelay chan a
    done >>
    let a = Cstruct.sub a 0 (amt - (mlen * (amt/mlen))) in
    Net.Flow.write_nodelay chan a >>
    Net.Flow.close chan
  in
  OS.Time.sleep 1. >>
  (printf "Iperf client: Attempting connection. \n%!";
   lwt conn = Net.Flow.connect mgr (`TCPv4 (Some (Some src_ip, 0),
					    (dest_ip, dport), iperftx)) in
   printf "Iperf client: Done.\n%!";
   return ()
  )


let print_data st ts_now = 
  Printf.printf "Iperf server: t = %f, rate = %Ld KBits/s, totbytes = %Ld, live_words = %d\n%!"
    (ts_now -. st.start_time)
    (Int64.of_float (((Int64.to_float st.bin_bytes) /. (ts_now -. st.last_time)) /. 125.))
    st.bytes Gc.((stat()).live_words); 
  st.last_time <- ts_now;
  st.bin_bytes <- 0L;
  st.bin_packets <- 0L 


let iperf (dip,dpt) chan =
  printf "Iperf server: Received connection.\n%!";
  let t0 = OS.Clock.time () in
  let st = {bytes=0L; packets=0L; bin_bytes=0L; bin_packets=0L; start_time = t0; last_time = t0} in
  let rec iperf_h chan =
    match_lwt Net.Flow.read chan with
    | None ->
	let ts_now = (OS.Clock.time ()) in 
	st.bin_bytes <- st.bytes;
	st.bin_packets <- st.packets;
	st.last_time <- st.start_time;
        print_data st ts_now;
	Net.Flow.close chan >>
	(printf "Iperf server: Done - closed connection. \n%!"; return ())
    | Some data -> begin
	let l = Cstruct.len data in
	st.bytes <- (Int64.add st.bytes (Int64.of_int l));
	st.packets <- (Int64.add st.packets 1L);
	st.bin_bytes <- (Int64.add st.bin_bytes (Int64.of_int l));
	st.bin_packets <- (Int64.add st.bin_packets 1L);
	let ts_now = (OS.Clock.time ()) in 
	if ((ts_now -. st.last_time) >= 1.0) then begin
          print_data st ts_now;
	end;
	iperf_h chan
    end
  in
  iperf_h chan >>
  (Lwt.wakeup server_done_u ();
   return ())


let main () =
  let mgr_th =  Net.Manager.create (fun mgr interface id ->
    let first, second = match Net.Manager.get_intfs mgr with
    | [] | [_] -> failwith "iperf_self requires at least 2 network interfaces, exiting."
    | h::t  -> fst h, fst (List.hd t) in
    match id with
    | id when id = second -> (* client *)
	OS.Time.sleep 1.0 >> 
	Net.Manager.configure interface ip1 >>
	(
	 server_ready >>
	 let () = printf "Setting up iperf client on interface %s\n%!" (OS.Netif.string_of_id id) in
	 let src_ip = Net.Manager.get_intf_ipv4addr mgr first in
	 let dest_ip = Net.Manager.get_intf_ipv4addr mgr second in
	 let src_ip_str = Ipaddr.V4.to_string src_ip in
	 let dest_ip_str = Ipaddr.V4.to_string dest_ip in
	 OS.Console.log (Printf.sprintf "I have IP %s, trying to connect to %s" src_ip_str dest_ip_str);
	 iperfclient mgr src_ip dest_ip port
	)
    | id when id = first -> (* server *)
	OS.Time.sleep 1.0 >> 
	Net.Manager.configure interface ip2 >>
	(
	 printf "Setting up iperf server on interface %s port %d\n%!" (OS.Netif.string_of_id id) port;
	 let _ = Net.Flow.listen mgr (`TCPv4 ((None, port), iperf)) in
	 printf "Done setting up server \n%!";
	 Lwt.wakeup server_ready_u ();
	 return ()
	)
    | _ ->
	(printf "interface %s not used\n%!" (OS.Netif.string_of_id id); return ())
  ) in
  server_done >>
  (Lwt.cancel mgr_th;
   return ()
  )
