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


let ip1 =
  let open Net.Nettypes in
  ( ipv4_addr_of_tuple (10l,100l,100l,101l),
    ipv4_addr_of_tuple (255l,255l,255l,0l),
   [ipv4_addr_of_tuple (10l,100l,100l,101l)]
  )

let ip2 =
  let open Net.Nettypes in
  ( ipv4_addr_of_tuple (10l,100l,100l,102l),
    ipv4_addr_of_tuple (255l,255l,255l,0l),
   [ipv4_addr_of_tuple (10l,100l,100l,102l)]
  )


let port = 5001

let msg = "01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890"

let mlen = String.length msg

let iperfclient tt ip =
  OS.Time.sleep 2. >>
  (printf "Iperf client: Attempting connection. \n%!";
   lwt conn = Net.Tcp.Pcb.connect tt ~dest_ip:ip ~dest_port:port in
   match conn with
   | None ->
       printf "Iperf client: Unable to connect to remote host (is the iperf server up?) \n%!";
       return ()
   | Some (pcb, _) ->
       printf "Iperf client: Made connection to server. \n%!";
       let a_io = OS.Io_page.get () in
       let a = OS.Io_page.to_cstruct a_io in
       Cstruct.blit_from_string msg 0 a 0 mlen;
       let a = Cstruct.sub a 0 mlen in
       let amt = 1000000000 in
       for_lwt i = (amt / mlen) downto 1 do
         Net.Tcp.Pcb.write pcb a
       done >>
       let a = Cstruct.sub a 0 (amt - (mlen * (amt/mlen))) in
       Net.Tcp.Pcb.write pcb a >>
       (printf "Iperf client: Done.\n%!";
	Net.Tcp.Pcb.close pcb)
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
  iperf_h chan


let main () =
  Net.Manager.create (fun mgr interface id ->
    let intfnum = int_of_string id in
    match intfnum with
    | 0 ->
	OS.Time.sleep 2. >>
	(printf "Setting up iperf client on interface %s\n%!" id;
	 Net.Manager.configure interface (`IPv4 ip2) >>
	 let tcps = Net.Manager.tcpv4_of_addr mgr None in
	 let tt = List.hd tcps in
	 let (ip,_,_) = ip1 in
	 lwt () = iperfclient tt ip in
         return ()
	)
    | 1 ->
	OS.Time.sleep 1. >>
	(printf "Setting up iperf server on interface %s\n%!" id;
	 Net.Manager.configure interface (`IPv4 ip1) >>
	 let _ = Net.Flow.listen mgr (`TCPv4 ((None, port), iperf)) in
	 printf "Done setting up server \n%!";
	 return ()
	)
    | _ ->
	(printf "interface %s not used\n%!" id; return ())
  )


let _ = OS.Main.run (main ())
