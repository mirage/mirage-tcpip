(*
 * Copyright (c) 2006-2010 Anil Madhavapeddy <anil@recoil.org>
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
 *
 *)

open Lwt
open Printf

(* This is a hand-crafted DHCP option parser. Did not use MPL
   here as it doesn't have enough variable length array support
   yet. At some point, this should be rewritten to use more of the
   autogen Mpl_stdlib *)

type msg = [  (* Message types, without payloads *)
|`Pad
|`Subnet_mask
|`Time_offset
|`Router
|`Broadcast
|`Time_server
|`Name_server
|`DNS_server
|`Netbios_name_server
|`Host_name
|`Domain_name
|`Requested_ip
|`Lease_time
|`Message_type
|`Server_identifier
|`Interface_mtu
|`Parameter_request
|`Message
|`Max_size
|`Client_id
|`Domain_search (* RFC 3397 *)
|`End
|`Unknown of char
]

type op = [  (* DHCP operations *)
|`Discover
|`Offer
|`Request
|`Decline
|`Ack
|`Nak
|`Release
|`Inform
|`Unknown of char
]

type t = [   (* Full message payloads *)
| `Pad
| `Subnet_mask of Ipaddr.V4.t
| `Time_offset of string
| `Router of Ipaddr.V4.t list
| `Broadcast of Ipaddr.V4.t
| `Time_server of Ipaddr.V4.t list
| `Name_server of Ipaddr.V4.t list
| `DNS_server of Ipaddr.V4.t list
| `Netbios_name_server of Ipaddr.V4.t list
| `Host_name of string
| `Domain_name of string
| `Requested_ip of Ipaddr.V4.t
| `Interface_mtu of int
| `Lease_time of int32
| `Message_type of op
| `Server_identifier of Ipaddr.V4.t
| `Parameter_request of msg list
| `Message of string
| `Max_size of int
| `Client_id of string
| `Domain_search of string (* not full support yet *)
| `Unknown of (char * string) (* code * buffer *)
| `End 
]

let msg_to_string (x:msg) =
  match x with
  |`Pad -> "Pad"
  |`Subnet_mask -> "Subnet mask"
  |`Broadcast -> "Broadcast"
  |`Time_offset -> "Time offset"
  |`Router -> "Router"
  |`Time_server -> "Time server"
  |`Name_server -> "Name server"
  |`DNS_server -> "DNS server"
  |`Host_name -> "Host name"
  |`Domain_name -> "Domain name"
  |`Requested_ip -> "Requested IP"
  |`Lease_time -> "Lease time"
  |`Message_type -> "Message type"
  |`Server_identifier -> "Server identifier"
  |`Parameter_request -> "Parameter request"
  |`Message -> "Message"
  |`Interface_mtu -> "Interface MTU"
  |`Max_size -> "Max size"
  |`Client_id -> "Client id"
  |`Domain_search -> "Domain search"
  |`Netbios_name_server -> "Netbios name server"
  |`Unknown c -> sprintf "Unknown(%d)" (Char.code c)
  |`End -> "End"

let op_to_string (x:op) =
  match x with
  |`Discover -> "Discover"
  |`Offer -> "Offer"
  |`Request -> "Request"
  |`Decline -> "Decline"
  |`Ack -> "Ack"
  |`Nak -> "Nack"
  |`Release -> "Release"
  |`Inform -> "Inform"
  |`Unknown x -> "Unknown " ^ (string_of_int (Char.code x))
 
let t_to_string (t:t) =
  let ip_one s ip = sprintf "%s(%s)" s (Ipaddr.V4.to_string ip) in
  let ip_list s ips = sprintf "%s(%s)" s (String.concat "," (List.map Ipaddr.V4.to_string ips)) in
  let str s v = sprintf "%s(%s)" s (String.escaped v) in
  let strs s v = sprintf "%s(%s)" s (String.concat "," v) in
  let i32 s v = sprintf "%s(%lu)" s v in
  match t with
  | `Pad -> "Pad"
  | `Subnet_mask ip -> ip_one "Subnet mask" ip
  | `Time_offset x -> "Time offset"
  | `Broadcast x -> ip_one "Broadcast" x
  | `Router ips  -> ip_list "Routers" ips
  | `Time_server ips -> ip_list "Time servers" ips
  | `Name_server ips -> ip_list "Name servers" ips
  | `DNS_server ips -> ip_list "DNS servers" ips
  | `Host_name s -> str "Host name" s 
  | `Domain_name s -> str "Domain name" s
  | `Requested_ip ip -> ip_one "Requested ip" ip
  | `Lease_time tm -> i32 "Lease time" tm 
  | `Message_type op -> str "Message type" (op_to_string op)
  | `Server_identifier ip -> ip_one "Server identifer" ip
  | `Parameter_request ps -> strs "Parameter request" (List.map msg_to_string ps)
  | `Message s -> str "Message" s
  | `Max_size sz -> str "Max size" (string_of_int sz)
  | `Interface_mtu sz -> str "Interface MTU" (string_of_int sz)
  | `Client_id id -> str "Client id" id
  | `Domain_search d -> str "Domain search" d
  | `Netbios_name_server d -> ip_list "NetBIOS name server" d
  | `Unknown (c,x) -> sprintf "Unknown(%d[%d])" (Char.code c) (String.length x)
  | `End -> "End"

let ipv4_addr_of_bytes x =
  let open Int32 in
  let b n = of_int (Char.code (x.[n])) in
  let r = add (add (add (shift_left (b 0) 24) (shift_left (b 1) 16)) (shift_left (b 2) 8)) (b 3) in
  Ipaddr.V4.of_int32 r

module Marshal = struct
  let t_to_code (x:msg) =
    match x with
    |`Pad -> 0
    |`Subnet_mask -> 1
    |`Time_offset -> 2
    |`Router -> 3
    |`Time_server -> 4
    |`Name_server -> 5
    |`DNS_server -> 6
    |`Host_name -> 12
    |`Domain_name -> 15
    |`Interface_mtu -> 26
    |`Broadcast -> 28
    |`Netbios_name_server -> 44
    |`Requested_ip -> 50
    |`Lease_time -> 51
    |`Message_type -> 53
    |`Server_identifier -> 54
    |`Parameter_request -> 55
    |`Message -> 56
    |`Max_size -> 57
    |`Client_id -> 61
    |`Domain_search -> 119
    |`End -> 255
    |`Unknown c -> Char.code c

  let to_byte x = String.make 1 (Char.chr (t_to_code x))

  let uint32_to_bytes s = 
    let x = String.create 4 in
    let (>!) x y = Int32.logand (Int32.shift_right x y) 255l in
    x.[0] <- Char.chr (Int32.to_int (s >! 24));
    x.[1] <- Char.chr (Int32.to_int (s >! 16));
    x.[2] <- Char.chr (Int32.to_int (s >! 8));
    x.[3] <- Char.chr (Int32.to_int (s >! 0));
    x

  let uint16_to_bytes s =
    let x = String.create 2 in
    x.[0] <- Char.chr (s land 255);
    x.[1] <- Char.chr ((s lsl 8) land 255);
    x

  let size x = String.make 1 (Char.chr x)
  let str c x = to_byte c :: (size (String.length x)) :: [x]
  let uint32 c x = to_byte c :: [ "\004"; uint32_to_bytes x]
  let uint16 c x = to_byte c :: [ "\002"; uint16_to_bytes x]
  let ip_list c ips = 
    let x = List.map (fun x -> (uint32_to_bytes (Ipaddr.V4.to_int32 x))) ips in
    to_byte c :: (size (List.length x * 4)) :: x
  let ip_one c x = uint32 c (Ipaddr.V4.to_int32 x)

  let to_bytes (x:t) =
    let bits = match x with
    |`Pad -> [to_byte `Pad]
    |`Subnet_mask mask -> ip_one `Subnet_mask mask
    |`Time_offset off -> assert false (* TODO 2s complement not uint32 *)
    |`Router ips -> ip_list `Router ips
    |`Broadcast ip -> ip_one `Broadcast ip
    |`Time_server ips -> ip_list `Time_server ips
    |`Name_server ips -> ip_list `Name_server ips
    |`DNS_server ips -> ip_list `DNS_server ips
    |`Netbios_name_server ips -> ip_list `Netbios_name_server ips
    |`Host_name h -> str `Host_name h
    |`Domain_name n -> str `Domain_name n
    |`Requested_ip ip -> ip_one `Requested_ip ip
    |`Lease_time t -> uint32 `Lease_time t
    |`Message x -> str `Message x
    |`Max_size s -> uint16 `Max_size s
    |`Interface_mtu s -> uint16 `Interface_mtu s
    |`Message_type mtype ->
      let mcode = function
      |`Discover -> "\001"
      |`Offer -> "\002"
      |`Request -> "\003"
      |`Decline -> "\004"
      |`Ack -> "\005"
      |`Nak -> "\006"
      |`Release -> "\007"
      |`Inform -> "\008"
      |`Unknown x -> String.make 1 x in
      to_byte `Message_type :: "\001" :: [mcode mtype]
    |`Server_identifier id -> ip_one `Server_identifier id
    |`Parameter_request ps ->
      to_byte `Parameter_request :: (size (List.length ps)) :: 
        List.map to_byte ps
    |`Client_id s ->
      let s' = "\000" ^ s in (* only support domain name ids *)
      str `Client_id s'
    |`Domain_search s ->
      assert false (* not supported yet, requires annoying DNS compression *)
    |`End -> [to_byte `End]
    |`Unknown (c,x) -> [ (String.make 1 c); x ]
    in String.concat "" bits

  let options mtype xs = 
    let buf = String.make 312 '\000' in
    let p = String.concat "" (List.map to_bytes (`Message_type mtype :: xs @ [`End])) in
    (* DHCP packets have minimum length, hence the blit into buf *)
    String.blit p 0 buf 0 (String.length p);
    buf
end

module Unmarshal = struct

  exception Error of string

  let msg_of_code x : msg =
    match x with
    |'\000' -> `Pad
    |'\001' -> `Subnet_mask 
    |'\002' -> `Time_offset
    |'\003' -> `Router
    |'\004' -> `Time_server
    |'\005' -> `Name_server 
    |'\006' -> `DNS_server 
    |'\012' -> `Host_name 
    |'\015' -> `Domain_name 
    |'\026' -> `Interface_mtu
    |'\028' -> `Broadcast
    |'\044' -> `Netbios_name_server
    |'\050' -> `Requested_ip
    |'\051' -> `Lease_time
    |'\053' -> `Message_type
    |'\054' -> `Server_identifier
    |'\055' -> `Parameter_request 
    |'\056' -> `Message
    |'\057' -> `Max_size 
    |'\061' -> `Client_id
    |'\119' -> `Domain_search
    |'\255' -> `End
    |x -> `Unknown x

  let of_bytes buf : t list =
    let pos = ref 0 in
    let getc () =  (* Get one character *)
      let r = String.get buf !pos in
      pos := !pos + 1;
      r in
    let getint () = (* Get one integer *)
      Char.code (getc ()) in
    let slice len = (* Get a substring *)
      if (!pos + len) > (String.length buf) || !pos > (String.length buf) 
        then raise (Error (sprintf "Requested too much string at %d %d (%d)" !pos len (String.length buf) ));
      let r = String.sub buf !pos len in 
      pos := !pos + len;
      r in
    let check c = (* Check that a char is the provided value *)
      let r = getc () in 
      if r != c then raise (Error (sprintf "check failed at %d != %d" !pos (Char.code c))) in
    let get_addr fn = (* Get one address *)
      check '\004';
      fn (slice 4) in
    let get_number len = (* Get a number from len bytes *)
      let bytestring = slice len in
      let r = ref 0 in 
      for i = 0 to (len - 1) do
         let bitshift = ((len - (i + 1)) * 8) in
         r := ((Char.code bytestring.[i]) lsl bitshift) + !r;
      done; 
      !r in
    let get_addrs fn = (* Repeat fn n times and return the list *)
      let len = getint () / 4 in
      let res = ref [] in 
      for i = 1 to len do
        res := (fn (slice 4)) :: !res
      done;
      List.rev !res in 
    let uint32_of_bytes x =
      let fn p = Int32.shift_left (Int32.of_int (Char.code x.[p])) ((3-p)*8) in
      let (++) = Int32.add in
      (fn 0) ++ (fn 1) ++ (fn 2) ++ (fn 3) in
    let rec fn acc =
      let cont (r:t) = fn (r :: acc) in
      let code = msg_of_code (getc ()) in
      match code with
      |`Pad -> fn acc
      |`Subnet_mask -> cont (`Subnet_mask (get_addr ipv4_addr_of_bytes))
      |`Time_offset -> cont (`Time_offset (get_addr (fun x -> x)))
      |`Router -> cont (`Router (get_addrs ipv4_addr_of_bytes))
      |`Broadcast -> cont (`Broadcast (get_addr ipv4_addr_of_bytes))
      |`Time_server -> cont (`Time_server (get_addrs ipv4_addr_of_bytes))
      |`Name_server -> cont (`Name_server (get_addrs ipv4_addr_of_bytes))
      |`DNS_server -> cont (`DNS_server (get_addrs ipv4_addr_of_bytes))
      |`Host_name -> cont (`Host_name (slice (getint ())))
      |`Domain_name -> cont (`Domain_name (slice (getint ())))
      |`Requested_ip -> cont (`Requested_ip (get_addr ipv4_addr_of_bytes))
      |`Server_identifier -> cont (`Server_identifier (get_addr ipv4_addr_of_bytes)) 
      |`Lease_time -> cont (`Lease_time (get_addr uint32_of_bytes))
      |`Domain_search -> cont (`Domain_search (slice (getint())))
      |`Netbios_name_server -> cont (`Netbios_name_server (get_addrs ipv4_addr_of_bytes))
      |`Message -> cont (`Message (slice (getint ())))
      |`Message_type ->
          check '\001';
          let mcode = match (getc ()) with
          |'\001' -> `Discover
          |'\002' -> `Offer 
          |'\003' -> `Request 
          |'\004' -> `Decline
          |'\005' -> `Ack
          |'\006' -> `Nak
          |'\007' -> `Release
          |'\008'  -> `Inform
          |x -> `Unknown x in
          cont (`Message_type mcode)
      |`Parameter_request ->
          let len = getint () in
          let params = ref [] in
          for i = 1 to len do
            params := (msg_of_code (getc ())) :: !params
          done;
          cont (`Parameter_request (List.rev !params))
      |`Max_size ->
          let len = getint () in
          cont (`Max_size (get_number len))
      |`Interface_mtu -> 
          (* according to some printf/tcpdump testing, this is being set but not
           * respected by the unikernel *)
          let len = getint () in
          cont (`Interface_mtu (get_number len))
      |`Client_id ->
          let len = getint () in 
          let _ = getint () in (* disregard type information *)
          cont (`Client_id (slice len))
      |`End -> acc
      |`Unknown c -> cont (`Unknown (c, (slice (getint ()))))
      in
      fn []       
end 

module Packet = struct
  type p  = {
    op: op;
    opts: t list;
  }

  let of_bytes buf =
    let opts = Unmarshal.of_bytes buf in
    let mtype, rest = List.partition (function `Message_type _ -> true |_ -> false) opts in
    let op = match mtype with [ `Message_type m ] -> m |_ -> raise (Unmarshal.Error "no mtype") in
    { op=op; opts=rest }

  let to_bytes p =
    Marshal.options p.op p.opts

  let prettyprint t =
    sprintf "%s : %s" (op_to_string t.op) (String.concat ", " (List.map t_to_string t.opts))

  (* Find an option in a packet *)
  let find p fn = 
    List.fold_left (fun a b ->
      match fn b with 
      |Some x -> Some x
      |None -> a) None p.opts

  (* Find an option list, and return empty list if opt doesnt exist *)
  let findl p fn =
    match find p fn with
    |Some l -> l
    |None -> []
end
