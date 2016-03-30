open Result

module Make(IP : V1_LWT.IPV4) = struct
  type buffer = Cstruct.t
  type 'a io = 'a Lwt.t
  type ipaddr = Ipaddr.V4.t

  type t = {
    ip : IP.t;
    echo_reply : bool;
  }

  let pp_dst_unreachable buf =
    Printf.sprintf "ICMP Destination Unreachable: %s\n%!" @@
    match Icmpv4_wire.get_icmpv4_code buf with
    | 0  -> "Destination network unreachable"
    | 1  -> "Destination host unreachable"
    | 2  -> "Destination protocol unreachable"
    | 3  -> "Destination port unreachable"
    | 4  -> "Fragmentation required, and DF flag set"
    | 5  -> "Source route failed"
    | 6  -> "Destination network unknown"
    | 7  -> "Destination host unknown"
    | 8  -> "Source host isolated"
    | 9  -> "Network administratively prohibited"
    | 10 -> "Host administratively prohibited"
    | 11 -> "Network unreachable for TOS"
    | 12 -> "Host unreachable for TOS"
    | 13 -> "Communication administratively prohibited"
    | 14 -> "Host Precedence Violation"
    | 15 -> "Precedence cutoff in effect"
    | code -> Printf.sprintf "Unknown ICMP code: %d" code

  let input t ~src ~dst buf =
    let should_reply t dst =
      let aux found this =
        match found with
        | true -> true
        | false -> if (Ipaddr.V4.compare dst this) = 0 then true else false
      in
      List.fold_left aux false (IP.get_ip t.ip)
    in
    let open Lwt.Infix in
    let open Printf in
    MProf.Trace.label "icmp_input";
    match Icmpv4_wire.get_icmpv4_ty buf with
    |0 -> (* echo reply *)
      printf "ICMP: discarding echo reply from %s\n%!" (Ipaddr.V4.to_string src);
      Lwt.return_unit
    |3 -> printf "%s\n%!" (pp_dst_unreachable buf); Lwt.return_unit
    |8 -> if t.echo_reply && should_reply t dst then begin
      (* convert the echo request into an echo reply *)
      let csum =
        let orig_csum = Icmpv4_wire.get_icmpv4_csum buf in
        let shift = if orig_csum > 0xffff -0x0800 then 0x0801 else 0x0800 in
        (orig_csum + shift) land 0xffff in
      Icmpv4_wire.set_icmpv4_ty buf 0;
      Icmpv4_wire.set_icmpv4_csum buf csum;
      (* stick an IPv4 header on the front and transmit *)
      let frame, header_len = IP.allocate_frame t.ip ~dst:src ~proto:`ICMP in
      let frame = Cstruct.set_len frame header_len in
      IP.write t.ip frame buf
      end else Lwt.return_unit
    |ty ->
      printf "ICMP unknown ty %d from %s\n" ty (Ipaddr.V4.to_string src);
      Lwt.return_unit

  type error = [ `Routing | `Unknown ]

  type id = t

  let connect ip = Lwt.return (`Ok { ip; echo_reply = true; })

  let disconnect _ = Lwt.return_unit

  let pp_of_error formatter = function
    | `Routing -> Format.fprintf formatter "%s" "routing"
    | `Unknown -> Format.fprintf formatter "%s" "unknown!"

  let writev t ~dst bufs = 
    let frame, header_len = IP.allocate_frame t.ip ~dst ~proto:`ICMP in
    let frame = Cstruct.set_len frame header_len in
    IP.writev t.ip frame bufs

  let write t ~dst buf = writev t ~dst [buf]

end
