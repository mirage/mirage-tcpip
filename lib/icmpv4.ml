open Result

module Parse = struct
  (* second 4 bytes of the message have varying interpretations *)
  type subheader =
    | Id_and_seq of Cstruct.uint16 * Cstruct.uint16
    | Pointer of Cstruct.uint8
    | Address of Ipaddr.V4.t
    | Unused

  type t = {
    code : Cstruct.uint8;
    ty : Cstruct.uint8;
    csum : Cstruct.uint16;
    subheader : subheader;
    payload : Cstruct.t option;
  }

  let subheader_of_cstruct ty buf =
    let open Cstruct.BE in
    match ty with
    | 0 | 8 | 13 | 14 | 15 | 16 -> Id_and_seq (get_uint16 buf 0, get_uint16 buf 2)
    | 3 | 11 | 4 -> Unused
    | 5 -> Address (Ipaddr.V4.of_int32 (get_uint32 buf 0))
    | 12 -> Pointer (Cstruct.get_uint8 buf 0)
    | _ -> Unused

  let input buf =
    if Cstruct.len buf < Wire_structs.Ipv4_wire.sizeof_icmpv4 then
      Error "packet too short for ICMPv4 header"
    else begin
      let open Wire_structs.Ipv4_wire in
      let ty = get_icmpv4_ty buf in
      let code = get_icmpv4_code buf in
      let csum = get_icmpv4_csum buf in
      let subheader = subheader_of_cstruct ty (Cstruct.shift buf 4) in
      let payload =
        if Cstruct.len buf > sizeof_icmpv4
        then Some (Cstruct.shift buf sizeof_icmpv4)
        else None
      in
      Ok { code; ty; csum; subheader; payload }
    end

end

module Print = struct
  let echo_request id seq =
    let open Wire_structs.Ipv4_wire in
    (* TODO: can this just be an appropriately-sized cstruct? *)
    let buf = Io_page.(get 1 |> to_cstruct) in
    let buf = Cstruct.set_len buf sizeof_icmpv4 in
    set_icmpv4_ty buf 0x08;
    set_icmpv4_code buf 0x00;
    set_icmpv4_seq buf seq;
    set_icmpv4_id buf id;
    buf

end

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
    match Wire_structs.Ipv4_wire.get_icmpv4_code buf with
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
    match Wire_structs.Ipv4_wire.get_icmpv4_ty buf with
    |0 -> (* echo reply *)
      printf "ICMP: discarding echo reply from %s\n%!" (Ipaddr.V4.to_string src);
      Lwt.return_unit
    |3 -> printf "%s\n%!" (pp_dst_unreachable buf); Lwt.return_unit
    |8 -> if t.echo_reply && should_reply t dst then begin
      (* convert the echo request into an echo reply *)
      let csum =
        let orig_csum = Wire_structs.Ipv4_wire.get_icmpv4_csum buf in
        let shift = if orig_csum > 0xffff -0x0800 then 0x0801 else 0x0800 in
        (orig_csum + shift) land 0xffff in
      Wire_structs.Ipv4_wire.set_icmpv4_ty buf 0;
      Wire_structs.Ipv4_wire.set_icmpv4_csum buf csum;
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
