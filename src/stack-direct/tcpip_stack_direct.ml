(*
 * Copyright (c) 2011-2014 Anil Madhavapeddy <anil@recoil.org>
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

open Lwt.Infix

let src = Logs.Src.create "tcpip-stack-direct" ~doc:"Pure OCaml TCP/IP stack"
module Log = (val Logs.src_log src : Logs.LOG)

module IPV4V6 (Ipv4 : Tcpip.Ip.S with type ipaddr = Ipaddr.V4.t) (Ipv6 : Tcpip.Ip.S with type ipaddr = Ipaddr.V6.t) = struct

  type ipaddr   = Ipaddr.t
  type callback = src:ipaddr -> dst:ipaddr -> Cstruct.t -> unit Lwt.t

  let pp_ipaddr = Ipaddr.pp

  type error = [ Tcpip.Ip.error | `Ipv4 of Ipv4.error | `Ipv6 of Ipv6.error | `Msg of string ]

  let pp_error ppf = function
    | #Tcpip.Ip.error as e -> Tcpip.Ip.pp_error ppf e
    | `Ipv4 e -> Ipv4.pp_error ppf e
    | `Ipv6 e -> Ipv6.pp_error ppf e
    | `Msg m -> Fmt.string ppf m

  type t = { ipv4 : Ipv4.t ; ipv4_only : bool ; ipv6 : Ipv6.t ; ipv6_only : bool }

  let connect ~ipv4_only ~ipv6_only ipv4 ipv6 =
    if ipv4_only && ipv6_only then
      Lwt.fail_with "cannot configure stack with both IPv4 only and IPv6 only"
    else
      Lwt.return { ipv4 ; ipv4_only ; ipv6 ; ipv6_only }

  let disconnect _ = Lwt.return_unit

  let input t ~tcp ~udp ~default =
    let tcp4 ~src ~dst payload = tcp ~src:(Ipaddr.V4 src) ~dst:(Ipaddr.V4 dst) payload
    and tcp6 ~src ~dst payload = tcp ~src:(Ipaddr.V6 src) ~dst:(Ipaddr.V6 dst) payload
    and udp4 ~src ~dst payload = udp ~src:(Ipaddr.V4 src) ~dst:(Ipaddr.V4 dst) payload
    and udp6 ~src ~dst payload = udp ~src:(Ipaddr.V6 src) ~dst:(Ipaddr.V6 dst) payload
    and default4 ~proto ~src ~dst payload = default ~proto ~src:(Ipaddr.V4 src) ~dst:(Ipaddr.V4 dst) payload
    and default6 ~proto ~src ~dst payload = default ~proto ~src:(Ipaddr.V6 src) ~dst:(Ipaddr.V6 dst) payload
    in
    fun buf ->
      if Cstruct.length buf >= 1 then
        let v = Cstruct.get_uint8 buf 0 lsr 4 in
        if v = 4 && not t.ipv6_only then
          Ipv4.input t.ipv4 ~tcp:tcp4 ~udp:udp4 ~default:default4 buf
        else if v = 6 && not t.ipv4_only then
          Ipv6.input t.ipv6 ~tcp:tcp6 ~udp:udp6 ~default:default6 buf
        else
          Lwt.return_unit
      else
        Lwt.return_unit

  let write t ?fragment ?ttl ?src dst proto ?size headerf bufs =
    match dst with
    | Ipaddr.V4 dst ->
      if not t.ipv6_only then
        match
          match src with
          | None -> Ok None
          | Some (Ipaddr.V4 src) -> Ok (Some src)
          | _ -> Error (`Msg "source must be V4 if dst is V4")
        with
        | Error e -> Lwt.return (Error e)
        | Ok src ->
          Ipv4.write t.ipv4 ?fragment ?ttl ?src dst proto ?size headerf bufs >|= function
          | Ok () -> Ok ()
          | Error e -> Error (`Ipv4 e)
      else begin
        Log.warn (fun m -> m "attempted to write an IPv4 packet in a v6 only stack");
        Lwt.return (Ok ())
      end
    | Ipaddr.V6 dst ->
      if not t.ipv4_only then
        match
          match src with
          | None -> Ok None
          | Some (Ipaddr.V6 src) -> Ok (Some src)
          | _ -> Error (`Msg "source must be V6 if dst is V6")
        with
        | Error e -> Lwt.return (Error e)
        | Ok src ->
          Ipv6.write t.ipv6 ?fragment ?ttl ?src dst proto ?size headerf bufs >|= function
          | Ok () -> Ok ()
          | Error e -> Error (`Ipv6 e)
      else begin
        Log.warn (fun m -> m "attempted to write an IPv6 packet in a v4 only stack");
        Lwt.return (Ok ())
      end

  let pseudoheader t ?src dst proto len =
    match dst with
    | Ipaddr.V4 dst ->
      let src =
        match src with
        | None -> None
        | Some (Ipaddr.V4 src) -> Some src
        | _ -> None (* cannot happen *)
      in
      Ipv4.pseudoheader t.ipv4 ?src dst proto len
    | Ipaddr.V6 dst ->
      let src =
        match src with
        | None -> None
        | Some (Ipaddr.V6 src) -> Some src
        | _ -> None (* cannot happen *)
      in
      Ipv6.pseudoheader t.ipv6 ?src dst proto len

  let src t ~dst =
    match dst with
    | Ipaddr.V4 dst -> Ipaddr.V4 (Ipv4.src t.ipv4 ~dst)
    | Ipaddr.V6 dst -> Ipaddr.V6 (Ipv6.src t.ipv6 ~dst)

  let get_ip t =
    List.map (fun ip -> Ipaddr.V4 ip) (Ipv4.get_ip t.ipv4) @
    List.map (fun ip -> Ipaddr.V6 ip) (Ipv6.get_ip t.ipv6)

  let mtu t ~dst = match dst with
    | Ipaddr.V4 dst -> Ipv4.mtu t.ipv4 ~dst
    | Ipaddr.V6 dst -> Ipv6.mtu t.ipv6 ~dst
end

module MakeV4V6
    (Time     : Mirage_time.S)
    (Random   : Mirage_random.S)
    (Netif    : Mirage_net.S)
    (Eth      : Ethernet.S)
    (Arpv4    : Arp.S)
    (Ip       : Tcpip.Ip.S with type ipaddr = Ipaddr.t)
    (Icmpv4   : Icmpv4.S)
    (Udp      : Tcpip.Udp.S with type ipaddr = Ipaddr.t)
    (Tcp      : Tcpip.Tcp.S with type ipaddr = Ipaddr.t) = struct

  module UDP = Udp
  module TCP = Tcp
  module IP = Ip

  type t = {
    netif : Netif.t;
    ethif : Eth.t;
    arpv4 : Arpv4.t;
    icmpv4 : Icmpv4.t;
    ip : IP.t;
    udp : Udp.t;
    tcp : Tcp.t;
    mutable task : unit Lwt.t option;
  }

  let pp fmt t =
    Format.fprintf fmt "mac=%a,ip=%a" Macaddr.pp (Eth.mac t.ethif)
      Fmt.(list ~sep:(any ", ") Ipaddr.pp) (IP.get_ip t.ip)

  let tcp { tcp; _ } = tcp
  let udp { udp; _ } = udp
  let ip { ip; _ } = ip

  let listen t =
    Lwt.catch (fun () ->
        Log.debug (fun f -> f "Establishing or updating listener for stack %a" pp t);
        let tcp = Tcp.input t.tcp
        and udp = Udp.input t.udp
        and default ~proto ~src ~dst buf =
          match proto, src, dst with
          | 1, Ipaddr.V4 src, Ipaddr.V4 dst -> Icmpv4.input t.icmpv4 ~src ~dst buf
          | _ -> Lwt.return_unit
        in
        let ethif_listener = Eth.input
            ~arpv4:(Arpv4.input t.arpv4)
            ~ipv4:(IP.input ~tcp ~udp ~default t.ip)
            ~ipv6:(IP.input ~tcp ~udp ~default t.ip)
            t.ethif
        in
        Netif.listen t.netif ~header_size:Ethernet.Packet.sizeof_ethernet ethif_listener
        >>= function
        | Error e ->
          Log.warn (fun p -> p "%a" Netif.pp_error e) ;
          (* XXX: error should be passed to the caller *)
          Lwt.return_unit
        | Ok _res ->
          let nstat = Netif.get_stats_counters t.netif in
          let open Mirage_net in
          Log.info (fun f ->
              f "listening loop of interface %s terminated regularly:@ %Lu bytes \
                 (%lu packets) received, %Lu bytes (%lu packets) sent@ "
                (Macaddr.to_string (Netif.mac t.netif))
                nstat.rx_bytes nstat.rx_pkts
                nstat.tx_bytes nstat.tx_pkts) ;
          Lwt.return_unit)
      (function
        | Lwt.Canceled ->
          Log.info (fun f -> f "listen of %a cancelled" pp t);
          Lwt.return_unit
        | e -> Lwt.fail e)

  let connect netif ethif arpv4 ip icmpv4 udp tcp =
    let t = { netif; ethif; arpv4; ip; icmpv4; tcp; udp; task = None } in
    Log.info (fun f -> f "Dual TCP/IP stack assembled: %a" pp t);
    Lwt.async (fun () -> let task = listen t in t.task <- Some task; task);
    Lwt.return t

  let disconnect t =
    Log.info (fun f -> f "Dual TCP/IP stack disconnected: %a" pp t);
    (match t.task with None -> () | Some task -> Lwt.cancel task);
    Lwt.return_unit
end

module TCPV4V6 (S : Tcpip.Stack.V4V6) : sig
  include Tcpip.Tcp.S with type ipaddr = Ipaddr.t
                       and type flow = S.TCP.flow
                       and type t = S.TCP.t

  val connect : S.t -> t Lwt.t
end = struct
  include S.TCP

  let connect stackv4v6 = Lwt.return (S.tcp stackv4v6)
end
