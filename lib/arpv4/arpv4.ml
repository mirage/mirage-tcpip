(*
 * Copyright (c) 2010-2011 Anil Madhavapeddy <anil@recoil.org>
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

open Lwt.Infix
open Result

let src = Logs.Src.create "arpv4" ~doc:"Mirage ARP module"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (Ethif : V1_LWT.ETHIF) (Clock : V1.CLOCK) (Time : V1_LWT.TIME) = struct

  module Generic_arp = Common.Make(Ethif)(Log)

  include Generic_arp

  let arp_timeout = 60. (* age entries out of cache after this many seconds *)
  let probe_repeat_delay = 1.5 (* per rfc5227, 2s >= probe_repeat_delay >= 1s *)
  let probe_num = 3 (* how many probes to send before giving up *)

  let rec tick t () =
    let now = Clock.time () in
    let expired = Hashtbl.fold (fun ip entry expired ->
        match entry with
        | Pending _ -> expired
        | Confirmed (t, _) -> if t >= now then ip :: expired else expired) t.cache []
    in
    List.iter (fun ip ->
         Log.info (fun f -> f "ARP: timeout %a" Ipaddr.V4.pp_hum ip); Hashtbl.remove t.cache ip
      ) expired;
    Time.sleep arp_timeout >>= tick t

  let notify t ip mac =
    let now = Clock.time () in
    let expire = now +. arp_timeout in
    try
      match Hashtbl.find t.cache ip with
      | Pending (_, w) ->
        Hashtbl.replace t.cache ip (Confirmed (expire, mac));
        Lwt.wakeup w (`Ok mac)
      | Confirmed _ ->
        Hashtbl.replace t.cache ip (Confirmed (expire, mac))
    with
    | Not_found ->
      Hashtbl.replace t.cache ip (Confirmed (expire, mac))

  (* Respond to incoming ARP requests if they're for one of our bound IPs *)
  let input t frame =
    MProf.Trace.label "arpv4.input";
    match Arpv4_packet.Unmarshal.of_cstruct frame with
    | Result.Error s ->
      Log.debug (fun f -> f "Failed to parse arpv4 header: %a (buffer: %S)"
                   Arpv4_packet.Unmarshal.pp_error s (Cstruct.to_string frame));
      Lwt.return_unit
    | Result.Ok arp ->
      match arp.op with
      | Arpv4_wire.Reply ->
        (* If we have pending entry, notify the waiters that answer is ready *)
        notify t arp.spa arp.sha;
        Lwt.return_unit
      | Arpv4_wire.Request ->
        (* Received ARP request, check if we can satisfy it from
           our own IPv4 list *)
        match List.mem arp.tpa t.bound_ips with
        | false -> Lwt.return_unit
        | true ->
          output t (Generic_arp.answer_query t arp)

  (* Query the cache for an ARP entry, which may result in the sender sleeping
     waiting for a response *)
  let query t ip =
    try match Hashtbl.find t.cache ip with
      | Pending (t, _) -> t
      | Confirmed (_, mac) -> Lwt.return (`Ok mac)
    with
    | Not_found ->
      let response, waker = MProf.Trace.named_wait "ARP response" in
      Hashtbl.add t.cache ip (Pending (response, waker));
      let rec retry n () =
        (* First request, so send a query packet *)
        output_probe t ip >>= fun () ->
        Lwt.choose [ (response >>= fun _ -> Lwt.return `Ok);
                     (Time.sleep probe_repeat_delay >>= fun () -> Lwt.return `Timeout) ] >>= function
        | `Ok -> Lwt.return_unit
        | `Timeout ->
          if n < probe_num then begin
            let n = n+1 in
            Log.info (fun f -> f "ARP: retrying %a (n=%d)" Ipaddr.V4.pp_hum ip n);
            retry n ()
          end else begin
            Hashtbl.remove t.cache ip;
            Lwt.wakeup waker `Timeout;
            Lwt.return_unit
          end
      in
      Lwt.async (retry 0);
      response

  let connect ethif =
    let t = Generic_arp.connect ethif in
    Lwt.async (tick t);
    Lwt.return (`Ok t)

  let disconnect t =
    Log.info (fun f -> f "Disconnected arpv4 device on %s" (Macaddr.to_string (
               Ethif.mac t.ethif)));
    Lwt.return_unit (* TODO: should kill tick *)
end
