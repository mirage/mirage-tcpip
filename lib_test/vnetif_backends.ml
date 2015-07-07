(*
 * Copyright (c) 2015 Magnus Skjegstad <magnus@skjegstad.com>
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

module type Backend = sig
  include Vnetif.BACKEND
  val create : unit -> t
end

(** This backend adds a random number of trailing bytes to each frame *)
module Trailing_bytes : Backend = struct
  module X = Basic_backend.Make
  include X

  let max_bytes_to_add = 10

  (* Just adds trailing bytes, doesn't store anything in them *)
  let add_random_bytes src =
    let bytes_to_add = Random.int max_bytes_to_add in
    let len = Cstruct.len src in
    let dst = Cstruct.create (len + bytes_to_add) in
    Cstruct.blit src 0 dst 0 len;
    dst

  let set_listen_fn t id fn =
    (* Add random bytes before returning result to real listener *)
    X.set_listen_fn t id (fun buf ->
        fn (add_random_bytes buf))

  let create () =
    X.create ~use_async_readers:true ~yield:(fun() -> Lwt_main.yield () ) () 

end 

(** This backend drops packets *)
module Uniform_packet_loss : Backend = struct
  module X = Basic_backend.Make
  include X

  let drop_p = 0.01

  let write t id buffer =
    if Random.float 1.0 < drop_p then
    begin
        MProf.Trace.label "pkt_drop";
        Lwt.return_unit (* drop packet *)
    end else
        X.write t id buffer (* pass to real write *)

  let writev t id buffers =
    if Random.float 1.0 < drop_p then
    begin
        MProf.Trace.label "pkt_drop";
        Lwt.return_unit (* drop packet *)
    end else
        X.writev t id buffers (* pass to real writev *)

  let create () =
    X.create ~use_async_readers:true ~yield:(fun() -> Lwt_main.yield () ) () 

end 

(** This backend delivers all packets unmodified *)
module Basic : Backend = struct
  module X = Basic_backend.Make
  include X

  let create () =
    X.create ~use_async_readers:true ~yield:(fun() -> Lwt_main.yield () ) () 
end
