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

module Trailing_bytes = struct
  module X = Basic_backend.Make
  include X

  let max_bytes_to_add = Int32.of_int 512

  (* Just adds trailing bytes, doesn't store anything in them *)
  let add_random_bytes src =
    let bytes_to_add = (Int32.to_int (Random.int32 max_bytes_to_add)) in
    let len = Cstruct.len src in
    let dst = Cstruct.create (len + bytes_to_add) in
    Cstruct.blit src 0 dst 0 len;
    dst

  let write t id buffer =
    X.write t id (add_random_bytes buffer)

  let writev t id buffers =
    let new_buffers = List.map (fun a -> (add_random_bytes a)) buffers in
    X.writev t id new_buffers

end
