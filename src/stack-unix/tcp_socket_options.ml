(*
 * Copyright (c) 2017 Docker Inc
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

external tcp_set_keepalive_params: Unix.file_descr -> int -> int -> int -> unit = "caml_tcp_set_keepalive_params"

let enable_keepalive ~fd ~after ~interval ~probes =
  let fd' = Lwt_unix.unix_file_descr fd in
  let after = Duration.to_ms after in
  let interval = Duration.to_ms interval in
  tcp_set_keepalive_params fd' after interval probes;
  Lwt_unix.setsockopt fd Lwt_unix.SO_KEEPALIVE true