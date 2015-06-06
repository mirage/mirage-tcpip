(*
 * Copyright (c) 2015 Thomas Gazagnaire <thomas@gazagnaire.org>
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

type t = {
  tcp_flows   : int;
  tcp_listens : int;
  tcp_channels: int;
  tcp_connects: int;
}

let tcp_flows = ref 0
let tcp_listens = ref 0
let tcp_channels = ref 0
let tcp_connects = ref 0

let incr_flow t = incr tcp_flows
let decr_flow t = decr tcp_flows

let incr_listen t = incr tcp_listens
let decr_listen t = decr tcp_listens

let incr_channel t = incr tcp_channels
let decr_channel t = decr tcp_channels

let incr_connect t = incr tcp_connects
let decr_connect t = decr tcp_connects

let create () = {
  tcp_flows    = !tcp_flows;
  tcp_listens  = !tcp_listens;
  tcp_channels = !tcp_channels;
  tcp_connects = !tcp_connects;
}
