(*
 * Copyright (c) 2011 Anil Madhavapeddy <anil@recoil.org>
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

(* Buffered reading and writing over the flow API *)
open Lwt
open Printf
open Nettypes

module Make(Flow:FLOW) : 
  (CHANNEL with type src = Flow.src
            and type dst = Flow.dst
            and type mgr = Flow.mgr)  = struct

  type flow = Flow.t
  type src = Flow.src
  type dst = Flow.dst
  type mgr = Flow.mgr

  type t = {
    flow: flow;
    mutable ibuf: OS.Io_page.t option; (* Queue of incoming buf *)
    mutable obufq: OS.Io_page.t list;  (* Queue of completed writebuf *)
    mutable obuf: OS.Io_page.t option; (* Active write buffer *)
    mutable opos: int;                 (* Position in active write buffer *)
    abort_t: unit Lwt.t;
    abort_u: unit Lwt.u;
  }

  exception Closed

  let create flow =
    let ibuf = None in
    let obufq = [] in
    let obuf = None in
    let opos = 0 in
    let abort_t, abort_u = Lwt.task () in
    { ibuf; obuf; flow; obufq; opos; abort_t; abort_u }

  let ibuf_refill t = 
    match_lwt Flow.read t.flow with
    |Some buf ->
      t.ibuf <- Some buf;
      return ()
    |None ->
      fail Closed

  let rec get_ibuf t =
    match t.ibuf with
    |None -> ibuf_refill t >> get_ibuf t
    |Some buf when Cstruct.len buf = 0 -> ibuf_refill t >> get_ibuf t
    |Some buf -> return buf

  (* Read one character from the input channel *)
  let read_char t =
    lwt buf = get_ibuf t in
    let c = Cstruct.get_char buf 0 in
    t.ibuf <- Some (Cstruct.shift buf 1);
    return c

  (* Read up to len characters from the input channel
     and at most a full view. If not specified, read all *)
  let read_some ?len t =
    lwt buf = get_ibuf t in
    let avail = Cstruct.len buf in
    let len = match len with |Some len -> len |None -> avail in
    if len < avail then begin 
      let hd,tl = Cstruct.split buf len in
      t.ibuf <- Some tl;
      return hd
    end else begin 
      t.ibuf <- None;
      return buf
    end
    
  (* Read up to len characters from the input channel as a 
     stream (and read all available if no length specified *)
  let read_stream ?len t =
    Lwt_stream.from (fun () ->
      try_lwt
        lwt v = read_some ?len t in
        return (Some v)
      with Closed ->
        return None
    )
 
  (* Read until a character is found *)
  let read_until t ch =
    lwt buf = get_ibuf t in
    let len = Cstruct.len buf in
    let rec scan off =
      if off = len then None else begin
        if Cstruct.get_char buf off = ch then
          Some off else scan (off+1)
      end
    in
    match scan 0 with
    |None -> (* not found, return what we have until EOF *)
      t.ibuf <- None;
      return (false, buf)
    |Some off -> (* found, so split the buffer *)
      let hd = Cstruct.sub_buffer buf 0 off in
      t.ibuf <- Some (Cstruct.shift buf (off+1));
      return (true, hd)

  (* This reads a line of input, which is terminated either by a CRLF
     sequence, or the end of the channel (which counts as a line).
     @return Returns a stream of views that terminates at EOF.
     @raise Closed to signify EOF  *)
  let read_line t =
    let rec get acc =
      match_lwt read_until t '\n' with
      |(false, v) ->
        get (v :: acc)
      |(true, v) -> begin
        (* chop the CR if present *)
        let vlen = Cstruct.len v in
        let v =
         if vlen > 0 && (Cstruct.get_char v (vlen-1) = '\r') then
           Cstruct.sub v 0 (vlen-1) else v
        in
        return (v :: acc) 
      end
    in
    get [] >|= List.rev
    
  (* Output functions *)

  let alloc_obuf t =
    let buf = OS.Io_page.get () in
    t.obuf <- Some buf;
    t.opos <- 0;
    buf

  (* Queue the active write buffer onto the write queue, resizing the
   * view if necessary to the correct size. *)
  let queue_obuf t =
    match t.obuf with
    |None -> ()
    |Some buf when Cstruct.len buf = t.opos -> (* obuf is full *)
      t.obufq <- buf :: t.obufq;
      t.obuf <- None
    |Some buf when t.opos = 0 -> (* obuf wasnt ever used, so discard *)
      t.obuf <- None
    |Some buf -> (* partially filled obuf, so resize *)
      let buf = Cstruct.sub buf 0 t.opos in
      t.obufq <- buf :: t.obufq;
      t.obuf <- None

  (* Get an active output buffer, which will allocate it if needed.
   * The position to write into is stored in t.opos *)
  let get_obuf t =
    match t.obuf with
    |None -> alloc_obuf t
    |Some buf when Cstruct.len buf = t.opos -> queue_obuf t; alloc_obuf t
    |Some buf -> buf

  (* Non-blocking character write, since Io page allocation never blocks.
   * That may change in the future... *)
  let write_char t ch =
    let buf = get_obuf t in
    Cstruct.set_char buf t.opos ch;
    t.opos <- t.opos + 1

  (* This is zero copy; flush current IO page and queue up the incoming
   * buffer directly. *)
  let write_buffer t buf =
    queue_obuf t;
    t.obufq <- buf :: t.obufq

  let rec write_string t s off len =
    let buf = get_obuf t in
    let avail = Cstruct.len buf - t.opos in 
    if avail < len then begin
      Cstruct.set_buffer s off buf t.opos avail;
      t.opos <- t.opos + avail;
      write_string t s (off+avail) (len-avail)
    end else begin
      Cstruct.set_buffer s off buf t.opos len;
      t.opos <- t.opos + len
    end

  let write_line t buf =
    write_string t buf 0 (String.length buf);
    write_char t '\n'

  let rec flush t =
    queue_obuf t;
    let l = List.rev t.obufq in
    t.obufq <- [];
    Flow.writev t.flow l
 
  let close t =
    flush t >>
    Flow.close t.flow

  let connect mgr ?src dst fn =
    Flow.connect mgr ?src dst (fun f -> fn (create f))

  let listen mgr src fn =
    Flow.listen mgr src (fun dst f -> fn dst (create f))

end

module TCPv4 = Make(Flow.TCPv4)
module Shmem = Make(Flow.Shmem)

type t =
  | TCPv4 of TCPv4.t
  | Shmem of Shmem.t

let read_char = function
  | TCPv4 t -> TCPv4.read_char t
  | Shmem t -> Shmem.read_char t

let read_until = function
  | TCPv4 t -> TCPv4.read_until t
  | Shmem t -> Shmem.read_until t

let read_some ?len = function
  | TCPv4 t -> TCPv4.read_some ?len t
  | Shmem t -> Shmem.read_some ?len t

let read_stream ?len = function
  | TCPv4 t -> TCPv4.read_stream ?len t
  | Shmem t -> Shmem.read_stream ?len t

let read_line = function
  | TCPv4 t -> TCPv4.read_line t
  | Shmem t -> Shmem.read_line t

let write_char = function
  | TCPv4 t -> TCPv4.write_char t
  | Shmem t -> Shmem.write_char t

let write_string = function
  | TCPv4 t -> TCPv4.write_string t
  | Shmem t -> Shmem.write_string t

let write_buffer = function
  | TCPv4 t -> TCPv4.write_buffer t
  | Shmem t -> Shmem.write_buffer t

let write_line = function
  | TCPv4 t -> TCPv4.write_line t
  | Shmem t -> Shmem.write_line t

let flush = function
  | TCPv4 t -> TCPv4.flush t
  | Shmem t -> Shmem.flush t

let close = function
  | TCPv4 t -> TCPv4.close t
  | Shmem t -> Shmem.close t

let connect mgr = function
  |`TCPv4 (src, dst, fn) ->
     TCPv4.connect mgr ?src dst (fun t -> fn (TCPv4 t))
  |`Shmem (src, dst, fn) ->
     Shmem.connect mgr ?src dst (fun t -> fn (Shmem t))
  |_ -> fail (Failure "unknown protocol")

let listen mgr = function
  |`TCPv4 (src, fn) ->
     TCPv4.listen mgr src (fun dst t -> fn dst (TCPv4 t))
  |`Shmem (src, fn) ->
     Shmem.listen mgr src (fun dst t -> fn dst (Shmem t))
  |_ -> fail (Failure "unknown protocol")
