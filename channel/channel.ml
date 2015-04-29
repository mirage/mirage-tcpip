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

(** Buffered reading and writing over the Flow API *)

open Lwt

module Make(Flow:V1_LWT.FLOW) = struct

  type flow = Flow.flow
  type buffer = Cstruct.t
  type +'a io = 'a Lwt.t
  type 'a io_stream = 'a Lwt_stream.t

  exception Write_error of Flow.error
  exception Read_error of Flow.error

  type t = {
    flow: flow;
    mutable ibuf: Cstruct.t option; (* Queue of incoming buf *)
    mutable obufq: Cstruct.t list;  (* Queue of completed writebuf *)
    mutable obuf: Cstruct.t option; (* Active write buffer *)
    mutable opos: int;                 (* Position in active write buffer *)
  }

  let create flow =
    let ibuf = None in
    let obufq = [] in
    let obuf = None in
    let opos = 0 in
    { ibuf; obuf; flow; obufq; opos }

  let to_flow { flow; _ } = flow

  let ibuf_refill t =
    Flow.read t.flow >>= function
    | `Ok buf ->
      (* users of get_ibuf (and therefore ibuf_refill) expect the buffer
         returned here to have length >0; if Flow.read ever gives us empty
         buffers, this will be violated causing Channel users to see Cstruct
         exceptions *)
      t.ibuf <- Some buf;
      return_unit
    | `Error e ->
      fail (Read_error e)
    | `Eof ->
      (* close the flow before throwing exception; otherwise it will never be
         GC'd *)
      Flow.close t.flow >>= fun () ->
      fail End_of_file

  let rec get_ibuf t =
    match t.ibuf with
    | None -> ibuf_refill t >>= fun () -> get_ibuf t
    | Some buf when Cstruct.len buf = 0 -> ibuf_refill t >>= fun () -> get_ibuf t
    | Some buf -> return buf

  (* Read one character from the input channel *)
  let read_char t =
    get_ibuf t (* the fact that we returned means we have at least 1 char *)
    >>= fun buf ->
    let c = Cstruct.get_char buf 0 in
    t.ibuf <- Some (Cstruct.shift buf 1); (* advance read buffer, possibly to
                                             EOF *)
    return c

  (* Read up to len characters from the input channel
     and at most a full view. If not specified, read all *)
  let read_some ?len t =
    (* get_ibuf potentially throws EOF-related exceptions *)
    get_ibuf t >>= fun buf ->
    let avail = Cstruct.len buf in
    let len = match len with |Some len -> len |None -> avail in
    if len < avail then begin
      let hd,tl = Cstruct.split buf len in
      t.ibuf <- Some tl; (* leave some in the buffer; next time, we won't do a
                            blocking read *)
      return hd
    end else begin
      t.ibuf <- None;
      return buf
    end

 (* Read up to len characters from the input channel as a
    stream (and read all available if no length specified *)
  let read_stream ?len t =
    Lwt_stream.from (fun () ->
        Lwt.catch
          (fun () -> read_some ?len t >>= fun v -> return (Some v))
          (function End_of_file -> return_none | e -> fail e)
      )

  (* Read until a character is found *)
  let read_until t ch =
    Lwt.catch
       (fun () -> get_ibuf t >>= fun buf ->
       let len = Cstruct.len buf in
       let rec scan off =
         if off = len then None else begin
           if Cstruct.get_char buf off = ch then
             Some off else scan (off+1)
         end
       in
       match scan 0 with
       |None -> (* not found, return what we have until EOF *)
         t.ibuf <- None; (* basically guaranteeing that next read is EOF *)
         return (false, buf)
       |Some off -> (* found, so split the buffer *)
         let hd = Cstruct.sub buf 0 off in
         t.ibuf <- Some (Cstruct.shift buf (off+1));
         return (true, hd)
       )
      (function End_of_file -> return (false, Cstruct.create 0) | e -> fail e)

  (* This reads a line of input, which is terminated either by a CRLF
     sequence, or the end of the channel (which counts as a line).
     @return Returns a stream of views that terminates at EOF. *)
  let read_line t =
    let rec get acc =
      read_until t '\n' >>= function
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
    let buf = Io_page.to_cstruct (Io_page.get 1) in
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
    |Some _ when t.opos = 0 -> (* obuf wasnt ever used, so discard *)
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
      Cstruct.blit_from_string s off buf t.opos avail;
      t.opos <- t.opos + avail;
      write_string t s (off+avail) (len-avail)
    end else begin
      Cstruct.blit_from_string s off buf t.opos len;
      t.opos <- t.opos + len
    end

  let write_line t buf =
    write_string t buf 0 (String.length buf);
    write_char t '\n'

  let flush t =
    queue_obuf t;
    let l = List.rev t.obufq in
    t.obufq <- [];
    Flow.writev t.flow l >>= function
    | `Ok () -> Lwt.return_unit
    | `Error (e : Flow.error) -> fail (Write_error e)
    | `Eof -> fail (End_of_file)

  let close t =
    Lwt.catch
      (fun () -> flush t)
      (fun _  -> Flow.close t.flow)

end
