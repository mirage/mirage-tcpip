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

(** Persistent and hierarchical Key/Value stores.

    This module can be used to pass data to the network stack or to
    get back data from the stack.
*)

(** Signature for hierarchical and persitent K/V stores. *)
module type S = sig
  (** {1 Persistant and hierarchical K/V store} *)

  type step = string
  (** The type for {!key} steps. *)

  type key = step list
  (** The type for hierarchical keys. *)

  type value = string
  (** The type for raw values. *)

  val read: key -> value option Lwt.t
  (** Read a value in the store. *)

  val writev: (key * value) list -> unit Lwt.t
  (** Write a list of key/values in the store. The operation is
      atomic. *)

  val remove: key -> unit Lwt.t
  (** Remove a value from the store. *)

  val dirs: key -> step list Lwt.t
  (** List the key sub-directories. *)

end

module Memory: S

module Global: sig
  include S
  val set: (module S) -> unit
end
(** A global KV store. Byt default, it is using {!Memory}, but the
    implementation can be changed at runtime by using {!Global.set}. *)
