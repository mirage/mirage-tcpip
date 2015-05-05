open Lwt

(* this is a very small set of tests for the channel interface, intended to
   ensure that EOF conditions on the underlying flow are handled properly *)
module Channel = Channel.Make(Fflow)

let cmp a b =
  match (String.compare a b) with | 0 -> true | _ -> false

let fail fmt = Printf.ksprintf OUnit.assert_failure fmt

let test_read_char_eof () =
  let f = Fflow.make () in
  let c = Channel.create f in
  let try_char_read () =
    Channel.read_char c >>= fun ch ->
    fail "character %c was returned from Channel.read_char on an empty flow" ch
  in
  Lwt.try_bind
    (try_char_read)
    (fun () -> fail "no exception") (* "success" case (no exceptions) *)
    (function
      | End_of_file -> Lwt.return_unit
      | e -> fail "wrong exception: %s" (Printexc.to_string e))

let check a b =
  OUnit.assert_equal ~printer:(fun a -> a) ~cmp a (Cstruct.to_string b)

let test_read_until_eof () =
  let input =
    Fflow.input_string "I am the very model of a modern major general"
  in
  let f = Fflow.make ~input () in
  let c = Channel.create f in
  Channel.read_until c 'v' >>= function
  | true, buf ->
    check "I am the " buf;
    Channel.read_until c '\xff' >>= fun (found, buf) ->
    OUnit.assert_equal ~msg:"claimed we found a char that couldn't have been
      there in read_until" false found;
    check "ery model of a modern major general" buf;
    Channel.read_until c '\n' >>= fun (found, buf) ->
    OUnit.assert_equal ~msg:"claimed we found a char after EOF in read_until"
      false found;
    OUnit.assert_equal ~printer:string_of_int 0 (Cstruct.len buf);
    Lwt.return_unit
  | false, _ ->
    OUnit.assert_failure "thought we couldn't find a 'v' in input test"

let test_read_line () =
  let input = "I am the very model of a modern major general" in
  let f = Fflow.make ~input:(Fflow.input_string input) () in
  let c = Channel.create f in
  Channel.read_line c  >>= fun buf ->
  check input (Cstruct.of_string (Cstruct.copyv buf));
  Lwt.return_unit

let suite = [
  "read_char + EOF" , test_read_char_eof;
  "read_until + EOF", test_read_until_eof;
  "read_line"       , test_read_line;
]
