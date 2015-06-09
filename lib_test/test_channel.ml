open Common

let (>>=) = Lwt.(>>=)

(* this is a very small set of tests for the channel interface,
   intended to ensure that EOF conditions on the underlying flow are
   handled properly *)
module Channel = Channel.Make(Fflow)

let err_read ch =
  fail "character %c was returned from Channel.read_char on an empty flow" ch

let err_no_exception () = fail "no exception"
let err_wrong_exception e = fail "wrong exception: %s" (Printexc.to_string e)

let test_read_char_eof () =
  let f = Fflow.make () in
  let c = Channel.create f in
  let try_char_read () = Channel.read_char c >>= err_read in
  Lwt.try_bind
    (try_char_read)
    err_no_exception (* "success" case (no exceptions) *)
    (function
      | End_of_file -> Lwt.return_unit
      | e -> err_wrong_exception e)

let test_read_until_eof () =
  let input =
    Fflow.input_string "I am the very model of a modern major general"
  in
  let f = Fflow.make ~input () in
  let c = Channel.create f in
  Channel.read_until c 'v' >>= function
  | true, buf ->
    assert_cstruct "wrong flow prefix"
      (Cstruct.of_string "I am the ") buf;
    Channel.read_until c '\xff' >>= fun (found, buf) ->
    assert_bool "found a char that couldn't have been there in read_until"
      false found;
    assert_cstruct "wrong flow suffix"
      (Cstruct.of_string "ery model of a modern major general") buf;
    Channel.read_until c '\n' >>= fun (found, buf) ->
    assert_bool "found a char after EOF in read_until"
      false found;
    assert_int "wrong flow size" 0 (Cstruct.len buf);
    Lwt.return_unit
  | false, _ ->
    OUnit.assert_failure "thought we couldn't find a 'v' in input test"

let test_read_line () =
  let input = "I am the very model of a modern major general" in
  let f = Fflow.make ~input:(Fflow.input_string input) () in
  let c = Channel.create f in
  Channel.read_line c  >>= fun buf ->
  assert_string "read line" input (Cstruct.copyv buf);
  Lwt.return_unit

let suite = [
  "read_char + EOF" , `Quick, test_read_char_eof;
  "read_until + EOF", `Quick, test_read_until_eof;
  "read_line"       , `Quick, test_read_line;
]
