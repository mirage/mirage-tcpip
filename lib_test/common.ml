open Lwt

let cmp a b = String.compare a b = 0

let fail fmt = Printf.ksprintf OUnit.assert_failure fmt

let expect msg expected actual =
  (if not (cmp expected actual) then
     fail "Expected '%s', got '%s': %s" expected actual msg) ;
  Lwt.return_unit

let or_error name fn t =
  fn t >>= function
  | `Error e -> fail "or_error starting %s" name
  | `Ok t -> return t

