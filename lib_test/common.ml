let (>>=) = Lwt.(>>=)

let fail fmt = Printf.ksprintf OUnit.assert_failure fmt

let or_error name fn t =
  fn t >>= function
  | `Error e -> fail "or_error starting %s" name
  | `Ok t    -> Lwt.return t

let expect_error error name fn t =
  fn t >>= function
  | `Error error2 when error2 = error ->
          Lwt.return t
  | _    -> fail "expected error on %s" name

let assert_string msg a b =
  let cmp a b = String.compare a b = 0 in
  OUnit.assert_equal ~msg ~printer:(fun x -> x) ~cmp a b

let assert_cstruct msg a b =
  OUnit.assert_equal ~msg ~printer:Cstruct.to_string ~cmp:Cstruct.equal a b

let assert_bool msg a b =
  OUnit.assert_equal ~msg ~printer:string_of_bool a b

let assert_int msg a b =
  OUnit.assert_equal ~msg ~printer:string_of_int a b
