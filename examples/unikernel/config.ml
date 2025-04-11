(* mirage >= 4.6.0 & < 4.10.0 *)

open Mirage

let main =
  let packages = [ package ~min:"2.9.0" "ipaddr" ] in
  main ~packages "Services.Main" (stackv4v6 @-> job)

let stack = generic_stackv4v6 default_network

let () = register "services" [ main $ stack ]
