open Mirage

let main =
  let packages = [ package ~min:"2.9.0" "ipaddr" ] in
  foreign ~packages "Services.Main" (stackv4 @-> job)

let stack = generic_stackv4 default_network

let () =
  register "services" [
    main $ stack
  ]
