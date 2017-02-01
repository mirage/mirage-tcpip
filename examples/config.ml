open Mirage

let main = foreign "Services.Main" (console @-> stackv4 @-> job)

let stack = generic_stackv4 default_network

let () =
  register "services" [
    main $ default_console $ stack
  ]
