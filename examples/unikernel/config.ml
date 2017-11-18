open Mirage

let main = foreign "Services.Main" (stackv4 @-> job)

let stack = generic_stackv4 default_network

let () =
  register "services" [
    main $ stack
  ]
