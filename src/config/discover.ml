module C = Configurator.V1

let () =
  (* Extend the pkg-config path rather than overwriting it.
     See #25 *)
  let prepend = try Unix.getenv "OPAM_PKG_CONFIG_PATH" ^ ":" with _ -> "" in
  let onto = try Unix.getenv "PKG_CONFIG_PATH" with _ -> "" in
  let combined = prepend ^ onto in
  if not(String.equal combined "") then Unix.putenv "PKG_CONFIG_PATH" combined;

  C.main ~name:"mirage-xen-ocaml" (fun c ->
    let default : C.Pkg_config.package_conf =
      { libs   = []
      ; cflags = []
      }
    in
    let conf =
      match C.Pkg_config.get c with
      | None -> default
      | Some pc ->
        (match C.Pkg_config.query pc ~package:"mirage-xen-ocaml" with
         | None -> default
         | Some c -> c)
    in
    C.Flags.write_sexp "c_flags_xen.sexp" conf.cflags)
