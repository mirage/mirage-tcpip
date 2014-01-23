module X = struct
  type 'a io = 'a Lwt.t
  include OS.Time
end

include Tcpv4.Flow.Make(Ipv4_unix)(X)(Clock)(Random)
