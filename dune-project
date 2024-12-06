(lang dune 2.7)

(name tcpip)

(formatting disabled)
(generate_opam_files true)

(license ISC)
(authors
 "Anil Madhavapeddy"
 "Balraj Singh"
 "David Scott"
 "Gabor Pali"
 "Hannes Mehnert"
 "Haris Rotsos"
 "Kia"
 "Luke Dunstan"
 "Magnus Skjegstad"
 "Mindy Preston"
 "Nicolas Ojeda Bar"
 "Pablo Polvorin"
 "Richard Mortier"
 "Thomas Gazagnaire"
 "Thomas Leonard"
 "Tim Cuthbertson"
 "Vincent Bernardoff"
 "lnmx"
 "pqwy")
(maintainers "anil@recoil.org")
(source (github mirage/mirage-tcpip))

(package
 (name tcpip)
 (synopsis "OCaml TCP/IP networking stack, used in MirageOS")
 (description "`mirage-tcpip` provides a networking stack for the [Mirage operating system](https://mirage.io). It provides implementations for the following module types (which correspond with the similarly-named protocols): IP (via the IPv4 and IPv6 modules), ICMP, UDP, TCP")
 (tags ("org:mirage"))
 (depends
  (ocaml (>= 4.08.0))
  (arp (>= 3.0.0))
  (cmdliner (>= 1.1.0))
  (cstruct (>= 6.0.0))
  cstruct-lwt
  duration
  (ethernet (>= 3.0.0))
  (fmt (>= 0.8.7))
  (ipaddr (>= 5.6.0))
  ipaddr-cstruct
  (logs (>= 0.6.0))
  (lru (>= 0.3.0))
  (lwt (>= 4.0.0))
  lwt-dllist
  (macaddr (>= 4.0.0))
  macaddr-cstruct
  metrics
  (mirage-clock (>= 3.0.0))
  (mirage-crypto-rng-mirage (>= 1.0.0))
  (mirage-flow (>= 4.0.0))
  (mirage-net (>= 3.0.0))
  (mirage-time (>= 2.0.0))
  (randomconv (>= 0.2.0))
  (bisect_ppx (and :dev (> 2.5.0)))
  (alcotest (and :with-test (>= 1.5.0)))
  (mirage-clock-unix (and :with-test (>= 3.0.0)))
  (mirage-crypto-rng (and :with-test (>= 1.0.0)))
  (mirage-vnetif (and :with-test (>= 0.6.2)))
  (pcap-format :with-test))
 (conflicts
  ocaml-freestanding
  (mirage-xen (< 6.0.0))
  (result (< 1.5))))
