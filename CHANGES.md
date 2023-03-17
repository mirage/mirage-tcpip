### v8.0.0 (2023-03-17)

* TCP: add ID for PCB for connection tracking (#495 @TheLortex)
* Unix stack, UDP: copy buffer before passing it to client (#502 @reynir)

* API renamings (due to ppx_cstruct removal): accessors such as
  Icmpv4_wire.get_icmpv4_ty are now Icmpv4_wire.get_ty ("_icmpv4" is removed)
  (#505)

* Use Cstruct.to_string instead of deprecated Cstruct.copy (#506 @hannesm)
* Remove ppx_cstruct dependency (#505 @hannesm)
* Remove mirage-profile dependency (#504 @hannesm)
* Remove Mirage3 cross-compilation runes (#507 @hannesm)
* opam: add lower bounds for cmdliner and alcotest (#506 @hannesm)

### v7.1.2 (2022-07-27)

* TCP: fix memory leaks on connection close in three scenarios (#489 @TheLortex)
  - simultanous close: set up the timewait timer in the `Closing(1) - Recv_ack(2) -> Time_wait` 
    state transition
  - client sends a RST instead of a FIN: enable sending a challenge ACK even when the reception
    thread is stopped
  - client doesn't ACK server's FIN: enable the retransmit timer in the `Closing(_)` state

### v7.1.1 (2022-05-24)

* Ndpv6: demote more logs to debug level (#480 @reynir)
* Ndpv6: set RS opt header (#482 @reynir)
* Icmpv6: add redirect parsing (#481 @reynir)
* Improve log messages of connect and disconnect of various layers and stacks:
  separate IP addresses with ", " (#485 @hannesm)
* TCP log sources: prefix "tcp" to distinguish them (#484 @reynir)

### v7.1.0 (2022-03-23)

* Work with MSVC compiler (@jonahbeckford, #476)
* Skip `Lwt_bytes` UDP tests on Windows (@MisterDA, #469)
* Run `PKG_CONFIG_PATH` through cypath (@MisterDA, #469)
* Add Windows CI via GitHub Action (@MisterDA, #469)
* Remove `which` command and replace it by `command -v` (@hannesm, #472)
* Fix some typos (@MisterDA, #471)
* Update binaries to `cmdliner.1.1.0` (@dinosaure, #475)
* Be able to extract via _functor_/`functoria` the TCP/IP stack (@dinosaure, #474)
* Remove missing deprecated usage of `Cstruct.len` (@dinosaure, #477)

### v7.0.1 (2021-12-17)

* Fix cancellation of Unix socket when we don't use `Stack.connect` (@dinosaure, @hannesm, #466)

### v7.0.0 (2021-12-10)

* Fix memory leak in processing RST packets (#460 @balrajsingh, reported in
  #456 by @dinosaure)
* Move module types (IP, UDP, TCP, STACK, ICMP) into tcpip core library
  (#463 @hannesm)
* API breakage: `Tcpip_checksum` is now part of tcpip.checksum (used to be
  part of tcpip #463 @hannesm)
* API breakage: tcpip.unix has been removed (#463 @hannesm)
* Use Lwt.pause instead of deprecated `Lwt_{unix,main}.yield` (#461 @dinosaure)

### v6.4.0 (2021-11-11)

* Adapt to mirage-protocols 6.0.0 API (#457 @hannesm)
* TCP and UDP now have a listen and unlisten function (fixes #452)
* type ipinput (in TCP and UDP) and listener (in TCP) have been removed

### v6.3.0 (2021-10-25)

* Use Cstruct.length instead of deprecated Cstruct.len (#454 @hannesm)
* Avoid deprecated Fmt functions (#455 @hannesm)
* Remove rresult dependency (#455 @hannesm)
* Require OCaml 4.08
* Record TCP statistics via metrics library (#455 @hannesm)

### v6.2.0 (2021-07-19)

* This allows to listen on the same port as sending via UDP in the dual socket
  stack, and avoids file descriptor leaks in the socket stack.
* Socket stack: avoid file descriptor leaks (remember opened file descriptors in
  data structure, close them in disconnect)
  (#449 @reynir @hannesm, fixes #446 #450)
* Socket stack: convert an incoming packet on a dual socket to v4 source IP if
  received via IPv4 (#451 @reynir @hannesm)
* Allow freestanding compilation without opam (#447 @sternenseemann)
* Adapt to alcotest 1.4.0 breaking change (#448 @CraigFE)

### v6.1.0 (2021-03-17)

* checksum stubs: Drop `caml_` from their name (@hannesm, #445)
* Add cancellation on `tcpip.stack-socket` (@dinosaure, @talex5, @hannesm, #443)
* Ensure that listen really binds the given socket before
  creating a task on `tcpip.stack-socket` (@dinosaure, @hannesm, #439)
* Add `ppx_cstruct` as a dependency (@hannesm, @dinosaure, #439)
* Upgrade to ocamlformat.0.17.0 (@dinosaure, #442)
* Drop the support of OCaml 4.08.0 (@dinosaure, #442)
* Use the usual layout to compile freestanding C stubs and link them to
  a Solo5 unikernel (@dinosaure, @hannesm, #441)
  **breaking changes**
  C stubs are prepended by `mirage_`. Symbols such as checksum's
  symbols are `caml_mirage_tcpip_*` instead of `caml_tcpip_*`
  `tcpip.unix` is a fake sub-package and user does not it anymore, he can
  safely remove it from its project.
* Conflict with `< ocaml-freestanding.0.4.1` (@hannesm, #441)

### v6.0.0 (2020-11-30)

* Dual IPv4 and IPv6 socket and direct stack support, now requires
  mirage-stack 2.2.0 and mirage-protocols 5.0.0 (#433 @hannesm)
* The above change also unified arguments passed to connect functions which
  are API-breaking changes
* IPv6 waits for timeout after sending neighbour advertisement (for duplicate
  address detection)
* Remove Xen cross-compilation runes, with mirage-xen 6.0.0 they're provided
  by mirage-xen (#434 @hannesm)
* Move to dune 2.7.0 (and bisect instrumentation if desired) (#436 @hannesm)

### v5.0.1 (2020-09-22)

* Assorted IPv6 improvements (#428 #431 #432 @MagnusS @hannesm)
  - set length in packets to be sent
  - preserve updated ctx from Ndv6.handle
  - fix ICMP checksum computation
  - implement Mirage_stack.V6 signature
  - add connect, mtu, iperf tests
  - fix DAD protocol implementation (and test it)
  - avoid out of bounds accesses of IPv6 packets (check length before accessing)
* Fix 32 bit issues (@MagnusS)
* Implement stack-direct and tcp disconnect: tear down existing connections (#429 @hannesm)
* Treat broadcast address of network as broadcast as well (#430 @hannesm, reported in #427)

### v5.0.0 (2020-06-19)

* Static_ipv4.connect API change: takes a cidr:Ipaddr.V4.Prefix.t instead of
  ip:Ipaddr.V4.t and network:Ipaddr.V4.Prefix.t (#426 @hannesm)
* Adapt to ipaddr 5.0.0 API changes (#426 @hannesm)

### v4.1.0 (2020-02-08)

* Revert "Ipv4.Fragments use a Lru.M.t instead of Lru.F.t" (#423 by @hannesm)
  A Lru.M.t allocates a Hashtbl.t of size = capacity (= 256 * 1024 in our case),
  this leads to excessive ~2MB memory consumption for each Fragment cache,
  reported by @xaki23 in mirage/qubes-mirage-firewall#93
* use SOCK_RAW for an ICMP socket in the unix sockets API (previously used
  SOCK_DGRAM which did not work)
  reported by @justinc1 in #358, fixed in #424 by @hannesm
* tcp is now compatible with lwt >= 5.0.0 (where Lwt.async requires a function
  of (unit -> unit Lwt.t) (#370 #425 @cfcs @hannesm, issue #392 @emillon)
* Add a dependency on dune-configurator to support dune 2.0.0 (#421 @avsm)

### v4.0.0 (2019-11-01)

* Adapt to mirage-protocols 4.0.0, mirage-net 3.0.0, mirage-time 2.0.0,
  mirage-clock 3.0.0, mirage-stack 2.0.0 interface changes (#420 @hannesm)
* Revise Static_ipv4.connect signature (for more safety):
  val connect : ip:(Ipaddr.V4.Prefix.t * Ipaddr.V4.t) -> ?gateway:Ipaddr.V4.t ->
                ?fragment_cache_size:int -> E.t -> A.t -> t Lwt.t
  it used to be:
  val connect : ?ip:Ipaddr.V4.t -> ?network:Ipaddr.V4.Prefix.t ->
                ?gateway:Ipaddr.V4.t option -> C.t -> E.t -> A.t -> t Lwt.t
  The clock `C.t` is gone (due to mirage-clock 3.0.0), `~ip` and `~network` are
  now required and passed as pair `~ip`. The optional argument `?gateway` is
  of type Ipaddr.V4.t. The new optional labeled argument `~fragment_cache_size`
  specifies the byte size of the IPv4 fragment cache (#420 @hannesm)

### v3.7.9 (2019-10-15)

* Add ?ttl:int parameter to Udp and Icmp write (#416 @phaer)
* Ipv4.Fragments use a Lru.M.t instead of Lru.F.t (#418 @hannesm)
* Adapt to mirage-protocols 3.1.0 changes (#419 @hannesm)
  - removed IP.set_ip
  - added `Would_fragment to Ip.error

### v3.7.8 (2019-08-12)

* provide Fragments.fragment for the write side of fragmentation, use in Static_ipv4 (#415, @hannesm)

### v3.7.7 (2019-07-16)

* support ipaddr/macaddr.4.0.0 interfaces (@avsm)
* remove extraneous debug messages from Ipv4.Fragments (@hannesm, #410)

### v3.7.6 (2019-07-08)

* opam: ensure Xen bindings are built with right mirage-xen-ocaml CFLAGS (@avsm)
* opam: correctly register mirage-xen-ocaml as a depopt (@avsm)
* use mirage-protocols-3.0 interface for ipaddr printing (#408 @yomimono @linse)
* remove dependency on configurator and use dune's builtin one instead (@avsm)

### v3.7.5 (2019-05-03)

* drop IPv4 packets which destination address is not us or broadcast (#407 by @hannesm)

### v3.7.4 (2019-04-11)

* ipv4 reassembly requires lru 0.3.0 now (#406 by @hannesm)
* ICMP test maintenance (#405 by @yomimono @linse)
* remove usage of Cstruct.set_len (use Cstruct.sub with offset 0 instead) (#403 by @hannesm)

### v3.7.3 (2019-04-06)

* fix ICMPv4 checksum calculation (#401 by @yomimono)

### v3.7.2 (2019-03-29)

* add Ipv4_packet.Unmarshal.header_of_cstruct (#397 by @linse)
* require cstruct version 3.2.0 (#398 by @hannesm)

### v3.7.1 (2019-02-25)

* Adjust to mirage-protocols 2.0.0 changes (#394 by @hannesm)
* Ethif is now Ethernet (#394 by @hannesm)
* IPv4 write now fragments if payload exceeds MTU (and the optional labeled
  fragment argument is not false) (#394 by @hannesm)

### v3.7.0 (2019-02-02)

* Use `Lwt_dllist` instead of `Lwt_sequence`, due to the latter being deprecated
  upstream in Lwt (ocsigen/lwt#361) (#388 by @avsm).
* Remove arpv4 and ethif sublibraries, now provided by ethernet and arp-mirage
  opam packages (#380 by @hannesm).
* Upgrade from jbuilder to dune (#391 @avsm)
* Switch from topkg to dune-release (#391 @avsm)

### v3.6.0 (2019-01-04)

* The IPv4 implementation now supports reassembly of IPv4 fragments (#375 by @hannesm)
  - using a LRU cache using up to 256KB memory
  - out of order fragments are supported
  - maximum number of fragments is 16
  - timeout between first and last fragment is 10s
  - overlapping fragments are dropped

* IPv6: use correct timeout value after first NS message (#334 @djs55)

* Use `Ipaddr.pp` instead of `Ipaddr.pp_hum` due to upstream
  interface changes (#385 @hannesm).

### v3.5.1 (2018-11-16)

* socket stack (tcp/udp): catch exception in recv_from and accept (#376 @hannesm)
* use mirage-random-test for testing (Stdlibrandom got removed from mirage-random>1.2.0, #377 @hannesm)

### v3.5.0 (2018-09-16)

* Ipv4: require Mirage_random.C, used for generating IPv4 identifier instead of using OCaml's stdlib Random directly (#371 @hannesm)
* Tcp: use entire 32 bits at random for the initial sequence number, thanks to Spencer Michaels and Jeff Dileo of NCC Group for reporting (#371 @hannesm)
* adjust to mirage-protocols 1.4.0 and mirage-stack 1.3.0 changes (#371 @hannesm)
  Arp no longer contains the type alias ethif
  Ethif no longer contains the type alias netif
  Static_ipv4 no longer contains the type alias ethif and prefix
  Ipv6 no longer contains the type alias ethif and prefix
  Mirage_protocols_lwt.IPV4 no longer contains the type alias ethif
  Mirage_protocols_lwt.UDPV4 and TCPV4 no longer contain the type alias ip
* remove unused types: 'a config, netif, and id from socket and direct stack (#371 @hannesm)
* remove usage of Result, depending on OCaml >= 4.03.0 (#372 @hannesm)

### v3.4.2 (2018-06-15)

Note the use of the new TCP keep-alive feature can cause excessive amounts
of memory to be used in some circumstances, see
  https://github.com/mirage/mirage-tcpip/issues/367

* Ensure a zero UDP checksum is sent as 0xffff, not 0x0000 (#359 @stedolan)
* Avoid leaking a file descriptor in the socket stack if the connection fails (#363 @hannesm)
* Avoid raising an exception with `Lwt.fail` when `write` fails in the socket stack (#363 @hannesm)
* Ignore `EBADF` errors in `close` in the socket stack (#366 @hannesm)
* Emit a warning when TCP keep-alives are used (#368 @djs55)

### v3.4.1 (2018-03-09)

* expose tcp_socket_options in the socket stack, fixing downstream builds (#356 @yomimono)
* add missing dependencies and constraints (#354 @yomimono, #353 @rgrinberg)
* remove leftover ocamlbuild files (#353 @rgrinberg)

### v3.4.0 (2018-02-15)

* Add support for TCP keepalives (#338 @djs55)
* Fix TCP deadlock (#343 @mfp)
* Update the CI to test OCaml 4.04, 4.05, 4.06 (#344 @yomimono)

### v3.3.1 (2017-11-07)

* Add an example for user-space `ping`, and some socket ICMPv4 fixes (#336 @djs55)
* Make tcpip safe-string-safe (and buildable by default on OCaml 4.06.0) (#341 @djs55)

### v3.3.0 (2017-08-08)

* Test with current mirage-www master (#323 @yomimono)
* Improve the Tcp.Wire API (#325 @samoht)
* Add dependency from stack-unix to io-page-unix (@avsm)
* Replace dependency on cstruct.lwt with cstruct-lwt (#322 @yomimono)
* Update to lwt 3.0 (#326 @samoht)
* Replace oUnit with alcotest (#329 @samoht)
* Fix stub linking on Xen (#332 @djs55)
* Add support for ICMP sockets on Windows (#333 @djs55)

### v3.2.0 (2017-06-26)

* port to jbuilder. Build time is now roughly 4-5x faster than the old oasis-based build system.
* packs have been replaced by module aliases.

### v3.1.4 (2017-06-12)

* avoid linking to cstruct.ppx in the compiled library and only use it at build time (#316 @djs55)
* use improved packet size support in `mirage-vnetif>=0.4.0` to test the MTU fixes in #313.

### v3.1.3 (2017-05-23)

* involve the IP layer's MTU in the TCP MSS calculation (hopefully correctly) (#313, by @yomimono)

### v3.1.2 (2017-05-14)

* impose a maximum TCP MSS of 1460 to avoid sending over-large datagrams on 1500 MTU links
  (#309, by @hannesm)

### v3.1.1 (2017-05-14)

* fix parsing 20-byte cstructs as ipv4 packets (#307, by @yomimono)
* udp: payload length parse fix (#307, by @yomimono)
* support lwt >= 2.7.0 (#308, by @djs55)

### v3.1.0 (2017-03-14)

* implement MTU setting and querying in the Ethernet module (compatibility with mirage-protocols version 1.1.0), and use this value to inform TCP's MSS. (#288, by @djs55)
* rename the ~payload argument of TCP/UDP marshallers to `~payload_len`, in an attempt to clarify that the payload will not be copied to the Cstruct.t returned by these functions (#301, by @talex5)
* functorize ipv6 over a random implementation (#298, by @olleolleolle and @hannesm)
* add tests for sending and receiving UDP packets over IPv6 (#300, by @mattgray)
* avoid float in TCP RTO calculations. (#295, by @olleolleolle and @mattgray)
* numerous bugfixes in header marshallers and unmarshallers (#301, by @talex5 and @yomimono)
* replace polymorphic equality in `_packet.equals` functions (#302, by @yomimono)

### v3.0.0 (2017-02-23)

* adapt to MirageOS 3 API changes (*many* PRs, from @hannesm, @samoht, and @yomimono):
  - replace error polyvars in many functions with result types
  - define and use error types
  - `connect` in various modules now returns the device directly or raises an exception
  - refer to mirage-protocols and mirage-stacks, rather than mirage-types
* if no UDP source port is given to UDP.write, choose a random one (#272, by @hannesm)
* remove `Ipv4.Routing.No_route_to_destination_address` exception; treat routing failures as normal packet loss in TCP (#269, by @yomimono)
* Ipv6.connect takes a list of IPs (#268, by @yomimono)
* remove exception "Refused" in TCP (#267, by @yomimono)
* remove DHCP module. Users may be interested in the replacement charrua-core (#260, by @yomimono)
* move Ipv4 to Static\_ipv4, which can be used by other IPv4 modules with their own configuration logic (#260, by @yomimono)
* remove `mode` from STACKV4 record and configuration; Ipv4.connect now requires address parameters and the module exposes no methods for modifying them. (#260, by @yomimono)
* remove unused `id` types no longer required by mirage-types (#255, by @yomimono)
* overhaul how `random` is used and handled (#254 and others, by @hannesm)
* fix redundant `memset` that zeroed out options in Tcp\_packet.Marshal.into\_cstruct (#250, by @balrajsingh)
* add vnetif backend for triggering fast retransmit in iperf tests (#248, by @magnuss)
* fixes for incorrect timer values (#247, by @balrajsingh)
* add vnetif backend that drops packets with no payload (#246, by @magnuss)
* fix a race when closing test pcap files (#246, by @magnuss)

### v2.8.1 (2016-09-12)

* Set the TCP congestion window correctly when going into fast-recovery mode. (#244, by @balrajsingh)
* When TCP packet loss is discovered by timeout, allow transition into fast-recovery mode. (#244, by @balrajsingh) 

### v2.8.0 (2016-04-04)

* Provide an implementation for the ICMPV4 module type defined in mirage-types 2.8.0.  Remove default ICMP handling from the IPv4 module, but preserve it in tcpip-stack-direct. (#195 by @yomimono)
* Explicitly require the use of an OCaml compiler >= 4.02.3 . (#195 by @yomimono)
* Explicitly depend on `result`. (#195 by @yomimono)

### v2.7.0 (2016-03-20)

* Raise Invalid\_argument if given an invalid port number in listen_{tcp,udp}v4
  (#173 by @matildah and #175 by @hannesm)
* Improve TCP options marshalling/unmarshalling (#174 by @yomimono)
* Add state tests and fixes for closure conditions (#177 #176 by @yomimono)
* Remove bogus warning (#178 by @talex5)
* Clean up IPv6 stack (#179 by @nojb)
* RST checking from RFC5961 (#182 by @ppolv)
* Transform EPIPE exceptions into `Eof (#183 by @djs55)
* Improve error strings in IPv4 (#184 by @yomimono)
* Replace use of cstruct.syntax with cstruct.ppx (#188 by @djs55)
* Make the Unix subpackages optional, so the core builds on Win32
  (#191 by @djs55)

### v2.6.1 (2015-09-15)

* Add optional arguments for settings in ip v6 and v4 connects (#170, by @Drup)
* Expose `Ipv4.Routing.No_route_to_destination_address` (#166, by @yomimono)

### v2.6.0 (2015-07-29)

* ARP now handles ARP frames, not Ethernet frames with ARP payload
  (#164, by @hannesm)
* Check length of received ethernet frame to avoid cstruct exceptions
  (#117, by @hannesm)
* Pull arpv4 module out of ipv4. Also add unit-tests for the newly created
  ARP library  (#155, by @yomimono)

### v2.5.1 (2015-07-07)

* Fix regression introduced in 2.5.0 where packet loss could lead to the
  connection to become very slow (#157, MagnusS, @talex5, @yomimono and
  @balrajsingh)
* Improve the tests: more logging, more tracing and compile to native code when
  available, etc (@MagnusS and @talex5)
* Do not raise `Invalid_argument("Lwt.wakeup_result")` every time a connection
  is closed. Also now pass the raised exceptions to `Lwt.async_exception_hook`
  instead of ignoring them transparently, so the user can decide to shutdown
  its application if something wrong happens (#153, #156, @yomomino and @talex5)
* The `channel` library now lives in a separate repository and is released
  separately (#159, @samoht)

### v2.5.0 (2015-06-10)

* The test runs now produce `.pcap` files (#141, by @MagnusS)
* Strip trailing bytes from network packets (#145, by @talex5)
* Add tests for uniform packet loss (#147, by @MagnusS)
* fixed bug where in case of out of order packets the ack and window were set
  incorrectly (#140, #146)
* Properly handle RST packets (#107, #148)
* Add a `Log` module to control at runtime the debug statements which are
  displayed (#142)
* Writing in a PCB which does not have the right state now returns an error
  instead of blocking (#150)

### v2.4.3 (2015-05-05)

* Fix infinite loop in `Channel.read_line` when the line does not contain a CRLF
  sequence (#131)

### v2.4.2 (2015-04-29)

* Fix a memory leak in `Channel` (#119, by @yomimono)
* Add basic unit-test for channels (#119, by @yomimono)
* Add alcotest testing templates
* Modernize Travis CI scripts

### v2.4.1 (2015-04-21)

* Merge between 2.4.0 and 2.3.1

### v2.4.0 (2015-03-24)

* ARP improvements (#118)

### v2.3.1 (2015-03-31)

* Do not raise an assertion if an IP frame has extra trailing bytes (#221).

### v2.3.0 (2015-03-09)

* Fix `STACKV4` for the `DEVICE` signature which has `connect` removed
  (in Mirage types 2.3+).

### v2.2.3 (2015-03-09)

* Add ICMPv6 error reporting functions (#101)
* Add universal IP address converters (#108)
* Add `error_message` functions for human-readable errors (#98)
* Improve debug logging for ICMP Destination Unreachable packets.
* Filter incoming frames by MAC address to stop sending unnecessary RSTs. (#114)
* Unhook unused modules `Sliding_window` and `Profiler` from the build. (#112)
* Add an explicit `connect` method to the signatures. (#100)

### v2.2.2 (2015-01-11)

* Readded tracing and ARP fixes which got accidentally reverted in the IPv6
  merge. (#96)

### v2.2.1 (2014-12-20)

* Use `Bytes` instead of `String` to begin the `-safe-string` migration in OCaml
  4.02.0 (#93).
* Remove dependency on `uint` to avoid the need for a C stub (#92).

### v2.2.0 (2014-12-18)

Add IPv6 support. This changeset minimises interface changes to the existing
`STACKV4` interfaces to facilitate a progressive merge.  The only visible
interface changes are:

* `IPV4.set_ipv4_*` functions have been renamed `IPV4.set_ip_*` because they
  are shared between IPV4 and IPV6.
* `IPV4.get_ipv4` and `get_ipv4_netmask` now return a `list` of `Ipaddr.V4.t`
  (again because this is the common semantics with IPV6.)
* Several types that had `v4` in their names (like `IPV4.ipv4addr`) have lost
  that particle.

### v2.1.1 (2014-12-12)

* Improve console printing for the DHCP client to output line
  breaks properly on Xen consoles.

### v2.1.0 (2014-12-07)

* Build Xen stubs separately, with `CFLAGS` from `mirage-xen` 2.1.0+.
  This allows us to use the red zone under x86_64 Unix again.
* Adding tracing labels and counters, which introduces a new dependency on the
  `mirage-profile` package.

### v2.0.3 (2014-12-05)

* Fixed race waiting for ARP response (#86).
* Move the the code that configures IPv4 address, netmask and gateways
  after receiving a successful lease out of the `Dhcp_clientv4` module
  and into `Stackv4` (#87)

### v2.0.2 (2014-12-01)

* Add IPv4 multicast to MAC address mapping in IPv4 output processing
  (#81 from Luke Dunstan).
* Improve formatting of DHCP console logging, including printing out options
  (#83).
* Build with -mno-red-zone on x86_64 to avoid stack corruption on Xen (#80).

### v2.0.1 (2014-11-04)

* Fixed race condition in the signalling between the rx/tx threads under load.
* Experimentally switch to immediate ACKs in TCPv4 by default instead of delayed ones.

### v2.0.0 (2014-11-02)

* Moved 1s complement checksum C code here from mirage-platform.
* Depend on `Console_unix` and `Console_xen` instead of `Console`.
* [socket] Do not return an `Eof` when writing 0-length buffer (#76).
* [socket] Accept callbacks now run in async threads instead of being serialised
  (#75).

### v1.1.6 (2014-07-20)

* Quieten down the stack logging rate by not announcing IPv6 packet discards.
* Raise exception `Bad_option` for unparsable or invalid TCPv4 options (#57).
* Fix linking error with module `Tcp_checksum` by lifting it into top library
  (#60).
* Add `opam` file to permit easier local pinning, and fix Travis to use this.

### v1.1.5 (2014-06-18)

* Ensure that DHCP completes before the application is started, so that
  unikernels that establish outgoing connections can do so without a race.
  (fix from Mindy Preston in #53, followup in #55)
* Add `echo`, `chargen` and `discard` services into the `examples/`
  directory. (from Mindy Preston in #52).

### v1.1.4 (2014-06-03)

* [tcp] Fully process the last `ACK` in a 3-way handshake for server connections.
  This ensures that a `FIN` is correctly transmitted upon application-initiated
  connection close. (fix from Mindy Preston in #51).

### v1.1.3 (2014-03-01)

* Expose IPV4 through the STACKV4 interface.

### v1.1.2 (2014-03-27)

* Fix DHCP variable length option parsing for MTU responses, which
  in turns improves robustness on Amazon EC2 (fix from @yomimono
  via mirage/mirage-tcpip#48)

### v1.1.1 (2014-02-21)

* Catch and ignore top-level socket exceptions (#219).
* Set `SO_REUSEADDR` on listening sockets for Unix (#218).
* Adapt the Stack interfaces to the v1.1.1 mirage-types interface
  (see mirage/mirage#226 for details).

### v1.1.0 (2014-02-03)

* Rewrite of the library as a set of functors that parameterize the
  stack across the `V1_LWT` module types from Mirage 1.1.x.  This removes
  the need to compile separate Xen and Unix versions of the stack.

### v0.9.5 (2013-12-08)

* Build for either Xen or Unix, depending on the value of the `OS` envvar.
* Shift to the `mirage-types` 0.5.0+ interfaces, which breaks the
  socket backend (temporarily).
* Port the direct stack to the new interfaces.
* Add Travis CI scripts.

### v0.9.4 (2013-08-09)

* Use the `Ipaddr` external library and remove the Homebrew
  equivalents in `Nettypes`.

### v0.9.3 (2013-07-18)

* Changes in module Manager: Removed some functions from the `.mli
  (plug/unplug) and added some modifications in the way the Manager
  interacts with the underlying module Netif. The Netif.create function
  does not take a callback anymore.

### v0.9.2 (2013-07-09)

* Improve TCP state machine for connection teardown.
* Limit fragment number to 8, and coalesce buffers if it goes higher.
* Adapt to mirage-platform-0.9.2 API changes.

### v0.9.1 (2013-06-12)

* Depend on mirage-platform-0.9.1 direct tuntap interfaces.
* Version bump to catch up with mirage-platform.

### v0.5.2 (2013-02-08)

* Encourage scatter-gather I/O all the time, rather than playing tricks
  with packet header buffers. This simplifies the output path considerably
  and cuts minor heap allocations down.
* Install the packed `cmx` along with the `cmxa` to ensure that the
  compiler can do cross-module optimization (this is not a fatal error,
  but will impact performance if the `cmx` file is not present).

### v0.5.1 (2012-12-20)

* Update socket stack to use Cstruct 0.6.0 API

### v0.5.0 (2012-12-20)

* Update Cstruct API to 0.6.0
* [tcp] write now blocks if the write buffer and write window are full

### v0.4.1 (2012-12-14)

* Add iperf self-test that creates two VIFs and transmits across
  them. This is a useful local test which stresses the bridge
  code using just one VM.
* Add support for attaching existing devices when initialising the
  network manager, via an optional `attached` parameter.
* Constrain TCP connect to be a `unit Lwt.t` instead of a polymorphic
  return value.
* Expose IPv4 netmask function.
* Reduce ARP verbosity to the console.
* Fix TCP fast recovery to wait until all in-flight packets are
  acked, rather then exiting early.

### v0.4.0 (2012-12-11)

* Require OCaml-4.00.0 or higher, and add relevant build fixes
  to deal with module packing.

### v0.3.1 (2012-12-10)

* Fix the DHCP client marshalling for IPv4 addresses.
* Expose the interface MAC address in the Manager signature.
* Tweak TCP ISN calculation to be more friendly on a 32-bit host.
* Add Manager.create ?devs to control the number of Netif devices
  constructed by default.
* Add Ethif.set/disable_promiscuous to permit directly tapping
  a network interface.

### v0.3.0 (2012-09-04)

* Initial public release.
