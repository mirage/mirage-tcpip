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
* Do not raise `Invalid_argument("Lwt.wakeup_result")` everytime a connection
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
`STACKV4` interfaces to faciliate a progressive merge.  The only visible
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
* Raise exception `Bad_option` for unparseable or invalid TCPv4 options (#57).
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
