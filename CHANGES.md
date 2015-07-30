### 2.6.0 (2015-07-29)

* ARP now handles ARP frames, not Ethernet frames with ARP payload
  (#164, by @hannesm)
* Check length of received ethernet frame to avoid cstruct exceptions
  (#117, by @hannesm)
* Pull arpv4 module out of ipv4. Also add unit-tests for the newly created
  ARP library  (#155, by @yomimono)

### 2.5.1 (2015-07-07)

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

### 2.5.0 (2015-06-10)

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

### 2.4.3 (2015-05-05)

* Fix infinite loop in `Channel.read_line` when the line does not contain a CRLF
  sequence (#131)

### 2.4.2 (2015-04-29)

* Fix a memory leak in `Channel` (#119, by @yomimono)
* Add basic unit-test for channels (#119, by @yomimono)
* Add alcotest testing templates
* Modernize Travis CI scripts

### 2.4.1 (2015-04-21)

* Merge between 2.4.0 and 2.3.1

### 2.4.0: (2015-03-24)

* ARP improvements (#118)

### 2.3.1 (2015-03-31)

* Do not raise an assertion if an IP frame has extra trailing bytes (#221).

### 2.3.0 (2015-03-09)

* Fix `STACKV4` for the `DEVICE` signature which has `connect` removed
  (in Mirage types 2.3+).

### 2.2.3 (2015-03-09)

* Add ICMPv6 error reporting functions (#101)
* Add universal IP address converters (#108)
* Add `error_message` functions for human-readable errors (#98)
* Improve debug logging for ICMP Destination Unreachable packets.
* Filter incoming frames by MAC address to stop sending unnecessary RSTs. (#114)
* Unhook unused modules `Sliding_window` and `Profiler` from the build. (#112)
* Add an explicit `connect` method to the signatures. (#100)

### 2.2.2 (2015-01-11)

* Readded tracing and ARP fixes which got accidentally reverted in the IPv6
  merge. (#96)

### 2.2.1 (2014-12-20)

* Use `Bytes` instead of `String` to begin the `-safe-string` migration in OCaml
  4.02.0 (#93).
* Remove dependency on `uint` to avoid the need for a C stub (#92).

### 2.2.0 (2014-12-18)

Add IPv6 support. This changeset minimises interface changes to the existing
`STACKV4` interfaces to faciliate a progressive merge.  The only visible
interface changes are:

* `IPV4.set_ipv4_*` functions have been renamed `IPV4.set_ip_*` because they
  are shared between IPV4 and IPV6.
* `IPV4.get_ipv4` and `get_ipv4_netmask` now return a `list` of `Ipaddr.V4.t`
  (again because this is the common semantics with IPV6.)
* Several types that had `v4` in their names (like `IPV4.ipv4addr`) have lost
  that particle.

### 2.1.1 (2014-12-12)

* Improve console printing for the DHCP client to output line
  breaks properly on Xen consoles.

### 2.1.0 (2014-12-07)

* Build Xen stubs separately, with `CFLAGS` from `mirage-xen` 2.1.0+.
  This allows us to use the red zone under x86_64 Unix again.
* Adding tracing labels and counters, which introduces a new dependency on the
  `mirage-profile` package.

### 2.0.3 (2014-12-05)

* Fixed race waiting for ARP response (#86).
* Move the the code that configures IPv4 address, netmask and gateways
  after receiving a successful lease out of the `Dhcp_clientv4` module
  and into `Stackv4` (#87)

### 2.0.2 (2014-12-01)

* Add IPv4 multicast to MAC address mapping in IPv4 output processing
  (#81 from Luke Dunstan).
* Improve formatting of DHCP console logging, including printing out options
  (#83).
* Build with -mno-red-zone on x86_64 to avoid stack corruption on Xen (#80).

### 2.0.1 (2014-11-04)

* Fixed race condition in the signalling between the rx/tx threads under load.
* Experimentally switch to immediate ACKs in TCPv4 by default instead of delayed ones.

### 2.0.0 (2014-11-02)

* Moved 1s complement checksum C code here from mirage-platform.
* Depend on `Console_unix` and `Console_xen` instead of `Console`.
* [socket] Do not return an `Eof` when writing 0-length buffer (#76).
* [socket] Accept callbacks now run in async threads instead of being serialised
  (#75).

### 1.1.6 (2014-07-20)

* Quieten down the stack logging rate by not announcing IPv6 packet discards.
* Raise exception `Bad_option` for unparseable or invalid TCPv4 options (#57).
* Fix linking error with module `Tcp_checksum` by lifting it into top library
  (#60).
* Add `opam` file to permit easier local pinning, and fix Travis to use this.

### 1.1.5 (2014-06-18)

* Ensure that DHCP completes before the application is started, so that
  unikernels that establish outgoing connections can do so without a race.
  (fix from Mindy Preston in #53, followup in #55)
* Add `echo`, `chargen` and `discard` services into the `examples/`
  directory. (from Mindy Preston in #52).

### 1.1.4 (2014-06-03)

* [tcp] Fully process the last `ACK` in a 3-way handshake for server connections.
  This ensures that a `FIN` is correctly transmitted upon application-initiated
  connection close. (fix from Mindy Preston in #51).

### 1.1.3 (2014-03-01)

* Expose IPV4 through the STACKV4 interface.

### 1.1.2 (2014-03-27)

* Fix DHCP variable length option parsing for MTU responses, which
  in turns improves robustness on Amazon EC2 (fix from @yomimono
  via mirage/mirage-tcpip#48)

### 1.1.1 (2014-02-21)

* Catch and ignore top-level socket exceptions (#219).
* Set `SO_REUSEADDR` on listening sockets for Unix (#218).
* Adapt the Stack interfaces to the v1.1.1 mirage-types interface
  (see mirage/mirage#226 for details).

### 1.1.0 (2014-02-03)

* Rewrite of the library as a set of functors that parameterize the
  stack across the `V1_LWT` module types from Mirage 1.1.x.  This removes
  the need to compile separate Xen and Unix versions of the stack.

### 0.9.5 (2013-12-08)

* Build for either Xen or Unix, depending on the value of the `OS` envvar.
* Shift to the `mirage-types` 0.5.0+ interfaces, which breaks the
  socket backend (temporarily).
* Port the direct stack to the new interfaces.
* Add Travis CI scripts.

### 0.9.4 (2013-08-09)

* Use the `Ipaddr` external library and remove the Homebrew
  equivalents in `Nettypes`.

### 0.9.3 (2013-07-18)

* Changes in module Manager: Removed some functions from the `.mli
  (plug/unplug) and added some modifications in the way the Manager
  interacts with the underlying module Netif. The Netif.create function
  does not take a callback anymore.

### 0.9.2 (2013-07-09)

* Improve TCP state machine for connection teardown.
* Limit fragment number to 8, and coalesce buffers if it goes higher.
* Adapt to mirage-platform-0.9.2 API changes.

### 0.9.1 (2013-06-12)

* Depend on mirage-platform-0.9.1 direct tuntap interfaces.
* Version bump to catch up with mirage-platform.

### 0.5.2 (08-Feb-2013-02-03)

* Encourage scatter-gather I/O all the time, rather than playing tricks
  with packet header buffers. This simplifies the output path considerably
  and cuts minor heap allocations down.
* Install the packed `cmx` along with the `cmxa` to ensure that the
  compiler can do cross-module optimization (this is not a fatal error,
  but will impact performance if the `cmx` file is not present).

### 0.5.1 (20-Dec-2012-12-20)

* Update socket stack to use Cstruct 0.6.0 API

### 0.5.0 (2012-12-20)

* Update Cstruct API to 0.6.0
* [tcp] write now blocks if the write buffer and write window are full

### 0.4.1 (2012-12-14)

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

### 0.4.0 (11-Dec-2012-12-11)

* Require OCaml-4.00.0 or higher, and add relevant build fixes
  to deal with module packing.

### 0.3.1 (2012-12-10)

* Fix the DHCP client marshalling for IPv4 addresses.
* Expose the interface MAC address in the Manager signature.
* Tweak TCP ISN calculation to be more friendly on a 32-bit host.
* Add Manager.create ?devs to control the number of Netif devices
  constructed by default.
* Add Ethif.set/disable_promiscuous to permit directly tapping
  a network interface.

### 0.3.0 (2012-09-04)

* Initial public release.
