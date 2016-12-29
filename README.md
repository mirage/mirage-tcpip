`mirage-tcpip` provides a networking stack for the Mirage operating
system.  It provides implementations for the following module types (which correspond with the similarly-named protocols):

* ETHERNET
* ARP
* IP (via the IPv4 and IPv6 modules)
* ICMP
* UDP
* TCP

There are two implementations of the IP, ICMP, UDP, and TCP module types - the `socket` stack, and the `direct` stack.

The `socket` stack uses socket calls to a traditional operating system to provide the functionality described in the module types.  See the `unix/` directory for the modules used as implementations of the `socket` stack.  The `socket` stack is used for testing or other applications which do not expect to run as unikernels.

The `direct` stack expects to write to a device implementing the `NETIF` module type defined for MirageOS.    See the `lib/` directory for the modules used as implementations of the `direct` stack, which are the expected stack for most MirageOS applications.  The `direct` stack is the only usable set of implementations for applications which will run as unikernels on a hypervisor target.

* WWW: <https://mirage.io>
* E-mail: <mirageos-devel@lists.xenproject.org>
* Issues: <https://github.com/mirage/mirage-tcpip/issues>

### License

`mirage-tcpip` is distributed under the ISC license.
