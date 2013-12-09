`mirage-tcpip` provides a networking stack for the Mirage operating
system that supports TCP/IP, ARP, DHCP and UDP.

It compiles against either `mirage-net-unix` or `mirage-net-xen` to provide an
equivalent package for either Unix or Xen respectively.  Future versions will
be functorised to avoid this repeated compilation, but for now the OPAM package
manager takes care of this for you.

WWW: <http://openmirage.org>
E-mail: <mirageos-devel@lists.xenproject.org>
