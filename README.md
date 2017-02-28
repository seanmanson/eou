eou
===

An Ethernet over UDP tunnel driver for OpenBSD 5.7, created for COMP3301 at UQ in 2015.
It provides a new ifconfig device driver to the system to allow connections to be
made over a dummy ethernet connection. This allows ip tunnelling between two distinct networks.

The UDP connection uses a proprietary protocol, given by the assignment spec provided in the respository.
The server end of this connection is not provided, as it wasn't given to us (the lecturer
kept it to themselves).
`eou` has the ability to allow multiple tunnels between the same server and client by using
separate network IDs, as well as support for different starting ips (if we have multiple connections
to different networks).

Usage
-----
Create a new `eou` device:
~~~
ifconfig eou0 create
~~~

Tunnel between this and a host and set the network ID: (port can be set optionally after the host ip)
~~~
ifconfig eou0 vnetid 1337
ifconfig eou0 tunnel localhost 123.123.123.0
~~~

Connection status can be viewed using `ifconfig`:
~~~
?>ifconfig eou0
eou0: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> mtu 1500
      priority: 0
      groups: eou
      media: Ethernet autoselect
      status: no carrier
      tunnel: inet 127.0.0.1 -> 216.58.203.110:3301
~~~
