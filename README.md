# IPV4_Router
This project implements the dataplane of an IPv4 router in C The router is capable of forwarding IPv4 packets based on a static routing table, using an efficient LPM implemented with a binary trie. It also handles essential ICMP  functionalities, including Time Exceeded, Destination Unreachable, and Echo Reply (ping).

  Features Implemented
  IPv4 Forwarding

The router reads a static routing table from a file and uses it to forward packets to the correct next hop.

Packets are verified using the IP checksum and have their TTL decremented before forwarding.

  Longest Prefix Match (LPM)

Implemented using a binary trie for optimal lookup efficiency (O(32) = O(1) per lookup).

The trie is built once at startup using all entries from the routing table.

  ICMP Handling

Implemented types:

Echo Reply (type 0) – responds to ICMP Echo Requests (ping)

Time Exceeded (type 11) – sent when TTL reaches 0

Destination Unreachable (type 3) – sent when no matching route is found

  Ethernet and IP Layer Handling

Ethernet headers are updated before forwarding packets.

IP checksum recalculated after TTL modification.

Interface MAC addresses retrieved dynamically.
