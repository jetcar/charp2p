# ADR-056: Publish only globally routable direct addresses in provider records

## Status

Accepted

## Date

2026-10-13

## Context

Kademlia provider records carry the provider's confirmed external addresses as
dial hints. A client node confirms no direct address today: the relay client
confirms only its circuit addresses, and identify-observed addresses stay
unconfirmed candidates. A joiner that finds the owner through the DHT can
therefore only dial relay circuits and must wait for DCUtR to reach a direct
path, even when the owner device listens on a publicly routable address.

Publishing every listen address would also expose the owner's private network
layout (RFC 1918, carrier-grade NAT, unique-local and link-local addresses) to
every serving node that stores the record and every holder of the rendezvous
key, without helping remote joiners, who cannot route to those addresses.
Devices on the same network segment already learn them through mDNS, and
invitation address hints (ADR-037) may carry them to the bearer's holder.

## Decision

A client node confirms as external, and so publishes in its provider records,
its relay circuit addresses and only those direct listen addresses whose IP is
globally routable: not unspecified, loopback, private, link-local, shared
(100.64.0.0/10), documentation, benchmarking, broadcast or reserved IPv4, and
for IPv6 only global unicast outside unique-local, link-local and
documentation ranges. Wildcard listen addresses are expanded by the swarm into
per-interface addresses before this filter applies.

At most four direct addresses are published, QUIC first, so the eight
addresses a serving node keeps per record (technical design, DHT) always leave
room for relay circuits. Identify-observed addresses are not confirmed; NAT
mappings are left to DCUtR over a relayed connection.

Joiners dial the direct addresses of a DHT-found provider before its relay
circuits, in the same order as remembered addresses (ADR-047): circuits only
after every direct address fails or none connects within the direct grace
period.

## Alternatives considered

### Publish all listen addresses

Lets same-network joiners without mDNS connect directly, but reveals private
addressing to unrelated serving nodes, and remote joiners waste dial attempts
on unroutable addresses.

### Publish no direct addresses

Keeps today's behavior and hides even public addresses, but every DHT-found
connection starts relayed, adding relay load and latency to devices that are
directly reachable.

### Confirm identify-observed addresses

Would publish the NAT mapping, which usually refuses unsolicited inbound
connections; without AutoNAT the node cannot tell which observations are
dialable.

## Consequences

- Devices with a public IPv4 or global IPv6 address become directly reachable
  from the DHT path, and their address is visible to serving nodes storing the
  record and to holders of the rendezvous key, as the relay already sees it.
- Private-network addresses never leave the device through the DHT.
- Devices behind NAT keep publishing only relay circuits and rely on DCUtR.
- Global IPv6 addresses may be stable identifiers; operating-system temporary
  addresses limit this where enabled.

## Sources

- docs/technical-design.md (DHT, Connectivity)
- docs/decisions/0037-invitation-address-hints.md
- docs/decisions/0047-tcp-fallback-transport.md
