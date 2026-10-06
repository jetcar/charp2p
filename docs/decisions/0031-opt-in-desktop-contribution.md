# ADR-031: Opt-in desktop routing and relay contribution

## Status

Accepted

## Date

2026-10-06

## Context

The Network page offers desktop-only opt-in contribution controls with explicit
bandwidth limits (product design, page 9). The technical design describes a
routing peer for opted-in desktop installations and a relay peer that accepts
bounded circuit-relay reservations. Application peers currently run only as
Kademlia clients with the relay client transport (ADR-005, ADR-026). Android
remains a light client until the open product decision on Android routing is
validated.

## Decision

Contribution is off by default and offered only on desktop builds. When the
user opts in, the application runs one long-lived contribution node with the
device's network identity, in Kademlia server mode, connected to the
configured bootstrap nodes. It answers routing queries and stores only the
bounded, expiring provider records Kademlia already keeps in memory. It
rejects application join and synchronization requests from unrelated peers,
as routing nodes do (ADR-009).

Relay capacity is a separate opt-in that requires routing contribution. Its
limits are explicit user choices bounded by the routing node limits of
ADR-026: 1 to 32 simultaneous circuits (also the reservation limit), 1 to 32
MiB per circuit, at most four circuits per peer, one reservation per peer,
one-hour reservations, and five-minute circuits. The worst-case relayed volume
is therefore the circuit count times the per-circuit limit per five minutes,
and the application shows that figure next to the controls. libp2p's default
per-peer and per-IP rate limiters stay enabled.

The preference is device-local, contains no secrets, and is not synchronized
to other devices.

## Consequences

- Desktop users who opt in add DHT routing and, optionally, bounded relay
  capacity without becoming group administrators or receiving group keys.
- Relay operators, including opted-in desktop users, can observe endpoint peer
  IDs, addresses, timing, and traffic volume (ADR-026).
- A desktop behind NAT that cannot accept inbound connections contributes
  little; reachability detection remains a separate increment.
- Android keeps the light-peer role.

## Sources

- https://github.com/libp2p/specs/tree/master/kad-dht
- https://libp2p.github.io/rust-libp2p/libp2p_relay/struct.Config.html
