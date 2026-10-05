# ADR-026: Bounded Circuit Relay v2 transport

## Status

Accepted

## Date

2026-10-05

## Context

Many Windows and Android peers cannot accept an inbound direct QUIC connection
because of NAT or firewall policy. DHT discovery can identify an online group
peer without making that peer directly dialable. The project-operated and
community routing nodes need to provide connectivity without terminating the
group protocol or receiving group keys.

## Decision

Enable the established libp2p Circuit Relay v2 server on routing nodes and the
libp2p relay client transport on application peers. Long-lived owner
advertisements request a reservation from each configured bootstrap node.
Relayed connections negotiate Noise authentication and encryption plus Yamux
multiplexing between the two endpoint peers. The existing bounded join and
synchronization protocols run unchanged over that authenticated connection.

Use conservative server limits: 32 total reservations, one reservation per
peer, one-hour reservations, 32 simultaneous circuits, four circuits per peer,
five minutes per circuit, and 32 MiB per circuit. Keep libp2p's default
per-peer and per-IP reservation and circuit-source rate limiters enabled.

Routing nodes add their active listen addresses as external relay addresses.
They continue to reject application join and synchronization requests and do
not persist chat events or message payloads.

## Consequences

- Peers behind NAT can accept authenticated join and synchronization streams
  through a configured routing node.
- Relay operators can observe endpoint peer IDs, addresses, timing, and traffic
  volume, but endpoint transport encryption and MLS protect group payloads.
- A circuit that reaches its time or byte limit closes and can be retried over
  a new circuit.
- AutoNAT, hole punching, quota metrics, and production deployment controls
  remain separate increments.

## Sources

- https://github.com/libp2p/specs/blob/master/relay/circuit-v2.md
- https://libp2p.github.io/rust-libp2p/libp2p_relay/struct.Config.html
