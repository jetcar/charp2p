# ADR-005: QUIC and Kademlia network foundation

## Status

Accepted

## Date

2026-09-28

## Context

CharP2P clients need authenticated peer connections and a shared discovery
network without sending chat events through a central service.

## Decision

Use rust-libp2p 0.57 with Tokio. Start client nodes with encrypted QUIC,
Identify, Ping, and client-mode Kademlia behaviours. Identify metadata supplies
learned peer addresses to Kademlia. Known bootstrap addresses are configured by
the application before starting a bootstrap query.

Keep TCP, relay, NAT traversal, provider advertisement, and synchronization
streams as later increments over this foundation.

## Consequences

- Transport identity is authenticated during every QUIC connection.
- Mobile and desktop clients do not answer unrelated DHT routing queries.
- A client requires at least one reachable bootstrap address when its routing
  table is empty.
- The node API exposes bounded lifecycle events rather than the full swarm.

## Sources

- https://docs.rs/libp2p/0.57.0
- https://github.com/libp2p/rust-libp2p/tree/master/examples
- https://github.com/libp2p/specs/tree/master/kad-dht
