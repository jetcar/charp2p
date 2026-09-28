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
the application before starting a bootstrap query. Invitation-scoped BLAKE3
rendezvous keys use Kademlia provider records to advertise and find online
group peers without publishing group metadata.

Keep TCP, relay, NAT traversal, and synchronization streams as later increments
over this foundation.

Expose an explicit routing-node mode that answers Kademlia queries while client
applications remain in client mode. Client searches use a bounded list of at
most 16 bootstrap multiaddresses and a 12-second provider-query deadline. The
development application may read this list from `CHARP2P_BOOTSTRAP_NODES`;
release bootstrap addresses remain a versioned built-in list.

## Consequences

- Transport identity is authenticated during every QUIC connection.
- Mobile and desktop clients do not answer unrelated DHT routing queries.
- A client requires at least one reachable bootstrap address when its routing
  table is empty.
- The node API exposes bounded lifecycle events rather than the full swarm.
- An empty built-in list is a visible configuration state until an operated or
  community bootstrap node is ready to ship.

## Sources

- https://docs.rs/libp2p/0.57.0
- https://github.com/libp2p/rust-libp2p/tree/master/examples
- https://github.com/libp2p/specs/tree/master/kad-dht
