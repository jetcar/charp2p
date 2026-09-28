# ADR-009: Standalone bootstrap and routing node

## Status

Accepted

## Date

2026-09-28

## Context

Clients need at least one reachable Kademlia server to enter the public peer
discovery network. Community operators must be able to run that role without
receiving protocol authority or access to group content.

## Decision

Ship `charp2p-node` as a separate Rust binary using the shared QUIC and libp2p
network crate in Kademlia server mode. It accepts a configurable QUIC listen
multiaddress, persists one stable libp2p identity, and prints the full bootstrap
address containing its peer ID.

Store the node identity as a bounded, versioned libp2p protobuf key record. Use
atomic create-new semantics. On Unix, create it with mode `0600` and refuse to
load a file accessible by group or other users. Erase temporary encoded key
buffers on drop.

The routing process keeps DHT records in memory, rejects all group
synchronization requests as unauthorized, and does not log discovery keys or
connected peer IDs. Graceful shutdown uses the operating-system interrupt
signal.

## Consequences

- Operators can provide independent bootstrap and routing capacity.
- Restarting with the same identity file preserves the advertised peer ID.
- Lost DHT state repopulates as clients re-advertise provider records.
- Relay service, rate limits, metrics, packaging, and deployment hardening are
  required before a public project-operated node is launched.
- The routing protocol gives a node no group names, membership lists, message
  contents, or administration authority.

## Sources

- https://github.com/libp2p/specs/tree/master/kad-dht
- https://docs.rs/libp2p/0.57.0
- https://doc.rust-lang.org/std/os/unix/fs/trait.OpenOptionsExt.html
