# ADR-050: Inbound byte-rate limits on serving nodes

## Status

Accepted

## Date

2026-10-11

## Context

The project node policy requires per-IP and per-peer bandwidth limits.
Routing nodes and opted-in desktop contributors already bound connection
counts and each peer's request rate, but a peer could still send large
request bodies, DHT messages or relayed bytes as fast as its link allows.

## Decision

Routing nodes and opted-in desktop contributors wrap every direct TCP and
QUIC connection's stream muxer so substream reads draw from two token
buckets: one per remote peer, shared by all of that peer's connections, and
one per remote IP address, shared by all direct connections from it. A read
proceeds only while both buckets hold bytes; otherwise it waits for the
refill, leaving unread bytes in the muxer's flow-control window so the
remote side slows down instead of being buffered.

- Per peer: a burst of 4 MiB, refilled at 1 MiB per second. The burst fits
  one maximum-size synchronization request.
- Per IP address: a burst of 16 MiB, refilled at 4 MiB per second.

Relayed connections are not wrapped; their bytes are bounded by the relay's
own circuit limits. Buckets are forgotten when their last connection closes.
Client nodes keep no byte bound. Writes are not throttled, because a serving
node writes only answers it chose to send.

## Consequences

- One peer or address can no longer saturate a serving node's inbound link.
- Concurrent reads on several substreams may briefly overdraw a bucket; the
  debt delays later reads, so the average rate still holds.
- Load-tested values remain a production gate and may change these numbers.

## Sources

- https://docs.rs/libp2p-core/0.44.0/libp2p_core/muxing/trait.StreamMuxer.html
- https://github.com/libp2p/rust-yamux
