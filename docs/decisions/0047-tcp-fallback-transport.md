# ADR-047: TCP fallback transport beside QUIC

## Status

Accepted

## Date

2026-10-10

## Context

ADR-005 started nodes on QUIC only and left TCP as a later increment. The
technical design's connectivity order places a direct TCP address after a
direct QUIC address, because some networks block or degrade UDP while
allowing outbound TCP.

## Decision

Every CharP2P node also builds a TCP transport upgraded with Noise
authentication and Yamux stream multiplexing, using libp2p's defaults for
both. The same behaviours, request limits, connection limits and block list
apply to TCP connections as to QUIC ones; a TCP connection authenticates the
remote peer ID exactly like QUIC.

When a node dials a peer at a list of remembered addresses, direct QUIC
addresses are placed first and the remaining addresses keep their relative
order. libp2p dials the listed addresses concurrently and keeps the first
authenticated connection, so QUIC is attempted first without delaying the
TCP fallback. An existing authenticated connection is reused before any new
dial.

Listening on TCP and publishing TCP address hints is a separate increment.

## Consequences

- Peers behind UDP-blocking networks can connect over TCP once TCP
  addresses are known.
- DCUtR hole punching keeps targeting QUIC; TCP adds no new NAT traversal.
- The relay transport is unchanged; relayed connections keep using Noise
  and Yamux over the relay circuit.

## Sources

- https://docs.rs/libp2p/0.57.0/libp2p/struct.SwarmBuilder.html
- https://github.com/libp2p/specs/tree/master/noise
