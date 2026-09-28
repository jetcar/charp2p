# ADR-003: Canonical signed event envelopes

## Status

Accepted

## Date

2026-09-28

## Context

Peers need to exchange and persist group changes without trusting the sending
peer. Events may arrive repeatedly or out of order, and message payloads will be
end-to-end protected independently of transport encryption.

## Decision

Represent each change as a versioned Postcard-encoded body signed by its author
device's Ed25519 identity. Derive a 32-byte event identifier from the canonical
body using domain-separated BLAKE3. Do not include the signature in the event
identifier.

Use explicit numeric event-kind codes so adding a Rust enum variant cannot
silently renumber existing wire values. Start author sequences at one. Limit an
event to 16 unique causal parents, 64 KiB of protected payload, and 128 KiB of
encoded data.

Treat sender timestamps as advisory metadata. Authorization and conflict
resolution will use the referenced group state and author sequence rather than
wall-clock ordering.

## Alternatives considered

### Hash the full signed envelope

This binds an identifier to a signature representation rather than the logical
event body and complicates signature replacement or migration.

### JSON envelopes

Readable, but require an additional canonicalization standard for stable event
identifiers and signatures.

### Timestamp ordering

Simple, but device clocks are neither trusted nor sufficiently consistent for
membership authorization or deterministic conflict resolution.

## Consequences

- Any peer can verify an event before persistence.
- Repeated delivery has one stable identifier and can be idempotent.
- Event-kind codes and body fields are protocol commitments.
- Membership authorization remains a separate validation layer.
- Protected payload schemas and group message encryption remain separate
  decisions.

## Sources

- https://docs.rs/libp2p-identity/0.3.0
- https://docs.rs/postcard/1.1.3
- https://docs.rs/blake3/1.8.7
- https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf

