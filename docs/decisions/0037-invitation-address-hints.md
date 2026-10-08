# ADR-037: Root-signed inviter address hints

## Status

Accepted

## Date

2026-10-08

## Context

The technical design lists optional peer and relay hints in the encoded
invitation. Invitation version 2 (ADR-002) carries no addresses, so a joiner
always needs bootstrap nodes and a DHT provider search before it can reach the
inviter device, even when the inviter's direct or relayed address is already
known to the owner. The version 2 encoding cannot gain a field without changing
its signed bytes.

## Decision

Add invitation version 3 with the domain separator `charp2p-invitation-v3`.
Its wire form is the version 2 claims, followed by a list of binary
multiaddresses, followed by the root signature; the signature covers the claims
and the hint list. Version 2 stays the encoding when an invitation carries no
hints, and decoders accept both versions.

A version 3 invitation carries one to four distinct hints of at most 256 bytes
each, in canonical multiaddress binary form, without a trailing `/p2p`
component. Hints may be direct addresses or circuit-relay addresses ending in
`/p2p-circuit`. Clients append the pinned inviter device peer ID before
dialing, so a hint can only lead to a connection that authenticates as the
root-authorized inviter; any other peer fails the libp2p handshake.

Hints are an optimization only. A joiner dials hinted addresses before the DHT
provider search and falls back to the search when no hint connects. Hints
never replace inviter pinning, invitation validation, or the join exchange
checks.

## Alternatives considered

### Unsigned hints appended outside the signature

Simpler to update, but anyone forwarding a link could redirect the first dial
attempt and the payload would no longer have one canonical byte form.

### Hints as provider records only

Keeps invitations small, but joiners without a working bootstrap path could
never reach an inviter whose address the owner already knew.

## Consequences

- Invitations with hints are larger and reveal the inviter's network addresses
  to every holder of the link, which is already a bearer credential.
- Hints go stale when the inviter's addresses change; the DHT search remains
  the fallback.
- Older clients that only accept version 2 reject hinted invitations as an
  unsupported version.
