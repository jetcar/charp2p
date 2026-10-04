# ADR-025: Retain owner rendezvous keys for admitted members

## Status

Accepted

## Date

2026-10-04

## Context

Joined members retain the opaque rendezvous key derived from their invitation.
Stopping publication and deleting the owner's copy when that invitation expires
or is revoked prevents those authorized members from finding the owner again.
Bearer expiry must end join authority without ending group synchronization.

## Decision

Store each owner-side derived rendezvous key in platform-protected storage with
a non-secret SQLite index. Keep it after the bearer invitation is expired or
revoked. While the owned group is active, publish every retained key through
one authenticated libp2p node and continue serving synchronization only to
current MLS members. Keep join authorization tied to the active signed bearer.
Bound retained keys to 64 per group.

## Consequences

- Existing members can rediscover the owner after their invitation expires.
- Revoked and expired bearers still reveal reachability to their holders, but
  cannot authorize a join or synchronization.
- Invitation rotation changes the published DHT-key set and restarts the local
  advertiser without changing the owner's peer identity.
- Selective rendezvous-key retirement requires membership-to-invitation
  provenance and remains separate work.
