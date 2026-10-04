# ADR-021: Revoke bearer invitations at the pinned owner

## Status

Accepted

## Date

2026-10-04

## Context

Invitation version 2 pins one root-authorized owner device. That device is the
only peer allowed to authorize the bearer and admit an MLS member. Other group
devices do not need replicated invitation state for the current protocol.

## Decision

Revocation is an owner-local capability deletion. While holding the shared
storage lock, remove the protected bearer before its SQLite index. Join
authorization requires both records and therefore fails closed if deletion is
interrupted. Stop the active DHT provider and request listener after the local
revocation commits.

This supersedes the invitation-revocation parts of ADR-013 that required a
signed group event. A future protocol that lets other members authorize joins
must introduce replicated signed revocation state before enabling that role.

## Consequences

- A copied link stops authorizing new joins immediately at its pinned owner.
- Revocation survives restart and does not depend on other peers being online.
- Devices already admitted remain members until separately removed.
- Network-level provider records may remain cached until DHT expiry, but no
  live CharP2P listener accepts the revoked bearer.
