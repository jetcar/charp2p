# ADR-008: Split storage for pending invitations

## Status

Accepted

## Date

2026-09-28

## Context

A user may accept an invitation while no group member is reachable. The app
must retain that pending join across restarts. The signed invitation contains a
bearer discovery secret, while the groups screen needs searchable display
metadata.

## Decision

Store authenticated pending-group metadata in the versioned SQLite application
database. Store each canonical signed invitation separately in the platform
credential store, keyed by its group ID. Limit protected invitation records to
2 KiB for compatibility with Windows Credential Manager.

Whenever pending groups are loaded, retrieve and verify the protected signed
invitation and compare every SQLite metadata field with its authenticated
claims. Fail closed on a missing, damaged, or mismatched record. Remove expired
pending invitations from both stores after successful verification.

User cancellation and expiry cleanup first remove any retained MLS pending-join
material, then delete the protected bearer and its SQLite metadata. If the
metadata write fails after bearer deletion, the remaining index keeps cleanup
retryable without restoring the join capability.

Before a completed join deletes the bearer invitation, derive its opaque
32-byte DHT discovery key and store that key under a separate versioned
credential-store entry. Persist this key before promoting the SQLite record so
an interrupted write cannot create a newly joined group without its future
rendezvous key. The derived key locates providers but cannot authorize group
membership or another join.

## Consequences

- The discovery secret does not enter SQLite or the JavaScript runtime.
- Editable metadata cannot change what the UI displays without detection.
- Saving one newer invitation for the same group replaces the previous pending
  capability and metadata.
- Completed members retain the minimum protected rendezvous material needed to
  rediscover peers without retaining the join capability.
- Larger future invitation formats need another protected-storage strategy.
- Writes span two storage systems and cannot use one atomic transaction; a
  failed metadata write may leave an unreachable credential record.

## Sources

- https://learn.microsoft.com/windows/win32/api/wincred/ns-wincred-credentialw
- https://developer.android.com/privacy-and-security/keystore
- https://www.sqlite.org/stricttables.html
