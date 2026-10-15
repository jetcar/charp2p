# ADR-057: Complete interrupted leaves from a durable cleanup record

## Status

Accepted

## Date

2026-10-15

## Context

ADR-027 removes the joined-group discovery key from platform-protected storage
after the SQLite transaction that forgets the group, and completes an
interrupted leave by leaving again. Once that transaction commits, the group no
longer appears in the interface, so the user cannot leave again, and a retry
reported `joined_group_not_found` although it removed the key. Protected
storage cannot be enumerated to find keys left behind.

## Decision

The leave transaction also records the group ID in a device-local
`left_group_discovery_cleanups` table. Removing the discovery key clears that
record. A retried leave whose database step already ran succeeds when it
clears a record. At start the app removes the discovery key of every recorded
group that is not joined again, and drops the record of a group that was
joined again so its new key stays. A failed removal keeps the record for the
next start.

## Consequences

- An interrupted leave no longer leaves a discovery key behind for good.
- The record holds only the group ID, which the device already knew; it reveals
  that this device once left that group until the cleanup completes.
- Leaves interrupted before this table existed have no record and still need
  the protected-storage entry removed by the platform's own tools.
