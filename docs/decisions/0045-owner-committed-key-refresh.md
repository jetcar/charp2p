# ADR-045: Owner-committed MLS key refresh

## Status

Accepted

## Date

2026-10-10

## Context

The technical design lists a `KeyEpochAdvanced` event type and claims
compromised member-device revocation for future access. Removing a device
(ADR-020) already advances the MLS epoch, but the owner has no way to replace
its own path secrets without changing membership, for example after suspecting
that one of its leaf secrets leaked. Members apply only MLS commits authored by
the pinned owner device (ADR-017), so a refresh must follow the same authority.

## Decision

A `KeyEpochAdvanced` event carries one MLS Commit authored by the owner
device. The Commit contains no proposals, so it cannot change membership or
group context, and carries a forced update path that replaces the owner's leaf
and path secrets and advances the epoch for every current member.

- The owner stages the Commit without consuming queued proposals, signs the
  event, persists the event and the merged provider snapshot in one SQLite
  transaction, and only then merges the pending Commit, exactly like a
  removal.
- Members apply a `KeyEpochAdvanced` event in the same ordered pass as
  `MemberAdded` and `MemberRemoved` commits, only when its author is the
  pinned owner device and the MLS sender matches the event author, and reject
  any carried Commit that has proposals or no update path.
- `KeyEpochAdvanced` events are delivered by pull synchronization and are
  never accepted through member pushes.
- Because the event advances the epoch that later messages depend on, it
  counts as a commit in the synchronization summary's membership state.

## Alternatives considered

### Member-initiated self-updates

Lets any device refresh its own leaf, but contradicts the owner-only commit
rule and creates concurrent commits for the same epoch without an ordering
authority.

### Only refreshing through a removal

Needs no new event, but cannot refresh keys when nobody should be removed.

## Consequences

- The owner can advance the group epoch on demand without a membership change.
- Older clients that do not apply `KeyEpochAdvanced` stop decrypting messages
  sent after a refresh until they update.
