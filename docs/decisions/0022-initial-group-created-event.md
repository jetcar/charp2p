# ADR-022: Start new owner histories with GroupCreated

## Status

Accepted

## Date

2026-10-04

## Context

Owner MLS setup previously persisted only the encrypted provider snapshot.
The first admission or message therefore became sequence one even though the
group already existed, leaving the event graph without an explicit causal
root.

## Decision

When creating or reconciling an owner MLS group with no owner-authored events,
sign an empty-payload `GroupCreated` event at owner sequence one. Commit that
event and the encrypted provider snapshot in one SQLite transaction. Restore
the preceding in-memory provider state if signing, encryption, or persistence
fails.

If a pre-migration group already has owner-authored events, keep its existing
sequence unchanged and do not insert history retroactively.

## Consequences

- New group histories have one stable signed causal root.
- The first admission or message references `GroupCreated` and uses sequence
  two.
- Initial MLS state and the event graph cannot diverge across a failed write.
- Older histories remain valid without renumbering or resigning events.
