# ADR-023: Keep local message deletion outside the signed event graph

## Status

Accepted

## Date

2026-10-04

## Context

The product offers deletion from one device. Removing a signed event would
damage synchronization history, while emitting `MessageDeleted` would request
a group-wide deletion and change the meaning of the action.

## Decision

Delete the event's encrypted materialized display body and store its event ID
in a device-local hidden-message table in one SQLite transaction. Keep the
verified signed event. Exclude hidden IDs from future message materialization.

## Consequences

- Local deletion persists across restart and later synchronization.
- Other group members retain their copies.
- The signed event remains available for synchronization and integrity checks.
- Reclaiming the small encrypted event ciphertext is outside this action.
