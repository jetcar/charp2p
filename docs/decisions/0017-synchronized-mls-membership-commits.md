# ADR-017: Apply synchronized MLS membership commits

## Status

Accepted

## Date

2026-10-04

## Context

A member joins from a Welcome at one MLS epoch. Later admissions advance the
owner and new member to newer epochs. Existing members must merge those signed
commits before they can send or receive application messages in the current
group state.

## Decision

Treat synchronized `MemberAdded` events as MLS state transitions. Process them
in author sequence before materializing application messages. Bind the MLS
sender credential to the signed event author, validate the staged profile, and
merge only a commit for the local group's current epoch. Defer future-epoch
commits until their predecessor arrives.

When a Welcome already incorporated an older commit, mark that past-epoch event
as applied without replaying it. Atomically persist each applied-event marker
with the resulting encrypted MLS provider snapshot. Restore the preceding
in-memory provider whenever validation or persistence fails.

## Consequences

- Existing members advance when another member joins.
- Messages created at the new epoch can fan out through the owner to every
  synchronized member.
- Restarts do not replay commits or advance MLS state without a matching durable
  marker.
- Membership removal and device revocation commits require their own event
  authorization rules before they use this path.
