# ADR-020: Persist owner-controlled device removal

## Status

Accepted

## Date

2026-10-04

## Context

An MLS removal advances the group epoch, but a reusable bearer invitation and
cached Welcome could otherwise admit the same device again immediately.
Provider state, event history, and admission policy must remain consistent
across crashes and owner restarts.

## Decision

Only a locally owned group can invoke removal. The owner stages an OpenMLS
remove commit, publishes it as a signed `MemberRemoved` event, merges it, and
atomically stores the event, encrypted provider snapshot, and removed device
identifier. The same transaction deletes any cached join response for that
device.

Admission checks the removed-device index before cached-response lookup or MLS
processing. A removed device remains blocked even when it presents a valid,
active reusable invitation. Other members apply synchronized `MemberRemoved`
commits through the existing bounded MLS commit pipeline.

## Consequences

- Removed devices cannot decrypt messages from later epochs.
- Replaying an old join request cannot recover a cached Welcome.
- Re-admission requires a future explicit owner-controlled unblock flow.
- Removal cannot erase plaintext or ciphertext already retained elsewhere.
