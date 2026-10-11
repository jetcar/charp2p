# ADR-052: Retain the pending KeyPackage after a rejected Welcome

## Status

Accepted

## Date

2026-10-11

## Context

OpenMLS consumes the one-time KeyPackage private material while decrypting a
Welcome, even when a later profile, group-identifier, or persistence check
rejects that Welcome. The technical design said the joining client then
publishes a fresh KeyPackage. Under ADR-019 the owner admits a device once per
KeyPackage hash: an exact retry returns the cached Welcome, and a different
KeyPackage for an already admitted device is rejected. A fresh KeyPackage
could therefore never complete the join, while discarding the old one would
make the owner's cached Welcome undecryptable.

## Decision

Welcome processing works on the in-memory provider only. On any rejection the
joining client restores the provider from the snapshot taken before
processing and persists nothing, so the durable pending join keeps its
original KeyPackage and private material. The pending join stays usable and a
retry sends the same join request, which the owner answers idempotently.

The joining client never publishes a replacement KeyPackage for a pending
join. Cancelling the pending invitation deletes the KeyPackage and its
private material; a later join from a new invitation creates a new one.

## Consequences

- Transient failures, such as a damaged transfer or a local storage error,
  recover on retry without creating a second MLS leaf.
- A Welcome the owner built outside the profile is rejected again on every
  retry, because the owner returns the same cached response. The user sees
  the invalid-response error and can discard the invitation; recovery needs
  the owner to remove the device's leaf and issue a new invitation.
- The KeyPackage private material for a pending join stays stored until the
  join completes or the invitation is discarded.

## Sources

- https://www.rfc-editor.org/rfc/rfc9420#section-12.4.3.1 (Joining via
  Welcome message)
- https://docs.rs/openmls/0.9.0/openmls/group/struct.StagedWelcome.html
