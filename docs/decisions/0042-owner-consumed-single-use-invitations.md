# ADR-042: Owner-consumed single-use invitations

## Status

Accepted

## Date

2026-10-09

## Context

The product design lets the owner choose whether an invitation is reusable and
the invitation format already signs a reuse policy (ADR-002), but ADR-018
rejects single-use invitations until their consumption is enforced. ADR-002
and ADR-013 note that the signed payload cannot prevent concurrent reuse; a
bearer link copied to several devices must admit at most one of them.

Only the owner device commits admissions (ADR-017, ADR-019), so the owner's
store is the single place that can serialize consumption.

## Decision

- The reuse policy is chosen per invitation when the owner issues it; the
  signed `reusable` claim is authoritative. The group's stored option is only
  the Invitations page default.
- The owner records a consumed single-use invitation (invitation identifier,
  group, admitted device, member-added event) in the same SQLite transaction
  that stores the member-added event, advanced MLS provider snapshot, and
  cached accepted response. The invitation identifier is the primary key, so
  a second admission through the same invitation fails the whole transaction
  and no MLS change is persisted.
- Before MLS processing, admission through a consumed single-use invitation
  answers the exact retry of the device that consumed it from its cached
  response (ADR-019), and answers every other device `unauthorized`.
- After consumption the owner stops advertising the invitation and removes its
  protected bearer record and index, as for revocation (ADR-021); the
  consumption record stays so a restored bearer copy still fails closed.
- Removing the admitted device does not restore the invitation. Owner
  approval (ADR-041) runs before consumption, so a pending or declined request
  does not consume a single-use invitation.

## Consequences

- A leaked single-use link admits at most one device even under concurrent
  joins; the losers retry and are answered `unauthorized`.
- Consumption is owner-local and not synchronized, matching the single owner
  committer model; members never need it to validate history.
- Invitations issued before this decision are reusable and unaffected.
