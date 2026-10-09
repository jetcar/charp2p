# ADR-043: Several active invitations per group

## Status

Accepted; supersedes the one-active-invitation rule of ADR-013.

## Date

2026-10-09

## Context

ADR-013 let the single-group shell keep one active issued invitation per group
so an older bearer credential could not become hidden from its interface.
Owner-issued member invitations (ADR-036), single-use invitations (ADR-042)
and per-invitation expiry mean an owner and each permitted member need their
own links at the same time. With one active invitation, a member's request
failed while the owner's invitation was active and the owner could not create
a single-use link without revoking a reusable one.

## Decision

An owned group may hold up to 16 active issued invitations. Issuing another
invitation leaves the existing ones valid; expired records are still removed
while issuing. A permitted member's repeated request still returns its own
active invitation, so one member holds at most one at a time. Issuing beyond
the bound fails with `invitation_limit_reached` for the owner and `busy` for a
member request, before any key or record is created. The per-group and total
retained discovery-key bounds (ADR-025) still apply.

The non-secret issued-invitation list exposes the requesting member device for
invitations issued under ADR-036 so the owner can see who asked for each one.
Revocation names one invitation by its identifier and leaves the group's other
invitations active; it is otherwise unchanged (ADR-021).

## Alternatives considered

### Replace the active invitation on each issue

Silently revoking the previous link would break links already shared by the
owner or a member.

### Unbounded invitations

Each invitation adds a protected record and an advertised rendezvous key; a
fixed bound keeps both and the interface list small.

## Consequences

- The owner and permitted members can share separate links concurrently and
  revoke them separately.
- The interface must list every active invitation so none is hidden from the
  owner.
- The bound is local policy and can change without a protocol change.
