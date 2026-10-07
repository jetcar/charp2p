# ADR-036: Owner-issued invitations for permitted members

## Status

Accepted

## Date

2026-10-07

## Context

The product design lets a member invite others when granted permission. The
current protocol has one committer: invitation version 2 is signed by the group
root key, which only the owner device holds, and pins that owner device as the
only peer that authorizes a bearer and admits an MLS member (ADR-002, ADR-021).
Members apply membership commits only from the pinned owner device. Letting a
member sign invitations or admit devices would need delegated root
authority, replicated revocation state, and concurrent MLS commits, none of
which the MVP defines.

## Decision

Invite permission is owner-granted and owner-executed. The owner device keeps
the root key, issues every invitation, and remains the only admitter.

The owner grants or withdraws permission for one admitted member device with a
signed `InvitePermissionChanged` event. Its payload is a versioned record of
the target device ID and a granted flag, carried as an MLS application message.
Members apply the change only when its author is the owner device that
admitted them; for each target device the change with the owner's highest
author sequence is current. Like metadata changes, it is delivered by pull
synchronization and never accepted through member pushes. Permission is not
inherited by later devices and is dropped when the device is removed.

A permitted member asks the owner device for an invitation over the
authenticated request-response protocol `/charp2p/invite/1.0.0`, with the same
30-second deadline and stream bound as the join exchange. The request carries
the group ID and a requested lifetime. The owner checks that the authenticated
transport peer is an admitted, non-removed device of a locally owned group and
currently holds permission in the owner's own event state, then issues a
version 2 invitation exactly as for itself: root-signed, owner device pinned as
inviter, reuse and approval taken from the group settings, lifetime capped by
the owner's maximum, stored in protected storage and advertised. The owner
records the requesting device in the non-secret issued-invitation index. The
response is the encoded invitation, a bearer credential that is redacted from
debug output and zeroed on drop. Rejections are only `unauthorized` and `busy`,
so a request does not reveal which check failed.

Only the owner revokes invitations (ADR-021). Withdrawing a member's permission
also revokes the active invitations issued at that member's request.

## Alternatives considered

### Delegated root signatures

The owner could sign a delegation certificate and let the member sign
invitations with its device key. Joiners would still need a peer that can
admit them, revocation would need replicated signed state, and the invitation
format would need a new version.

### Members as MLS committers

Any MLS member can technically commit an Add. Concurrent commits from several
devices would fork epochs and conflict with the single-committer rule that
members already enforce.

## Consequences

- Invitation format, join exchange, admission, and revocation are unchanged;
  joiners see the owner as the root-authorized inviter.
- A permitted member can create an invitation only while the owner device is
  reachable, which joining already requires.
- Members learn their permission through normal synchronization, so the
  interface can hide the action until it is granted; the owner still enforces
  the check on every request.
- Owner approval, reuse and lifetime limits apply equally to member requests.
