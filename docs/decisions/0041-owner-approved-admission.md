# ADR-041: Owner-approved admission

## Status

Accepted

## Date

2026-10-08

## Context

The product design lets the group owner "approve membership when approval is
required" and lists Approve on the Members and devices page. ADR-018 rejects
the manual-approval group option until an enforcement path exists, so every
valid invitation currently admits its bearer directly.

Joining is a single bounded request/response exchange (ADR-015) and the owner
may be offline when the joiner tries again. Holding a join stream open until
the owner decides would tie admission to one connection and to the 30-second
request timeout.

## Decision

Approval reuses the existing join exchange and the joiner's automatic retry of
saved pending invitations:

- A group created with approval required authorizes the invitation bearer as
  today, but admits only devices the owner has approved for that group.
- An authorized request from a device that is not yet approved is recorded on
  the owner device as a bounded approval request (group, authenticated device,
  invitation, first and last request time) and answered with a new stable join
  rejection category, `awaiting approval` (code 4). No MLS state changes and
  no KeyPackage is retained by the owner.
- The joiner keeps the pending invitation and its KeyPackage and retries as
  for `busy`; the join preview and Groups page show that owner approval is
  awaited.
- The owner approves or declines a request from the Members page. Approval is
  a device-local owner record; the next retry from that device proceeds
  through the normal durable, idempotent admission. Declining deletes the
  request and later requests from that device are answered `unauthorized`
  until the owner allows the device again (as for re-admission, ADR-034).
- Removing a member, revoking the invitation, or invitation expiry does not
  grant approval; an approved device that was later removed needs a new
  approval.
- Approval requests expire with their invitation and are bounded per group so
  a leaked invitation cannot grow owner storage without limit.

Groups created before this decision keep direct admission. Retained history
and single-use invitations stay rejected under ADR-018.

## Consequences

- The owner must be online twice: once to receive the request and once (or
  later) to admit the approved device on its next retry.
- The `awaiting approval` category tells a bearer only that its request was
  recorded; it reveals no member or group state beyond what the invitation
  already grants.
- Approval decisions are not synchronized to members, matching the single
  owner committer model.
