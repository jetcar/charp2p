# ADR-030: Report stored author heads for member observation receipts

## Status

Accepted

## Date

2026-10-06

## Context

The conversation must show when a message has been observed by all currently
known members (product design, send and synchronize a message). ADR-024 only
records that at least one peer accepted a push. Members synchronize through
the owner and never connect to each other, so a sender cannot ask every member
directly.

## Decision

After a member's pull and push complete, it sends one bounded `ReportHeads`
request with its gap-free author heads for the group. The serving device
authorizes the authenticated peer as a current MLS member, records each head
in the monotonic per-group, per-peer, per-author acknowledgement table
(ADR-024), and answers `ObservedHeads`: for every other current member, the
head of the requester's own events last reported by that member, and its own
stored head for those events. The requester records those heads in the same
table.

A message is shown as `observedByAll` when every other current MLS member on
this device has an acknowledged head at or above its author sequence. With no
other member it stays `local` or `sharedWithPeer`.

## Consequences

- Receipts are as fresh as each member's last synchronization with the owner;
  removed devices stop counting because only current members are compared.
- Group members learn which members have recently synchronized, which the
  member list already makes visible within the group.
- A member could over-report a head; the state is a display hint, never a
  delivery or permanence guarantee.
- One extra request per synchronization; both messages reuse the existing
  1,024-author bound.
