# ADR-049: Owner new-event notices

## Status

Accepted

## Date

2026-10-11

## Context

Joined members pull from the pinned owner when a group screen loads and then
once per minute, and background groups even less often. A message the owner
stores, whether authored locally or uploaded by another member, therefore
reaches connected members only after their next scheduled pull, although the
product flow expects connected members to receive it promptly.

## Decision

The synchronization protocol gains a notice exchange on the existing
`/charp2p/sync/2.0.0` protocol:

- `SyncRequest::EventsAvailable { group_id }` tells a member that the owner
  stored new events for the group. It carries no event data, identifiers or
  heads.
- A member answers `SyncResponse::Acknowledged { group_id }` only when the
  authenticated peer is the pinned owner (the joined group's inviter device)
  and a member of the group's current MLS epoch. Any other peer, and any device
  that does not hold the group as a joined group, receives `unauthorized`.
- An acknowledged notice changes no stored state. The member then runs its
  ordinary bounded pull from the pinned owner, which validates every event as
  before; a forged or repeated notice can at most cause an extra pull.
- The owner sends notices only over connections that already exist; it never
  dials members to notify them. A peer running an earlier build fails to
  decode the notice, which the owner ignores, so the protocol version is not
  raised.

## Alternatives considered

### Push the events themselves

Saves one round trip, but duplicates the pull validation, ordering and
bandwidth accounting paths and lets the owner send unbounded unsolicited data.

### Shorter retry interval

Needs no protocol change, but multiplies discovery and connection work for
every idle group and still delays delivery.

## Consequences

- Connected members pull new events immediately instead of at their next
  retry.
- Members that are not connected still rely on scheduled pulls.
- The notice reveals to the member only that the group changed, which the
  next pull would reveal anyway.
