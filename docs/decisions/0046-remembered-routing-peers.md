# ADR-046: Device-local remembered routing peers

## Status

Accepted

## Date

2026-10-10

## Context

The technical design says invitations and learned routing tables provide
entry points beside the built-in bootstrap list (Discovery). Today a client
forgets every routing peer when its node stops, so each start depends on the
built-in, environment or community bootstrap nodes (ADR-038) being reachable.
If those are down, a device that recently talked to other routing nodes still
cannot enter the discovery network.

## Decision

The application keeps a bounded, device-local list of routing peers that it
recently reached. A peer qualifies only after an authenticated connection
whose Identify information advertises the CharP2P DHT protocol (ADR-039),
which only routing-mode nodes (project, community and contributor nodes)
serve; ordinary clients and group members never qualify. Each entry is the
peer ID with the transport address that reached it, at most 256 bytes. The
list holds at most 8 entries, most recently successful first; a newly
successful peer replaces the oldest entry, and a peer appears once.

The list lives in a small JSON file next to the database, holds no secrets,
and is never synchronized, shown as configuration or included in invitations.
An unreadable or invalid file is treated as empty and replaced on the next
success, because the list is a cache rather than a user choice.

When a client node starts, remembered peers that are not already configured
bootstrap nodes are added as extra DHT entry points after the configured ones.
They do not count toward the 16-node bootstrap limit, do not satisfy the
"bootstrap required" status on their own, are not used for relay
reservations, and gain no protocol authority.

## Consequences

- A device that recently reached the network can usually re-enter it even
  when its configured bootstrap nodes are unreachable.
- The file reveals which routing nodes the device recently used to anyone who
  can read the application's data directory; it reveals no group, contact or
  message information.
- A remembered peer that has gone away costs one failed dial at start.

## Sources

- docs/technical-design.md, Discovery
- ADR-005, ADR-038, ADR-039
