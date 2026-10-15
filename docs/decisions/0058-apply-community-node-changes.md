# ADR-058: Apply community node changes to running nodes

## Status

Accepted

## Date

2026-10-15

## Context

ADR-038 applies a changed community node list to new connections, restarts the
owner advertising provider on its next refresh and lets a running contribution
node keep its routing table until it next starts. A device whose only entry
points are community nodes had no running contribution node when the list was
first filled, so an opted-in contribution stayed "Not contributing" until the
app restarted or the user toggled the option.

## Decision

Storing a changed community node list applies it to the running nodes as
follows:

- The owner advertising provider stops at once and its next refresh
  bootstraps and reserves relays through the new list.
- An opted-in contribution node stops and restarts immediately from the stored
  preference through the new list. A restart that fails is shown on the
  Network page and does not fail the change, because the list is already
  stored.
- A running member serving node keeps its connections to the owner and uses
  the new list when it next starts.

## Consequences

- Adding the first community node starts an opted-in contribution without a
  restart.
- A list change briefly interrupts the contribution node's routing and relay
  service; connections relayed through it are dropped.
- Removing a node still does not end a member serving node's open connections.

## Sources

- docs/product-design.md, page 9
- docs/technical-design.md, System topology and Discovery
- ADR-031, ADR-038, ADR-040
