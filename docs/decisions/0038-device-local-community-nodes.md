# ADR-038: Device-local community bootstrap nodes

## Status

Accepted

## Date

2026-10-08

## Context

Community nodes implement the same public protocol as the project node and can
be added to the routing table (technical design, System topology). The Network
page lists known bootstrap and community nodes (product design, page 9), but
the only way to add one is the `CHARP2P_BOOTSTRAP_NODES` environment variable,
which Android users and most desktop users cannot set. A device whose
built-in nodes are unreachable or untrusted has no way to choose another
entry point into the discovery network.

## Decision

The application keeps an optional, device-local list of community bootstrap
nodes. Each entry is a multiaddress ending in the node's `/p2p/` peer ID, at
most 256 bytes, with at most 8 entries and no duplicates. The list is held in
a small JSON file next to the database, holds no secrets and is never
synchronized or included in invitations.

Community nodes are used exactly like built-in and environment-configured
bootstrap nodes: for DHT bootstrap, provider searches and relay reservations.
They gain no protocol authority. Entries already configured by the build or
the environment are not repeated, and the combined list keeps the existing
limit of 16 bootstrap nodes; a change that would exceed it is refused.

The Network page lets the user add and remove community nodes. A change is
stored first and then applied to new connections. The owner advertising
provider restarts on its next refresh so it bootstraps and reserves relays
through the new list; a running contribution node keeps its routing table
until it next starts. A missing file means no community nodes; an unreadable
or invalid file is reported on the Network page and leaves only the built-in
and environment nodes in use, so the file is never silently replaced.

## Consequences

- Users can reach the discovery network through nodes they choose, without a
  rebuild or environment variable.
- A malicious community node can observe the DHT queries and relay traffic
  that pass through it, like any routing or relay peer; group contents remain
  protected end to end.
- Removing a node does not end connections that are already open.

## Sources

- docs/product-design.md, page 9
- docs/technical-design.md, System topology and Discovery
- ADR-005, ADR-009, ADR-026
