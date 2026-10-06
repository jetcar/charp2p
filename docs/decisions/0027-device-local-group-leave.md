# ADR-027: Leave a joined group by forgetting it on this device

## Status

Accepted

## Date

2026-10-06

## Context

The product lets a member leave a group. MLS lets a member propose its own
removal, but only a committer can apply it, and the MVP lets only the owner
device commit membership changes. A member that leaves while the owner is
offline would otherwise have to keep group secrets until the owner commits.

## Decision

Leaving is device-local. One SQLite transaction deletes the joined-group
metadata, every signed event of that group with its dependent local records
(materialized and edited bodies, reply references, unread and hidden markers,
applied commits), peer acknowledgements and local blocks, and stores the
encrypted MLS provider snapshot from which the OpenMLS group state was deleted.
The joined-group discovery key is then removed from platform-protected storage.
That removal is idempotent and refused while the group metadata still exists,
so an interrupted leave is completed by leaving again.

Owners cannot leave their own group; owned groups are not joined groups.

## Consequences

- The device keeps no group keys or messages after leaving and stops
  discovering and synchronizing the group.
- The owner and other members still list the device as an MLS member until the
  owner removes it; their copies of its messages remain.
- Rejoining with the same device identity needs the owner to remove the stale
  membership first, because admission rejects a new KeyPackage for an admitted
  device (ADR-019).
- A signed self-removal request to the owner is a later protocol addition.
