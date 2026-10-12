# ADR-053: Reserve administration-key rotation without authoring it

## Status

Accepted

## Date

2026-10-12

## Context

The technical design requires the protocol to support rotating a group's
administration key even though the MVP exposes one owner. The group ID is a
versioned hash of the group root public key, invitations and approvals are
root-signed (ADR-002, ADR-044), and members pin the owner device that admitted
them. Transfer of ownership and multiple owners are MVP exclusions, and the
MVP has no UI or recovery flow that would need a new administration key.
Choosing a rotation format now, without a flow that exercises it, would add
untested validation paths to every client.

## Decision

The group ID stays bound to the original root public key for the life of the
group. A rotation never changes the group ID; a future protocol version
records it as a signed hand-over from the current administration key to a
successor key, and clients verify the chain from the root key the group ID
commits to.

Event kind code 14, `AdministrationKeyRotated`, is reserved for that
hand-over. MVP clients never author it, refuse it through member pushes like
every non-message kind, and store a pulled event of that kind without applying
it to group state or showing it, as for the other reserved codes. The payload
format, the successor-key proof and the effect on pinned owner devices and
MLS membership are decided by the ADR that enables rotation.

## Consequences

- Rotation can be added without changing the group ID derivation, the event
  envelope or the event-kind code space.
- An MVP client that pulls a rotation event from a newer client keeps it but
  continues to trust only the original root key, so a group rotated by a newer
  client cannot be administered from MVP clients.
- A compromised administration key cannot be replaced in the MVP; the owner
  recovers by creating a new group, as after a lost owner device.

## Sources

- docs/technical-design.md (Identity; Group protocol event types)
- docs/threat-model.md (Owner administration-key rotation)
