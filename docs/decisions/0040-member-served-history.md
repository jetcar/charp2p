# ADR-040: Member-served history

## Status

Accepted

## Date

2026-10-08

## Context

The product design lets devices synchronize "the group history held by group
members" and says a joining or out-of-date device waits only until a member
returns. The implemented synchronization pulls and pushes only with the pinned
owner device (ADR-006): while the owner is offline, members that are online at
the same time cannot exchange messages.

Members cannot reuse the invitation rendezvous keys to find one another. Each
key derives from one invitation's discovery secret, so members admitted
through different invitations hold different keys, and only the owner retains
them all (ADR-025). A separate group-wide secret distributed by the owner would
need its own event type and re-keying on removal.

## Decision

Every current member derives a member rendezvous key from the MLS exporter of
its current epoch:

```text
member_secret = MLS-Exporter("charp2p member rendezvous v1", group_id, 32)
member_key    = DiscoveryKey::derive(group_id, member_secret)
```

The key uses the existing discovery-key format, so serving nodes store it like
any other 32-byte provider key. It changes with every MLS commit: a removed
device cannot derive keys for epochs after its removal, and a device behind by
a commit derives an older key and reaches the owner first.

While a joined group is open in the application, a member device advertises
the member key of its current epoch and re-advertises after its epoch
advances. Its serving node answers only the pull exchanges (summary, event-ID
pages, signed events) and only for authenticated peers that are current MLS
members in its own view; uploads and head reports remain owner-only and are
answered `unauthorized`. Responses a member serves are charged to its
synchronization data limit (ADR-033) and answered `busy` once it is spent.

A member synchronizes with the pinned owner first. When the owner cannot be
reached, it searches the member key and pulls from the first reachable
provider that is a current MLS member other than itself, trying at most four.
Every received event is verified exactly as from the owner; membership
commits still apply only when authored by the pinned owner device. The group
connection state reports the member-served pull separately from an owner
synchronization.

## Consequences

- Members online at the same time exchange messages while the owner is
  offline; a pull from member A gives member B everything A holds, including
  A's own messages.
- Uploads, acknowledgements ("shared with a peer") and observation receipts
  (ADR-024, ADR-030) still need the owner, so delivery states advance only
  after an owner synchronization.
- Members reveal their peer IDs and addresses to other current members of the
  same epoch through the DHT, as the owner already does to invitation holders.
- Joining still needs the owner, the only committer.

## Sources

- docs/product-design.md, Product statement and Join from an invitation
- docs/technical-design.md, Discovery and Connectivity
- ADR-006, ADR-012, ADR-025, ADR-033
- https://www.rfc-editor.org/rfc/rfc9420#name-exporters
