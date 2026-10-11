# ADR-051: Signed author cut-offs in member-removal Commits

## Status

Accepted

## Date

2026-10-11

## Context

When the owner removes a device it records that device's highest stored
author sequence as a cut-off and refuses later sequences. Members did not
record any cut-off, so a member serving node (ADR-040) could still store and
serve events the removed device authored after its removal. Each member
holds a different subset of the removed device's events, so a cut-off
computed locally by each member would disagree between members and could
refuse events the owner had accepted.

## Decision

The owner signs its cut-off into the removal itself. Before staging the
`MemberRemoved` Commit it sets the Commit's MLS authenticated data to:

```text
"charp2p-removal-cutoff\0" || version u16 (1) || cutoff_sequence u64
  || removed device peer ID bytes
```

All integers are big-endian. `cutoff_sequence` is the owner's highest stored
author sequence of the removed device, or zero when none is stored. MLS
signs the authenticated data with the Commit, and the Commit is the
owner-signed event's protected payload, so the cut-off is authenticated
twice. The owner records the same value in its own store.

A member applying an owner `MemberRemoved` Commit decodes the authenticated
data and records the cut-off only when it names exactly the one device the
Commit removed from the MLS group. From then on its store refuses that
device's later sequences, and its pull sessions cap and drop them, the same
way as on the owner. After applying any owner Commit, a member clears the
cut-offs of devices that are current MLS members again, which follows the
owner's re-admission of a removed device.

A removal Commit without valid cut-off data, such as one created before this
decision, is still applied but records no cut-off.

## Consequences

- Every member refuses the same post-removal events as the owner, so a
  removed device cannot reach other members through member serving nodes.
- The cut-off adds about 60 bytes to a removal Commit.
- A member that already stored post-removal events before applying the
  removal keeps them stored, but no longer advertises or serves them.
- Removals already in history carry no cut-off on members.

## Sources

- https://www.rfc-editor.org/rfc/rfc9420#section-6.1 (FramedContent
  authenticated_data)
- https://docs.rs/openmls/0.9.0/openmls/group/struct.MlsGroup.html#method.set_aad
