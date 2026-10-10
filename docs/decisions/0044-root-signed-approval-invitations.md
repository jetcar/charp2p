# ADR-044: Root-signed owner approval in invitations

## Status

Accepted

## Date

2026-10-10

## Context

The product design asks the join preview to show whether owner approval is
needed. ADR-041 enforces approval on the owner device per group, but
invitation versions 2 and 3 (ADR-002, ADR-037) do not say whether the group
requires it, so a joiner learns it only from the `awaiting approval` join
rejection after contacting the inviter.

## Decision

Add invitation version 4 with the domain separator `charp2p-invitation-v4`.
Its wire form is the version 3 layout, the version 2 claims followed by a list
of binary multiaddress hints and the root signature, except that the hint list
may be empty. Version 4 states that the owner must approve each joining device
before admission. The owner issues version 4 for every invitation of a group
created with approval required, and versions 2 or 3 otherwise, so existing
encodings are unchanged for direct-admission groups.

The version and its domain separator are covered by the root signature, so a
holder cannot rewrite a version 4 invitation into version 2 or 3 to hide the
requirement. The flag is informational for the joiner: the owner device keeps
enforcing approval from its local group record (ADR-041) regardless of the
invitation version presented.

## Alternatives considered

### A boolean claim in a new claims structure

More extensible, but it would add a second meaning for a value that the
version already selects and a non-canonical `false` form to reject.

### Showing approval only after the first join attempt

Needs no wire change, but the preview could not tell the user before they
decide to join.

## Consequences

- The join preview shows whether owner approval is required.
- Clients that only accept versions 2 and 3 reject invitations for groups that
  require approval as an unsupported version.
