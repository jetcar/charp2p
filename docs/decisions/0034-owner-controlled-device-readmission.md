# ADR-034: Let the owner allow a removed device to join again

## Status

Accepted

## Date

2026-10-07

## Context

ADR-020 blocks a removed device from every later admission, including through
an active reusable invitation, and leaves re-admission to a future explicit
owner-controlled flow. A device can be removed by mistake, or removed so that
it can rejoin after leaving locally (ADR-027), and then has no way back.

## Decision

The owner device can clear the re-admission block of a removed device in a
locally owned group. Clearing is device-local owner policy: it deletes the
removed-device marker and publishes no signed event. The signed
`MemberRemoved` event stays in history.

Clearing does not add the device back. The device must join again through an
active invitation with a new KeyPackage. The owner admits it as a new MLS leaf
with a new `MemberAdded` commit, so it cannot decrypt messages from the epochs
in which it was removed. A device that still holds the old group state must
leave the group locally first.

The Members view lists removed devices to the owner with an action to allow
them to join again, behind a confirmation.

## Consequences

- Mistaken removals can be undone without a new owner identity or group.
- Until the device rejoins, anyone holding that device identity and an active
  invitation can be admitted; the owner should revoke invitations it does not
  want reused.
- A rejoined device that left locally restarts from no history. It must pull
  its own earlier events before authoring, or its next events reuse author
  sequences and are reported as conflicts.
