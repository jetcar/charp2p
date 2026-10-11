# ADR-048: Bounded past-epoch message secrets

## Status

Accepted

## Date

2026-10-11

## Context

OpenMLS keeps no past-epoch message secrets by default. Pull synchronization
reads pending messages in their own epoch before applying the next commit, but
a message that reaches a device only after the commit ending its epoch was
applied, for example a member push the owner stored after a key refresh, or an
event pulled from another member later, can then never be decrypted. Keeping
every past epoch would make one leaked device state expose all retained
history and grow the encrypted provider snapshot without bound.

## Decision

Every profile version 1 group keeps message secrets for at most four past
epochs (`MAX_PAST_EPOCHS`), set through the OpenMLS join configuration of
created and joined groups.

- Groups stored before this decision carry the earlier configuration without
  past epochs. When the app opens its provider it upgrades every owned and
  joined group whose stored configuration exactly equals that earlier profile
  configuration; any other configuration stays rejected by profile
  validation. Secrets accumulate from the next applied commit, and the upgrade
  is persisted with the next provider snapshot.
- A message whose epoch is older than the current epoch minus the window is
  permanently unreadable and is recorded as such.
- A message from a past epoch is read only when its MLS sender is still a
  member of the group's current epoch. A removed device's messages are read
  only before its removal commit is applied, so it cannot use retained
  secrets of an epoch it belonged to for messages authored after its removal.

## Alternatives considered

### Keep all past epochs

Never loses a late message, but removes forward secrecy for all retained
history and grows provider snapshots with every commit.

### Owner re-encrypts late messages

Avoids retained secrets on members, but the owner would author content under
another member's name, breaking the signed author binding.

## Consequences

- Late messages from current members remain readable across up to four
  commits.
- A compromised device state additionally exposes up to four past epochs of
  message keys that have not yet been used.
- Late messages from removed devices are dropped once their removal applies.
