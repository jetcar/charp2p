# ADR-029: Export user-selected signed events as evidence

## Status

Accepted

## Date

2026-10-06

## Context

The product offers an evidence export of user-selected signed events instead
of a central report action. Signed events authenticate their author device and
fields, but their payloads are MLS ciphertext that a third party cannot
decrypt without group secrets, which must never leave the device.

## Decision

A member selects up to 64 readable messages from the timeline currently shown
on this device. The client exports a versioned `charp2p-evidence-v1` JSON
document containing, for each selected message, the canonical signed
`MessageCreated` envelope (hex), its event ID, author device, author sequence
and advisory creation time, the latest applied same-author `MessageEdited`
envelope if any, and the text this device displays. The document also names
the exporting device and group and states that `displayedText` is the
exporter's assertion and is not covered by the signatures.

The export is built in Rust from re-verified stored events; selections that
are not readable messages of that group on this device are refused. No MLS
state, local wrapping keys, invitations or other messages are included. The
file is saved or copied only on explicit user action.

## Consequences

- Anyone can verify which device signed each event and that it belongs to the
  group, without receiving group secrets.
- The readable text cannot be proven from the export alone; a recipient must
  trust the exporter or compare with another member's copy.
- Locally hidden messages and messages of blocked devices cannot be exported
  because they are not shown.
- Revealing MLS-derived proofs of plaintext is a later protocol addition.
