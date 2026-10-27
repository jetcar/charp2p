# ADR-060: Limit profile-v1 groups to 100 devices

## Status

Accepted

## Date

2026-10-27

## Context

An MLS member is one authorized device leaf. Group growth increases the ratchet
tree carried to a new device, local provider state, roster checks, and
synchronization work. The join protocol caps each MLS Welcome at 128 KiB, but a
limit discovered only after building an oversized Welcome would vary with tree
shape and would make a permanently full group appear temporarily busy.

## Decision

Profile version 1 permits at most 100 device leaves in one group, including the
owner. Admission checks the current roster before staging an Add proposal. A
valid join beyond the limit receives the stable `group full` rejection and
stops automatic retries.

The boundary test constructs the maximum roster through the fixed MLS profile,
checks that its generated Commit and Welcome remain within 128 KiB, and verifies
that the next admission is rejected without leaving a pending commit.

## Alternatives considered

- Rely only on the 128 KiB Welcome limit: rejected because the practical limit
  would depend on encoded tree shape and surface as an operational failure.
- Allow 256 or more devices: deferred until measured load tests cover owner
  admission, synchronization, storage, and constrained Android devices.
- Limit people instead of devices: rejected because the MVP has device
  identities and cannot reliably collapse several devices into one person.

## Consequences

- A group supports 100 authorized devices, including its owner device.
- Full groups return a permanent, user-readable result rather than retrying.
- Raising the limit requires a new measured profile decision and compatibility
  review.
