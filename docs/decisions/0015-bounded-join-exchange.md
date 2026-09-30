# ADR-015: Bounded join exchange

## Status

Accepted

## Date

2026-09-30

## Context

After discovery and an authenticated transport connection, a new device must
present its bearer invitation and an MLS KeyPackage. An owner that accepts the
capability returns an MLS Welcome. These fields contain secrets and
attacker-controlled encodings, so the shared wire model needs limits before a
network handler or OpenMLS processes them.

## Decision

Define one versioned binary join request containing the claimed group ID,
canonical unpadded Base64url invitation, and MLS KeyPackage. Length-prefix each
field and reject its declared size before allocation. Limit the outer request,
the invitation to 8 KiB, and the KeyPackage to 128 KiB. Define an accepted
response containing one MLS Welcome, also limited before allocation and to
128 KiB.

Expose only three rejection categories: unauthorized, busy, and unsupported
profile. They do not reveal whether the group, invitation, or prior use exists.
Redact invitation, KeyPackage, and Welcome bytes from debug output. Keep those
fields private, do not make their public objects cloneable, and zero their
owned buffers on drop. Construct outbound requests only from a verified
`Invitation`; construct accepted responses only through a validating function.

This wire validation checks shape and size only. The owner must still verify
the invitation signature, group, expiry, revocation and reuse state; parse the
KeyPackage with the pinned MLS profile; and bind its credential to the
authenticated transport peer before acceptance.

## Consequences

- Join handlers have one shared bounded input and output codec with stable
  version, variant, and rejection codes.
- A syntactically valid request grants no membership or synchronization access.
- Network transport, durable MLS state, approval flow, and acceptance remain
  separate increments.
