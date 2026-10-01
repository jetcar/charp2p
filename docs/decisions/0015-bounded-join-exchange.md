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

Carry this codec over the authenticated libp2p request-response protocol
`/charp2p/join/1.0.0`, with a 30-second deadline and at most 16 concurrent
streams per connection. The transport reads at most one byte beyond each outer
limit so an oversized message cannot be accepted as a valid prefix. Temporary
wire buffers are zeroed on drop. Routing-only nodes reject all join requests;
application advertisers validate inbound bearers against the owner's protected
issued-invitation state. Unknown, expired, or forged credentials receive the
same `unauthorized` response. After bearer authorization, advertisers parse and
verify the bounded MLS KeyPackage, require the pinned profile, and bind its
signed credential to the authenticated transport peer. Profile mismatches
receive `unsupported profile`; invalid credentials receive `unauthorized`.
Recognized, profile-valid requests and temporary protected storage failures
receive `busy` until the durable MLS acceptance handler is active.

## Consequences

- Join handlers have one shared bounded input and output codec with stable
  version, variant, and rejection codes.
- A syntactically valid request grants no membership or synchronization access.
- Owner advertisers reject unrecognized bearer credentials before MLS parsing,
  then authenticate the KeyPackage before durable admission work.
- Durable MLS state, approval flow, and acceptance remain separate increments.
