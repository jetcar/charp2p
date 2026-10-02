# ADR-002: Signed binary invitations

## Status

Accepted

## Date

2026-09-27

## Context

An invitation must be compact enough for links and QR codes, authenticate all
preview fields before they are displayed, carry an opaque discovery secret,
expire predictably, and remain independent of any project-operated server.

The group root identity must remain separate from member device identities so a
device can be revoked without changing the group identifier.

## Decision

Encode versioned invitation claims with Postcard, sign the exact encoded claims
with the group's Ed25519 root key, and encode the signed envelope as unpadded
URL-safe Base64.

Invitation version 2 prepends the domain separator `charp2p-invitation-v2`
before signing. Limit the
encoded payload to 8 KiB before decoding. Authenticate the group and inviter
display names, the inviter device peer ID, expiry, history policy, reuse policy,
group root public key, random invitation identifier, and 32-byte discovery
secret. A joining client considers only DHT providers whose authenticated
libp2p peer ID equals this root-authorized inviter device.

Use `libp2p-identity` for Ed25519 keys and verification and the operating-system
random source through `getrandom`. Do not implement cryptographic primitives in
the project.

## Alternatives considered

### JSON payload

Readable, but materially larger for links and requires a separate canonical
JSON profile before signatures are deterministic.

### Server-issued opaque token

Compact, but makes joining depend on one service and prevents independent nodes
from validating invitations.

### Device key as group root

Simple initially, but revoking or losing the creator device would also change
the stable group identity.

## Consequences

- Peers validate invitations without contacting a central authority.
- Invitation links are bearer credentials and must be kept out of logs.
- A holder who copies an invitation cannot impersonate its authorized inviter
  without also controlling that device identity.
- Reusable and single-use semantics still require membership-event validation;
  the signed payload alone cannot prevent concurrent reuse.
- Future wire changes require a new version and domain separator.

## Sources

- https://docs.rs/libp2p-identity/0.3.0
- https://docs.rs/postcard/1.1.3
- https://docs.rs/getrandom/0.4.3
- https://www.rfc-editor.org/rfc/rfc4648#section-5
