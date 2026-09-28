# ADR-011: Protected local group roots

## Status

Accepted

## Date

2026-09-28

## Context

Creating a group generates a long-lived root signing key. That private key
must survive restarts without entering the SQLite database, webview state,
logs, or diagnostics. Group display fields and invitation defaults are not
secret and need indexed local persistence.

The initial membership event and invitation issuance depend on the separate
message-protection decision, so local creation must not emit an unprotected
protocol event merely to complete the UI flow.

## Decision

Encode group-root Ed25519 keypairs with `libp2p-identity`, immediately wrap the
encoded bytes in zeroizing storage, and save them through the existing native
Windows or Android keyring adapter. Address each protected entry by the derived
group ID.

Store the group ID, validated display name, icon, new-member history policy,
join mode, invitation lifetime, and reusable-invitation default in a versioned
SQLite `local_groups` table. On every load, restore the protected root and
verify that its derived group ID matches the SQLite index.

Serialize device-identity, pending-invitation, and local-group protected-store
operations within the app and configure a bounded SQLite busy timeout. Bound
protected records while their buffers are zeroizing and before decoding.
During creation, commit metadata first, then write the protected root while the
operation lock is held. Roll back metadata if the protected write fails; after
an interrupted process, remove incomplete metadata that has no protected root.

Treat this as local group setup. Create the signed initial membership state and
invitations only after the selected end-to-end message-protection construction
can protect their payloads.

## Consequences

- Restarting the app preserves the same group fingerprint.
- SQLite backups alone cannot recover or impersonate a group owner.
- Metadata corruption or a mismatched protected key fails closed.
- Losing the protected key before creating a recovery copy loses group-owner
  authority.
- A locally created group is not advertised or joinable until protocol setup
  is completed.
- The current onboarding shell permits one locally created group; this bound
  can be lifted when the groups list exposes every stored root.

## Sources

- https://docs.rs/libp2p-identity/0.3.0
- https://docs.rs/keyring-core/1.0.0
