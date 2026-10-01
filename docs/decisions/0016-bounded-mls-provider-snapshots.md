# ADR-016: Bounded MLS provider snapshots

## Status

Accepted

## Date

2026-10-01

## Context

OpenMLS persists group state and one-time KeyPackage private material through a
storage provider. The selected Rust crypto provider normally uses an in-memory
store, so recreating it after restart would make pending KeyPackages and joined
groups unusable. Persisting its internal records without an outer bound would
also allow corrupt local data to trigger excessive allocation before OpenMLS
validation.

## Decision

Define one shared `ProfileProvider` that combines the established RustCrypto
implementation with OpenMLS memory storage. Export and restore its records
through a deterministic, versioned binary snapshot. Bound the complete snapshot
to 8 MiB, record count to 4,096, keys to 64 KiB, and values to 2 MiB. Check all
declared lengths before allocation, reject duplicate keys and trailing bytes,
and return exported bytes in zeroizing memory.

The snapshot contains MLS private keys and epoch secrets. It is an interchange
boundary for application persistence, not a safe at-rest format. The client
must encrypt and authenticate the complete snapshot with an established AEAD,
keep the wrapping key in platform-protected storage, and replace snapshots
atomically. No snapshot bytes may enter logs, diagnostics, or ordinary backups
without that protection.

## Consequences

- Pending one-time KeyPackages and joined MLS groups can survive provider
  reconstruction without changing the pinned cryptographic profile.
- Local corruption is rejected before unbounded provider records are restored.
- Application integration still requires authenticated encryption, atomic
  replacement, rollback handling, and Android device validation.
