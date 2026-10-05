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
encrypts and authenticates the complete snapshot with XChaCha20-Poly1305, a
fresh random 192-bit nonce, fixed domain-separated associated data, and a
versioned envelope. Its random 256-bit wrapping key stays in platform-protected
storage. Missing keys, invalid envelopes, and failed authentication stop startup
instead of discarding or replacing the stored state. No snapshot bytes enter
logs, diagnostics, or ordinary backups without that protection.

SQLite schema version 6 reserves one singleton ciphertext record, bounded to
the maximum snapshot plus encryption-envelope overhead. The storage layer
atomically replaces this opaque record and never receives plaintext provider
state. Each application provider mutation snapshots the preceding state, then
restores it if the operation, encryption, or durable replacement fails.
Mutations represented by signed group events persist that event and the
resulting encrypted snapshot in one SQLite transaction. A pending join stores
its bounded public KeyPackage alongside the snapshot containing the matching
private material; creation and completion of that pair are transactional.
Cancelling or expiring a pending invitation deletes the one-time KeyPackage
from the provider, then atomically removes its public index and stores the
reduced encrypted snapshot before the bearer invitation is discarded.

## Consequences

- Pending one-time KeyPackages and joined MLS groups can survive provider
  reconstruction without changing the pinned cryptographic profile.
- Local corruption is rejected before unbounded provider records are restored.
- Android device validation remains required.
