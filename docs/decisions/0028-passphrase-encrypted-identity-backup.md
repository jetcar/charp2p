# ADR-028: Passphrase-encrypted device identity backup

## Status

Accepted

## Date

2026-10-06

## Context

The device private key lives only in platform-protected storage (ADR-007).
Losing that storage loses the device identity, and the product requires an
explicitly encrypted backup flow that a user can store outside the device and
restore on a new installation. The backup must not depend on a project server
or on a key held by the operating system that is lost with the device.

## Decision

Export a bounded binary record, at most 1 KiB, that contains:

- a magic prefix `charp2p-identity-backup` and a format version byte;
- a random 16-byte Argon2id salt and a random 24-byte XChaCha20-Poly1305 nonce;
- the XChaCha20-Poly1305 ciphertext of a postcard record holding the display
  name and the libp2p protobuf encoding of the Ed25519 device key.

The 32-byte content key is derived from the user's passphrase with Argon2id
(version 0x13) using fixed version-1 parameters: 64 MiB of memory, 3 passes,
and 1 lane. The parameters are tied to the format version rather than read
from the record, so a crafted backup cannot request unbounded work. The magic,
version, salt, and nonce are authenticated as associated data.

Passphrases must contain at least 12 characters and at most 1024 bytes.
Decryption failures, a wrong passphrase, and tampering return one error. A
restored key must decode as an Ed25519 device identity before it is accepted.
Plaintext, derived keys, and passphrase copies are zeroized on drop.

The backup contains only the device identity. Group state, owner group roots,
and messages are not included; a restored device keeps its peer ID but must be
re-admitted or resynchronize groups by the existing flows.

## Consequences

- Possession of the backup file alone does not reveal the device key; a strong
  passphrase is required to resist offline guessing.
- Memory-hard key derivation makes export and restore take noticeable time on
  low-end phones.
- Restoring the same backup on two devices creates two installations with one
  peer ID; the restore flow must warn that the original device should no longer
  be used.
- Group-state backup is a separate later decision.

## Sources

- https://www.rfc-editor.org/rfc/rfc9106
- https://docs.rs/argon2/0.6.0/argon2/
- https://docs.rs/chacha20poly1305/0.10.1/chacha20poly1305/
