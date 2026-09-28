# ADR-007: Platform-protected device identity storage

## Status

Accepted

## Date

2026-09-28

## Context

The device Ed25519 private key must survive restarts without being written to
the SQLite event store, normal application files, logs, or the webview. Windows
and Android provide different native credential facilities.

## Decision

Use `keyring-core` behind a Rust-only application adapter. Use Windows
Credential Manager through `windows-native-keyring-store` on Windows. Use an
Android app-private SharedPreferences vault encrypted by a key held in Android
Keystore through `android-native-keyring-store` on Android.

Set Windows credential persistence to `Local` so the device identity survives
restarts but does not roam to other Windows devices through enterprise or
Microsoft-account credential synchronization.

Persist one versioned, bounded binary record containing the local display name
and the libp2p protobuf encoding of the Ed25519 private key. Limit the record to
512 bytes. Erase transient secret buffers on drop with `zeroize`. Return only
the display name and derived peer ID across the Tauri command boundary.

Serialize identity creation with an application mutex and refuse to replace an
existing identity. Recovery export and identity replacement require separate,
explicit flows.

## Consequences

- The private key does not enter the JavaScript runtime or routine app storage.
- Windows and Android use their native protected-storage mechanisms.
- A damaged record fails closed instead of silently generating a new identity.
- Removing operating-system credentials can make local group access
  unrecoverable without an encrypted recovery copy.

## Sources

- https://docs.rs/keyring-core/1.0.0/keyring_core/
- https://docs.rs/windows-native-keyring-store/1.1.0/windows_native_keyring_store/
- https://docs.rs/android-native-keyring-store/1.0.0/android_native_keyring_store/
- https://developer.android.com/privacy-and-security/keystore
- https://docs.rs/libp2p-identity/0.3.0/libp2p_identity/struct.Keypair.html
