# ADR-063: Disable Android automatic app-data backup

## Status

Accepted

## Date

2026-10-28

## Context

Android enables automatic app-data backup by default. CharP2P stores its local
event database beside device-bound secrets protected by Android Keystore.
Restoring only the files can leave protected records unreadable. Transferring a
complete installation can clone a device identity, MLS state, invitation
credentials, and local message history onto a second device without the
protocol's device-admission flow.

CharP2P already provides an explicit, passphrase-encrypted identity backup.
That backup intentionally excludes group state and requires a normal secure
join before the restored installation receives current group state.

## Decision

Set `android:allowBackup` to `false`. Also provide Android 11-and-earlier full
backup rules and Android 12-and-later data extraction rules that exclude every
app-private, device-protected, database, preferences, and external-files domain
from cloud backup and device-to-device transfer.

Keep identity recovery in the explicit encrypted backup flow. Do not add an
Android backup domain unless its restore behavior, device identity semantics,
and secret dependencies are specified and tested first.

## Alternatives considered

- Keep Android defaults: rejected because almost all app data would be eligible
  for backup and restore without CharP2P validating the resulting state.
- Back up only the SQLite database: rejected because it references protected
  secrets and includes local message and membership state.
- Permit device-to-device transfer: rejected because the transfer can duplicate
  one cryptographic device identity instead of admitting a new device.

## Consequences

- Android system restore and device migration do not restore CharP2P data.
- Users must create and retain an encrypted identity backup, then rejoin or
  resynchronize groups on the restored installation.
- Backup behavior is explicit on both sides of Android 12's rules change.

## Sources

- https://developer.android.com/privacy-and-security/risks/backup-best-practices
- https://developer.android.com/identity/data/autobackup
