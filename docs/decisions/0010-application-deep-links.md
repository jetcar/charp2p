# ADR-010: Application deep-link delivery

## Status

Accepted

## Date

2026-09-28

## Context

Invitation links must open the installed Windows or Android application both
from a cold start and while it is already running. Operating-system protocol
registration only routes input; it does not authenticate invitation content.
The production HTTPS association cannot be completed while the public join
host and release signing identities are undecided.

## Decision

Use Tauri's maintained deep-link plugin to statically register the `charp2p`
custom scheme on Windows and Android. Read the launch URL during startup and
subscribe to later open-URL events. On Windows, use Tauri's single-instance
plugin with deep-link integration so later activations reach the existing
window.

Accept only `charp2p://join/<credential>` at the UI boundary, then send the
whole input through the existing bounded Rust invitation parser and signature
verification before showing authenticated metadata. Do not log delivered URLs.

Keep the canonical fragment-based HTTPS format in the protocol. Register it as
a verified Android App Link only after a production host, `assetlinks.json`,
package signing certificate, and fallback page exist.

## Consequences

- Custom invitation links open the same verification flow as pasted links.
- Cold-start and already-running delivery work without duplicating Windows app
  state.
- Scheme ownership does not confer trust; forged or malformed links are still
  rejected locally.
- HTTPS link opening remains a release-infrastructure gate.

## Sources

- https://v2.tauri.app/plugin/deep-linking/
- https://v2.tauri.app/plugin/single-instance/
- https://developer.android.com/training/app-links/verify-android-applinks
