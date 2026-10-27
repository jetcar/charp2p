# ADR-057: Support serviced Windows 11 releases and Android 10 or later

## Status

Accepted

## Date

2026-10-27

## Context

CharP2P depends on an operating-system webview and protected credential
storage. Supporting an operating system after its browser engine or security
updates end would expose the application UI and device identity to known
platform vulnerabilities even when the Rust protocol implementation remains
current.

Windows 10 Home and Pro reached end of support on 2025-10-14. Microsoft lists
Windows 11 releases and their edition-specific servicing dates. Tauri uses the
WebView2 runtime on Windows.

The generated Android project previously allowed Android 7.0 (API level 24).
Current Chrome support, which shares Chromium with Android WebView, requires
Android 10 or later. Android build metadata can enforce that floor with
`minSdk`; the existing project targets API level 37, above Google Play's 2026
requirement of API level 36 for new apps and updates.

## Decision

The Windows MVP supports x86-64 Windows 11 releases that are still receiving
Microsoft security updates for their edition. The initial release test matrix
starts with Windows 11 25H2 and the current generally available Windows 11
release. Windows 10 and Windows 11 releases outside their servicing window are
unsupported. A supported, current WebView2 Evergreen Runtime is required.

The Android MVP supports Android 10 (API level 29) and later. The Gradle
`minSdk` is 29, so the package cannot be installed on older versions. Release
validation covers API 29 and the current target API on both phone and tablet
layouts; intermediate API levels are covered by automated or emulator smoke
tests when the release toolchain provides images.

Support follows the operating-system vendor's security servicing window. A
future OS release remains provisional until the application build, protected
identity storage, invitation opening, local persistence, and peer networking
smoke tests pass on it.

## Alternatives considered

### Keep Android 7.0 as the minimum

This matches Tauri's broad platform floor and reaches older hardware, but those
devices cannot receive the current Chromium engine and are unsuitable for a
security-sensitive webview application.

### Support Windows 10 with WebView2

The runtime can still work on Windows 10, but normal Home and Pro servicing has
ended. Supporting only enrolled ESU and LTSC variants would complicate the
public support statement and test matrix.

### Pin one Windows feature release indefinitely

A fixed floor is easy to state but becomes insecure when that release leaves
servicing. Tying support to Microsoft's servicing window keeps the security
condition explicit.

## Consequences

- Android 7, 8, and 9 devices can no longer install CharP2P.
- Supported Windows devices must remain on a serviced Windows 11 release and
  receive WebView2 updates.
- Release checks need at least one minimum-version Android emulator and the
  current Android target, plus the oldest supported and current Windows 11
  releases.
- Version support can advance without changing the wire protocol or stored
  group data.

## Sources

- https://v2.tauri.app/start/prerequisites/#webview2
- https://learn.microsoft.com/en-us/windows/release-health/supported-versions-windows-client
- https://developer.android.com/guide/practices/compatibility#platform-version
- https://developer.chrome.com/docs/webview/#webview-updates
- https://support.google.com/chrome/a/answer/7100626#android
- https://developer.android.com/google/play/requirements/target-sdk
