# ADR-001: Rust core with Tauri 2 application shells

## Status

Accepted

## Date

2026-09-27

## Context

CharP2P needs one protocol implementation for Windows and Android, native access
to networking and secure storage, and an adaptive interface matching the
approved desktop and tablet designs. The networking plan uses libp2p, whose Rust
implementation provides the required identity, transport, discovery, relay,
and NAT traversal building blocks.

## Decision

Use a Rust workspace for shared domain, cryptographic identity, persistence,
synchronization, and libp2p networking. Use Tauri 2 application shells with a
TypeScript web UI for Windows and Android.

Keep the shared Rust core independent of Tauri. Tauri commands will be thin
adapters, allowing core protocol tests to run without a WebView or mobile SDK.

## Alternatives considered

### .NET MAUI

The host already includes .NET, and MAUI targets Windows and Android. It was not
selected because the planned libp2p stack is Rust-based; using MAUI would add a
second FFI boundary or require implementing the P2P stack independently.

### Flutter with a Rust core

Flutter provides strong adaptive UI support. It was not selected because it
requires an additional Dart toolchain and an explicit Rust FFI layer, while
Tauri can call Rust commands directly and still supports Windows and Android.

### Separate native Windows and Android applications

Separate shells maximize platform fidelity but duplicate navigation, state,
and presentation work before the protocol is proven.

## Consequences

- The same Rust protocol code and tests run for clients and community nodes.
- Windows uses WebView2; Android uses its system WebView.
- Android background networking may require a small native Kotlin plugin later.
- UI accessibility and adaptive breakpoints must be tested on both platforms.
- Rust, Node.js, Windows C++ build tools, and the Android SDK are required.

## Sources

- https://v2.tauri.app/start/
- https://v2.tauri.app/start/prerequisites/
- https://v2.tauri.app/develop/plugins/develop-mobile/
- https://libp2p.io/guides/getting-started-rust/
- https://docs.rs/libp2p-identity/0.3.0

