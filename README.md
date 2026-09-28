# CharP2P

CharP2P is a private, peer-to-peer group chat for Windows and Android. A shared
invite opens the application, locates online group members through an open
peer-discovery network, and synchronizes messages directly or through a relay.

The project does not depend on one central chat service. The project-operated
node is one bootstrap and relay participant; community members can run
compatible nodes.

## Current status

The repository includes the shared Rust protocol and network foundation plus an
adaptive Tauri application shell for Windows and Android.

- [Product design](docs/product-design.md)
- [Technical design](docs/technical-design.md)
- [Windows application mockup](design/windows-chat.png)
- [Android tablet mockup](design/android-tablet-chat.png)
- [Complete Windows UI flow](design/windows/README.md)
- [Complete Android tablet UI flow](design/tablet/README.md)

## Development

Test the shared Rust crates:

```powershell
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Run the application shell:

```powershell
cd apps/charp2p-app
pnpm install
pnpm tauri dev
```

Initialize or run the Android target after installing Tauri's Android
prerequisites:

```powershell
pnpm tauri android init
pnpm tauri android dev
```

Architecture decisions are recorded in [docs/decisions](docs/decisions).

## MVP principles

- Private, invite-only groups.
- Windows and Android clients.
- Signed device and group identities.
- Encrypted and authenticated peer connections.
- End-to-end protected message payloads using an established cryptographic
  construction; no custom cryptography.
- Open DHT-based discovery with bootstrap nodes, direct connections, and relay
  fallback.
- No central message storage.
- No public group directory or file transfer in the first release.
