# CharP2P

CharP2P is a private, peer-to-peer group chat for Windows and Android. A shared
invite opens the application, locates online group members through an open
peer-discovery network, and synchronizes messages directly or through a relay.

The project does not depend on one central chat service. The project-operated
node is one bootstrap and relay participant; community members can run
compatible nodes.

## Current status

The repository is implementing the shared Rust protocol core and network
foundation from the approved product and technical designs.

- [Product design](docs/product-design.md)
- [Technical design](docs/technical-design.md)
- [Windows application mockup](design/windows-chat.png)
- [Android tablet mockup](design/android-tablet-chat.png)
- [Complete Windows UI flow](design/windows/README.md)
- [Complete Android tablet UI flow](design/tablet/README.md)

## Development

The implementation uses a shared Rust core. Tauri application shells for
Windows and Android will be added after the core protocol contracts are proven.

```powershell
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
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
