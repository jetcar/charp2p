# CharP2P application

Adaptive Tauri 2 client shell for Windows and Android.

```powershell
pnpm install
pnpm dev
pnpm build
pnpm tauri dev
```

The current shell implements device onboarding and a local invitation preview.
Identity creation and restart detection use Rust commands and platform-protected
storage. Raw invitation payloads, canonical HTTPS links, and `charp2p://` links
are parsed and authenticated in Rust before any network access. Encrypted
recovery export and the final peer join remain later increments. Accepted
invitations survive restarts: safe group metadata is indexed in SQLite while
the signed bearer credential remains in platform-protected storage.

The pending-group screen can run a bounded Kademlia provider search with the
restored device identity. Release builds will use the versioned built-in
bootstrap list. During local development, set `CHARP2P_BOOTSTRAP_NODES` to up to
16 semicolon-separated QUIC multiaddresses ending in `/p2p/<peer-id>`. With no
configured node, the app reports that a bootstrap node is required.
