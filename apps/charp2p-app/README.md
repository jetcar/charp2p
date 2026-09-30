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

Windows and Android register `charp2p://` as an application link. Cold-start
and already-running link deliveries open the existing verified join preview;
Windows forwards links to one application instance. Debug Windows builds
register the scheme at startup. Installed release builds use the bundle's
protocol registration.

The pending-group screen can run a bounded Kademlia provider search and direct
QUIC reachability check with the restored device identity. An owner with an
active invitation advertises its opaque rendezvous key while the app is
running, through the invitation expiry. Release builds will use the versioned
built-in bootstrap list. During local development, set
`CHARP2P_BOOTSTRAP_NODES` to up to 16 semicolon-separated QUIC multiaddresses
ending in `/p2p/<peer-id>`. With no configured node, the app reports that a
bootstrap node is required.

The ready screen can create and restore a first local group, then issue and
copy signed custom-URI invitations. Group-root keys and issued bearer
credentials use the platform keyring; SQLite stores their non-secret indexes
and invitation defaults. Expired invitations are removed from both stores.
Revocation events and the initial protected membership event remain later
increments. Until the groups list is implemented, the backend enforces one
locally created group so extra protected roots cannot become hidden from the
interface.
