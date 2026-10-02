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
recovery export and the joined-group interface remain later increments. Accepted
invitations survive restarts: safe group metadata is indexed in SQLite while
the signed bearer credential remains in platform-protected storage. Invitation
version 2 also pins the root-authorized inviter device; discovery ignores
providers with another authenticated peer identity.

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
and invitation defaults. Group creation also initializes the owner's durable
MLS group and rolls the local group back if that secure setup fails. Existing
local groups are reconciled with MLS state at startup. Expired invitations are
removed from both stores.
Inbound join requests are checked against this protected issuance state before
MLS processing. The advertiser then verifies the bounded MLS KeyPackage,
requires the pinned profile, and binds its signed device credential to the
authenticated connection. An accepted request publishes the MLS Commit as a
signed `MemberAdded` event and atomically persists the advanced MLS provider
state before returning the Welcome. MLS group state and one-time private
material survive restarts in an authenticated encrypted SQLite snapshot whose
wrapping key stays in the platform keyring. Revocation events and the initial
protected membership event remain later increments. Until the groups list is
implemented, the backend enforces one locally created group so extra protected
roots cannot become hidden from the interface.

The joining client now prepares and reuses one durable MLS KeyPackage, finds
the invitation's pinned owner through the DHT, exchanges the join request over
authenticated QUIC, validates the returned Welcome, and atomically replaces
the pending private material with joined MLS group state. Authenticated display
metadata is then promoted from pending to joined storage, the bearer invitation
is deleted, and an interrupted post-join cleanup can resume without repeating
the network exchange. The pending-group screen exposes the secure join action,
shows availability separately, and restores the completed joined-group card
after restart.
