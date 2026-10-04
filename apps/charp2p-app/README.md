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
recovery export remains a later increment.
Accepted invitations survive restarts: safe group metadata is indexed in SQLite
while the signed bearer credential remains in platform-protected storage. Invitation
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
removed from both stores. The owner can explicitly revoke an active invitation;
the bearer and index are removed and its live network advertisement stops. The
owner view renders the signed invitation as a QR code for Windows and Android
handoff without sending it to a QR service.
The current secure profile exposes only expiring reusable invitations, direct
invite-based admission, and messages sent after joining. The backend rejects
single-use, manual-approval, and retained-history creation options so the UI
cannot promise unenforced access controls.
Inbound join requests are checked against this protected issuance state before
MLS processing. The advertiser then verifies the bounded MLS KeyPackage,
requires the pinned profile, and binds its signed device credential to the
authenticated connection. An accepted request publishes the MLS Commit as a
signed `MemberAdded` event and atomically persists the advanced MLS provider
state before returning the Welcome. The encrypted accepted response is cached
with that transaction, so retrying the exact request after a lost connection or
owner restart returns the same Welcome without adding the device twice. A
different KeyPackage for an already admitted device is rejected. MLS group
state and one-time private material survive restarts in an authenticated
encrypted SQLite snapshot whose
wrapping key stays in the platform keyring. New owner groups atomically store a
signed `GroupCreated` event with their initial encrypted MLS provider state, so
later owner events begin from one durable causal root. The owner can remove a verified
device from the Members & devices view. The signed `MemberRemoved` event,
advanced MLS state, and durable re-admission block commit atomically; cached
join responses are deleted so active reusable invitations cannot restore the
removed device. Removing a device prevents future access but cannot erase
messages it already stored. Until the groups list is
implemented, the backend enforces one locally created group so extra protected
roots cannot become hidden from the interface.

The owner and joined-group screens can create bounded text messages as MLS
private application messages and persist each signed `MessageCreated` event
atomically with sender ratchet state. They also keep an event-bound encrypted
local display copy and restore the timeline after restart. Timeline actions can
copy text or delete only the readable copy on this device. A durable local
marker prevents the retained signed event from recreating a deleted copy;
other members keep their copies. Delivery receipts remain a later increment.

Joined members upload bounded batches of their own signed message events to the
pinned owner after each pull. The owner verifies that every event author
matches the authenticated connection, persists accepted events idempotently,
and makes them available to other members through later pulls. Creating a
joined-member message triggers an immediate synchronization attempt; the
minute retry loop retains locally saved messages while the owner is offline.
An active group screen refreshes its encrypted local timeline every two
seconds, so the owner sees newly accepted member messages without reopening the
group. Timeline reads are bounded to the latest 256 messages and disclose when
older locally retained messages are outside the current view.

While an owner advertises an active invitation, authenticated devices already
present in its MLS group can request bounded synchronization summaries, event
identifier pages, and signed events. Devices outside that MLS membership get
only the stable unauthorized response. Immediately after joining, the new
device uses the existing authenticated connection to pull and persist the
owner's verified signed events.

The joining client now prepares and reuses one durable MLS KeyPackage, finds
the invitation's pinned owner through the DHT, exchanges the join request over
authenticated QUIC, validates the returned Welcome, and atomically replaces
the pending private material with joined MLS group state. Authenticated display
metadata is then promoted from pending to joined storage, the bearer invitation
is replaced by its opaque derived discovery key in protected storage, and an
interrupted post-join cleanup can resume without repeating the network
exchange. The derived key supports later peer discovery but cannot authorize
another join. The pending-group screen exposes the secure join action,
shows availability separately, and restores the completed joined-group card
after restart. The joined-group card can use that protected key to rediscover
the pinned owner and retry a bounded authorized synchronization without keeping
the bearer invitation. It synchronizes once after loading, continues once per
minute while the app runs, and keeps manual retry available. Readable MLS
application messages are authenticated against their signed event authors,
stored as event-bound encrypted local copies, and shown in the joined-group
timeline. Messages from epochs before this device joined remain opaque.
Synchronized membership commits advance existing members before message
decryption, so messages continue to fan out after more members join.
The group screen also exposes a responsive Members & devices view backed by the
current verified MLS leaf credentials. It identifies the local device and owner
device without inventing account-level names or presence that the protocol does
not yet provide. Owners can remove non-owner devices from this view.
