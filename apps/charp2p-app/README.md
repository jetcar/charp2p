# CharP2P application

Adaptive Tauri 2 client shell for Windows and Android.

```powershell
pnpm install
pnpm dev
pnpm build
pnpm tauri dev
```

The checked-in Android Studio project supports arm64, armv7, x86, and x86_64.
Build an arm64 debug APK with `pnpm tauri android build --debug --apk` after
installing Tauri's Android prerequisites. Windows build hosts must allow
symbolic-link creation, normally through Developer Mode.

The shell implements device onboarding, owned and joined groups, messaging,
members and devices, network status, and settings. Its group list restores
every owned and joined membership, keeps them accessible in one session, and
opens another invitation without hiding existing groups.
The Privacy and How identity works pages, linked from the onboarding screen and
the group navigation, explain local message storage, observable network
metadata, relay limits, device-key continuity, and identity backup from inside
the Windows and Android interface.
Identity creation and restart detection use Rust commands and platform-protected
storage. Raw invitation payloads, canonical HTTPS links, and `charp2p://` links
are parsed and authenticated in Rust before any network access. Settings can
export a passphrase-encrypted identity backup as a file or text, and onboarding
can restore the device name and identity key from it.
Accepted invitations survive restarts: safe group metadata is indexed in SQLite
while the signed bearer credential remains in platform-protected storage. Invitation
version 2 also pins the root-authorized inviter device; discovery ignores
providers with another authenticated peer identity.

Windows and Android register `charp2p://` as an application link. Cold-start
and already-running link deliveries open the existing verified join preview;
Windows forwards links to one application instance. Debug Windows builds
register the scheme at startup. Installed release builds use the bundle's
protocol registration.

The pending-group screen can run a bounded Kademlia provider search and an
authenticated direct, local-network, or relayed reachability check with the
restored device identity. While the app runs, it advertises the opaque
rendezvous keys of every owned group in the background, not only the group
currently open: active invitation keys until they expire, plus the retained
keys that already admitted members use to rediscover the owner. Release builds
will use the versioned built-in bootstrap list. The Network page can add and
remove up to 8 device-local community nodes (ADR-038), and during local
development `CHARP2P_BOOTSTRAP_NODES` accepts semicolon-separated
multiaddresses ending in `/p2p/<peer-id>`; the combined list holds at most 16
nodes. Nodes connect over QUIC with a Noise and Yamux TCP fallback (ADR-047)
for networks that block UDP. With no configured node, the app reports that a
bootstrap node is required.

Owner advertisements request a Circuit Relay v2 reservation from configured
bootstrap nodes. The relay transport uses Noise and Yamux over the authenticated
relay connection, so discovered peers can establish the existing join and sync
protocols when the owner's direct QUIC address is not reachable.

The ready screen can create and restore local groups, then issue and
copy signed custom-URI invitations. Group-root keys and issued bearer
credentials use the platform keyring; SQLite stores their non-secret indexes
and invitation defaults. Group creation also initializes the owner's durable
MLS group and rolls the local group back if that secure setup fails. Existing
local groups are reconciled with MLS state at startup. Expired invitations are
removed from both stores. The owner can explicitly revoke an active invitation;
the bearer and index are removed immediately. Its protected rendezvous key is
retained so already admitted members can still discover the owner, while new
join attempts are rejected. The owner view renders the signed invitation as a
QR code for Windows and Android handoff without sending it to a QR service.
Invitations always expire and can be reusable or single-use; a consumed
single-use invitation is retired but still lets its admitted device finish
joining. Groups can require owner approval, in which case join requests wait in
the Members & devices view until the owner approves or declines them. Members
see messages sent after they joined: the backend rejects the retained-history
creation option so the UI cannot promise unenforced access controls.
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
messages it already stored. A device can own several local groups, each with
its own group-root key, alongside multiple joined groups. Expired pending joins
also remove their retained one-time MLS key material before the invitation is
discarded.

The owner and joined-group screens can create bounded text messages as MLS
private application messages and persist each signed `MessageCreated` event
atomically with sender ratchet state. They also keep an event-bound encrypted
local display copy and restore the timeline after restart. Timeline actions can
copy text, reply to a message (the reply reference travels inside the protected
payload), edit this device's own messages through a signed `MessageEdited`
event, and delete them for everyone through a signed `MessageDeleted`
tombstone. Hiding a message removes only the readable copy on this device; a
durable local marker prevents the retained signed event from recreating it,
and other members keep their copies. A durable acknowledgement head distinguishes
messages saved only on this device from messages accepted by at least one peer.

Joined members upload bounded batches of their own signed message events to the
pinned owner after each pull. The owner verifies that every event author
matches the authenticated connection, persists accepted events idempotently,
and makes them available to other members through later pulls. Creating a
joined-member message triggers an immediate synchronization attempt; the
minute retry loop retains locally saved messages while the owner is offline.
After storing new events, an owner sends a data-free `EventsAvailable` notice
over existing connections to current members (ADR-049), and a member that
accepts it from its pinned owner pulls at once. Joined groups that are not
open are synchronized in the background every five minutes.
Successful synchronization times persist and remain visible after restart.
The current session status also identifies direct, local-network, and relayed
connections.
An active group screen refreshes its encrypted local timeline every two
seconds, so the owner sees newly accepted member messages without reopening the
group. Timeline reads return pages of at most 256 messages; "Show earlier
messages" loads the page before the oldest shown message by its creation time
and event ID.

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
shows availability separately, labels authenticated reachability as direct,
local-network, or relayed, and restores the completed joined-group card after
restart. The joined-group card can use that protected key to rediscover
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
not yet provide. Owners can remove non-owner devices from this view, approve or
decline pending join requests, grant or withdraw a member's permission to
request invitations (ADR-036), allow a removed device to be admitted again
(ADR-034), and refresh the group keys (ADR-045). Any device can block another
device's messages locally.
