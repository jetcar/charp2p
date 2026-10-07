# CharP2P MVP threat model

## Scope

This document covers implementation gate 5 of the technical design: joins,
removal, conflicting membership events, and lost owner keys. It describes the
protocol as implemented in `crates/*` and `apps/charp2p-app/src-tauri`, not a
future design. Where a control is missing, the gap and its current mitigation
are stated explicitly.

## Assets

- Device identity key (Ed25519). It authenticates libp2p connections, signs
  group events, and is bound into the device's MLS credential.
- Group root key. It signs invitation capabilities and defines the group ID.
  Only the owner device holds it (ADR-011).
- MLS group state and the provider snapshot wrapping key (ADR-012, ADR-016).
- Bearer invitations and their derived rendezvous keys (ADR-008, ADR-013,
  ADR-025).
- Signed event history and encrypted local message copies.

## Adversaries

- **Network attacker**: observes, drops, delays, or replays traffic; operates
  DHT, bootstrap, or relay nodes.
- **Link holder**: a person who obtained an invitation link, legitimately or
  not.
- **Malicious member**: a device currently or formerly admitted to the group.
- **Device thief**: obtains an unlocked or locked device, or its SQLite files.

The owner device is trusted for its own group. A compromised owner device
controls the group; the MVP does not defend members against it.

## Trust structure

The MVP has exactly one committer per group: the owner device that holds the
group root. Invitation version 2 pins that device's peer ID under the root
signature. Members synchronize only with the pinned owner and accept
`MemberAdded`/`MemberRemoved` commits only through pulls from it. The owner
accepts member uploads only for `MessageCreated` and `MessageEdited` events
signed by the authenticated transport peer (`accept_pushed_events`). No member
can author a membership change that another device will apply.

## Joins

| Threat | Control | Residual risk |
| --- | --- | --- |
| Forged or altered invitation | Bounded parser; root signature over the invitation including the pinned owner, expiry, and preview metadata; tamper vectors in `protocol_vectors.rs`. | None known within the signature scheme. |
| Expired invitation | Expiry checked by the joining client and again by the owner. | Clock skew can shift the boundary. |
| Revoked invitation | Owner deletes the protected bearer before its index under the storage lock and stops the listener (ADR-021). Authorization requires both records and a constant-time bearer match. | DHT provider records stay until TTL; they reveal reachability only. |
| Rogue peer advertising the rendezvous key | Search results from any provider other than the pinned owner are ignored; the libp2p connection authenticates that peer ID. | A flood of provider records can delay discovery (bounded searches, 32-provider cap). |
| Link leaked to an unintended person | None beyond expiry and revocation: the MVP profile admits any valid bearer directly (ADR-018). | Unintended join until the owner revokes the link and removes the device. Approval-based joins are deferred. |
| KeyPackage substitution or credential theft | Owner verifies one bounded KeyPackage with OpenMLS, the pinned ciphersuite and profile, and requires its credential to equal the authenticated peer. | None known. |
| Duplicate or replayed join request | Admission is idempotent per device and exact KeyPackage hash; a different KeyPackage for an admitted device is rejected (ADR-019). | A device that lost its MLS state cannot rejoin until the owner removes it. |
| Welcome from a malicious peer | The client accepts a Welcome only from the pinned owner connection, validates every leaf, the ciphersuite, and the profile extension before persisting. | None known. |
| Oversized join messages | 8 KiB invitation, 128 KiB KeyPackage and Welcome bounds enforced before allocation; 30 s timeout; 16 streams per connection (ADR-015). | Owner CPU spent on bounded verification. |
| Bearer and secret leakage | Discovery secret never reaches the webview; secret-bearing buffers are redacted and zeroed; diagnostics exclude invitations and keys. | A link pasted into another app is outside CharP2P's control. |

## Removal

| Threat | Control | Residual risk |
| --- | --- | --- |
| Removed device reads future messages | Owner stages an MLS remove commit, publishes it as a signed `MemberRemoved` event, and stores event, snapshot, and removed marker in one transaction (ADR-020). Members apply it before materializing later messages. | Members that have not yet synchronized still encrypt to the old epoch until they pull the commit. |
| Removed device rejoins with a reusable link | Admission checks the removed-device index before cached responses or MLS processing; the cached Welcome is deleted in the removal transaction. | Re-admission needs a future owner unblock flow. |
| Removed device keeps synchronizing | The owner serves synchronization only to peers in its current MLS membership. | It can still find the owner through its retained rendezvous key (ADR-025). |
| Erasure of already received data | Not provided. | Removal and deletion never erase copies already held by any device. |
| Member leaves while the owner is offline | Leave is device-local and deletes the group's keys and messages on that device (ADR-027). | The owner still lists the device as a member until it removes it. |
| Compromised member device key | Owner removal advances the epoch. | The attacker keeps prior history and can impersonate the device until removal; identity is a device key, not a person. |

## Conflicting membership events

| Threat | Control | Residual risk |
| --- | --- | --- |
| Two commits for the same epoch | Only the owner device commits, sequentially and transactionally with its snapshot; pending commits are merged or aborted before the next. | A cloned owner device (see below) could fork the epoch; members apply whichever arrives first and fail the other. |
| Reused author sequence with different content | The event store rejects it as `SequenceConflict`; batches commit atomically. The rejected signed event is recorded per author (at most 64 sequences each) and the Members view flags the device as having signed conflicting events. | Only conflicts seen by this device are reported; conflicting copies held by other members are not exchanged. |
| Member-authored membership event | Owner rejects pushed events other than messages and edits; members apply a commit only when its signed author is the pinned owner device and OpenMLS validates the sender is a member whose credential equals that author. | None known. |
| Out-of-order or future-epoch commits | Commits are applied in author sequence; future epochs wait for their predecessor; a commit and its snapshot persist atomically (ADR-017). | A missing predecessor stalls the member until the owner serves it. |
| Past-epoch commits | Commits older than the local epoch are marked applied without replay (the Welcome already includes them). | Such a commit is not re-validated by MLS; its signature, author binding, and pinned-owner author are still checked. |
| Member-authored group metadata | `GroupMetadataChanged` is accepted only from the owner device that admitted the member; pushes of it are refused. | None known. |

## Lost owner keys

| Threat | Control | Residual risk |
| --- | --- | --- |
| Owner device lost or reset | Group root and MLS state live only in that device's protected storage (ADR-011). | The group can no longer admit, remove, rename, or relay: members synchronize only through the pinned owner, so the group stops exchanging new messages. Members keep their local history. |
| Identity backup restored after loss | The backup restores the device identity only, not group roots or MLS state (ADR-028). | A restored device has the owner's peer ID but cannot serve the group. Members cannot synchronize with it. A new group is the only recovery. |
| Owner identity restored while the original still runs | The restore flow warns to stop using the original device. | Two devices with one peer ID confuse discovery; only the one holding the group root can serve the group. |
| Stolen SQLite files | Group roots, bearers, rendezvous keys, and snapshot wrapping keys stay in platform-protected storage; SQLite holds encrypted snapshots and local copies (ADR-007, ADR-016). | An attacker with the unlocked platform account can read protected storage. |
| Owner administration-key rotation | Not implemented. The protocol keeps a root public key per group ID so rotation can be added. | No transfer of ownership in the MVP; multiple owners are an MVP exclusion. |

## Out of scope for the MVP

- An authorized member copying plaintext, screenshots, or received history.
- Network metadata visible to relays, DHT nodes, and members.
- Public node operation risks; these are covered by the "Before public node
  deployment" gates.
