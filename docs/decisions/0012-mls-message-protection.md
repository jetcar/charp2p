# ADR-012: MLS message protection

## Status

Accepted

## Date

2026-09-28

## Context

CharP2P needs end-to-end protection that remains sound when peers synchronize
through untrusted transports, members join asynchronously, and owners remove a
member or device. A bespoke sender-key protocol would require CharP2P to define
and audit key distribution, replay handling, epoch transitions, and recovery
from concurrent membership changes.

## Decision

Use Messaging Layer Security as specified by RFC 9420 through OpenMLS 0.9. Pin
profile version 1 to
`MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`; clients reject other
ciphersuites for this profile instead of silently downgrading. Carry version 1
in an authenticated MLS group-context extension from the RFC 9420 private-use
range and require every leaf to advertise support. Include the ratchet-tree
extension in Welcome messages created by both original and joined members so a
joining peer does not require a central delivery service to fetch the public
tree.

Use one wrapper to reject a mismatched ciphersuite from the public Welcome
header before OpenMLS processes it, apply the profile join configuration, and
validate the decrypted group context before returning unpersisted staged state.
Validate every staged commit before merging it. Validate restored group state,
including the ratchet-tree join configuration, before use. OpenMLS consumes a
matching one-time KeyPackage while decrypting a Welcome; a Welcome rejected
after decryption therefore requires the joining device to publish a fresh
KeyPackage.

Treat every authorized device as a separate MLS leaf. Bind the CharP2P device
peer ID into a domain-separated, versioned MLS Basic Credential. Reject
unscoped, malformed, oversized, and future-version credential identities.
Validate the extracted device ID against signed membership events before
accepting the leaf. The stable CharP2P group ID stays the application identity;
its canonical bytes are also the MLS group ID so persisted state can be loaded
without a separate secret mapping. The MLS epoch remains protocol state. Group
creation initializes the owner's leaf with the creating device credential and
fails closed if restored state names a different owner device.

Before an owner stages a member addition, bound the encoded KeyPackage to 128
KiB, parse exactly one value, and require OpenMLS signature, structure, and
lifetime validation. Require the pinned ciphersuite and exact profile version 1
leaf capabilities. Finally require the signed device credential to equal the
peer ID authenticated by the libp2p transport. These checks validate the
KeyPackage source but do not authorize its invitation or membership.

Generate outbound KeyPackages through the same profile wrapper. Require the
caller-supplied signing credential to name the local device, set the exact
profile capabilities, let OpenMLS create and store the one-time private
material, bound and encode the public package, and run it through the inbound
validator before use. Keep the encoded package in a zeroing, non-cloneable
buffer, then transfer that buffer directly into the bounded join request.

Prepare an accepted addition as a pending OpenMLS commit and bounded Welcome;
do not advance the owner's epoch in the preparation step. The application must
durably publish the Commit through the signed group event graph, then explicitly
merge the pending commit, and only then return the Welcome. Preparation errors
after OpenMLS stages a commit clear that pending state. If durable event
publication fails, the application explicitly aborts the prepared admission.
Keep the encoded Commit and Welcome in zeroing, non-cloneable buffers and redact
their contents from debug output.

Use the shared profile provider's bounded, versioned snapshots as the boundary
for application persistence. Encrypt and authenticate each complete snapshot
before writing it outside memory, keep its wrapping key in platform-protected
storage, and replace it atomically. Keep signature private keys and exported
recovery material protected. Never enable OpenMLS content or crypto debug
features in application builds. ADR-016 defines the snapshot format and limits.

The initial prototype fixes and authenticates the profile configuration,
rejects mismatched state, and verifies group creation, chained asynchronous
member admission through self-contained Welcomes, and authenticated encrypted
application messages across distinct providers.

## Consequences

- Membership changes and message protection use a reviewed standard rather
  than a CharP2P-specific cryptographic construction.
- Removing a leaf advances the MLS epoch and excludes it from future messages;
  previously received plaintext remains recoverable by that device.
- Group operation ordering and fork resolution must be defined before joins
  are connected to the append-only event graph.
- Every application path that merges a staged commit must apply the profile
  validator first; unit tests cover removal of the authenticated profile
  marker.
- Encrypted atomic storage for provider snapshots, signed membership
  authorization, state backup, and protocol test vectors remain required before
  invitation acceptance can create a membership.
- Profile version 1 rejects encoded MLS messages above 128 KiB before parsing.
  Self-contained Welcomes therefore have a size-dependent group limit; the
  supported member count remains to be set from worst-case measurements.
- OpenMLS builds Android targets in upstream CI but does not test them. The
  selected provider and profile require an Android target build and device test
  before application integration is complete.

## Sources

- https://www.rfc-editor.org/rfc/rfc9420
- https://docs.rs/openmls/0.9.0/openmls/
- https://book.openmls.tech/user_manual/create_group.html
- https://github.com/openmls/openmls/security
