# CharP2P product design

## Product statement

CharP2P lets a person create a private group, share an invitation, and exchange
messages without a central chat database. Devices find one another through an
open discovery network and synchronize the group history held by group
members.

The first release targets small private groups. It does not promise continuous
delivery: if no group member is online, a joining device or an out-of-date
device waits until a member returns.

## User roles

### Group owner

The creator holds the initial group administration key. The owner can change
group details, issue and revoke invitations, approve membership when approval
is required, remove members, and revoke devices.

### Member

A member can read and send messages, synchronize permitted history, invite
others when granted permission, block a device locally, and leave the group.

### Node operator

A node operator can contribute DHT routing and optionally relay capacity. An
operator controls only their node: limits, logs, blocked peer identities, and
availability. A node operator does not become a group administrator.

## Primary flows

### Create a group

1. The user creates or unlocks a local device identity.
2. The user chooses a group name. The current secure profile shares messages
   sent after a member joins.
3. The app creates the group identity and initial membership state.
4. The app starts advertising an opaque discovery key while it is online.
5. The user can create an expiring invitation.

### Join from an invitation

1. The user opens an HTTPS app link or a `charp2p:` URI.
2. The app validates the invitation locally before contacting peers.
3. The join preview shows the group name, inviter identity, invitation expiry,
   requested permissions, and whether a group peer is currently reachable.
4. The user explicitly accepts.
5. The app searches for providers of the invitation's secret discovery key.
6. It tries direct connections and then relay addresses.
7. A connected member validates the signed invitation and returns the current
   membership state and allowed history.
8. The new device verifies every received event before displaying the group.

An invitation does not guarantee immediate joining. With no reachable group
member, the app retains the pending invitation and retries when opened or when
the operating system permits background work.

### Send and synchronize a message

1. The sender creates, protects, and signs a message event locally.
2. Connected members receive and verify it.
3. Peers compare synchronization summaries and request missing events.
4. Delivery state distinguishes local, shared with a peer, and observed by all
   currently known members. It must not claim permanent delivery.

### Remove a member

1. The owner issues a signed membership-removal event.
2. Connected peers stop accepting new events from the removed membership.
3. Group key material advances so the removed member cannot read future
   messages.
4. Previously copied messages cannot be remotely erased.

## Application pages

### 1. Welcome and identity

- Create a device identity.
- Restore an encrypted identity backup.
- Explain that losing every authorized device and backup can permanently lose
  access.

### 2. Groups

- Joined groups, pending invitations, unread counts, and last synchronization.
- Clear online, relayed, waiting, and offline states.
- Create group and Join from link actions.

### 3. Create group

- Name and optional icon.
- Whether new members receive no history, history since invitation, or all
  retained history.
- Join mode: invitation grants access or owner approval is required.

### 4. Join preview

- Group name and identifier fingerprint.
- Root-authorized inviter-device fingerprint.
- Expiration and requested permissions.
- Reachability status.
- Join or Cancel.

### 5. Conversation

- Chronological message timeline.
- Author and device verification state.
- Reply, copy, edit, and local delete.
- Synchronization state without misleading server-style checkmarks.
- No attachments in the MVP.

### 6. Group details

- Group fingerprint and discovery status.
- Members, roles, and devices.
- History policy.
- Leave group.

### 7. Members and devices

- Approve, remove, block locally, or revoke a device according to permissions.
- Show key fingerprints and last observed activity.
- Make clear that a peer identity is not a verified legal identity.

### 8. Invitations

- Create, copy, display as QR, expire, and revoke invitations.
- Show whether an invitation is reusable and whether owner approval is needed.

### 9. Network

- Connection type: direct, relay, LAN, or offline.
- Known bootstrap and community nodes.
- Desktop-only opt-in contribution controls with explicit bandwidth limits.
- Diagnostic export with secrets removed.

### 10. Settings

- Local retention and storage use.
- Background and startup behavior.
- Bandwidth limits.
- Identity backup and device revocation.
- Privacy, node policy, licences, security contact, and version information.

## Safety and operational boundaries

Private groups are managed by their owners and members. The application does
not offer a public directory, algorithmic recommendations, or anonymous public
broadcasting.

The client provides local blocking, owner-controlled removal, device
revocation, and an evidence export containing user-selected signed events. It
does not present a central Report action as though the project can delete a
group from independent devices.

Project-operated nodes may limit or reject abusive traffic on those nodes.
They cannot erase groups, messages, or identities across independently operated
nodes.

## MVP exclusions

- Public groups and group search.
- File and media transfer.
- Central message backup.
- Telephone-number or email account discovery.
- Anonymous posting inside a group.
- Multiple concurrent group owners.
- A promise of immediate offline delivery.
- A global group ban mechanism.

## Product decisions still to validate

- Maximum supported group size.
- Whether the MVP permits reusable invitations or only expiring invitations.
- Exact history-sharing choices exposed to owners.
- Whether Android contributes DHT routing while foregrounded or always acts as
  a light client.
- Accessibility, localization, and minimum supported OS versions.
