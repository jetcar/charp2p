import { invoke, isTauri } from "@tauri-apps/api/core";
import { getCurrent, onOpenUrl } from "@tauri-apps/plugin-deep-link";
import QRCode from "qrcode";
import { ChangeEvent, FormEvent, useEffect, useMemo, useRef, useState } from "react";
import "./App.css";

type SetupStep = 1 | 2 | 3;
type DeviceProfile = { deviceName: string; peerId: string };
type InvitationPreview = {
  groupName: string;
  inviterName: string;
  inviterDeviceId: string;
  groupId: string;
  expiresAtUnix: number;
  historyPolicy: "none" | "fromInvitation" | "allRetained";
  reusable: boolean;
};
type PendingGroup = InvitationPreview;
type JoinedGroup = Omit<InvitationPreview, "expiresAtUnix" | "reusable"> & {
  lastSynchronizedAtUnix: number | null;
};
type LocalGroup = {
  groupId: string;
  groupName: string;
  icon: number;
  historyPolicy: InvitationPreview["historyPolicy"];
  approvalRequired: boolean;
  invitationLifetimeSeconds: number;
  reusableInvitation: boolean;
};
type IssuedInvitation = {
  invitationId: string;
  groupId: string;
  link: string;
  expiresAtUnix: number;
  reusable: boolean;
};
type PeerSearchResult = {
  status: "bootstrapRequired" | "peerReachable" | "peersFound" | "noPeers" | "unavailable";
  discoveredPeers: number;
  reachablePeers: number;
  connectionType: "direct" | "lan" | "relayed" | null;
};
type AdvertisementResult = {
  status: "advertising" | "bootstrapRequired" | "inactive";
  expiresAtUnix: number;
};
type NetworkStatus = {
  connectionType: "direct" | "lan" | "relayed" | "offline" | null;
  connectionObservedAtUnix: number;
  bootstrapNodes: { peerId: string; address: string; source: "builtIn" | "configured" }[];
  advertisingStatus: "advertising" | "bootstrapRequired" | "inactive";
  advertisedDiscoveryKeys: number;
  contributionStatus: "routing" | "routingAndRelay" | "inactive";
};
type ContributionPreference = {
  routing: boolean;
  relay: { maxCircuits: number; maxCircuitMib: number } | null;
};
type ContributionStatus = {
  available: boolean;
  preference: ContributionPreference;
  worstCaseRelayedBytes: number;
  circuitDurationSeconds: number;
};
type NetworkDiagnostics = {
  format: string;
  generatedAtUnix: number;
};
type EvidenceExport = {
  format: string;
  generatedAtUnixMs: number;
  events: { eventId: string }[];
};
type AppInformation = {
  appVersion: string;
  os: string;
  arch: string;
  storage: { databaseBytes: number };
};
type UnreadMessageCount = { groupId: string; count: number };
type GroupConnectionStateName = "online" | "relayed" | "waiting" | "offline";
type GroupConnectionState = {
  groupId: string;
  state: GroupConnectionStateName;
  observedAtUnix: number;
};
type SynchronizeGroupResult = {
  status: "synchronized";
  groupId: string;
  synchronizedEvents: number;
  uploadedEvents: number;
  synchronizedAtUnix: number;
  connectionType: "direct" | "lan" | "relayed";
};

type CreatedMessage = {
  eventId: string;
  groupId: string;
  authorId: string;
  authorSequence: number;
  createdAtUnixMs: number;
};

type StoredMessage = CreatedMessage & {
  text: string;
  edited: boolean;
  replyToEventId: string | null;
  deliveryState: "local" | "sharedWithPeer" | "observedByAll" | "received";
};
type StoredMessagePage = { messages: StoredMessage[]; hasEarlier: boolean };
type GroupMemberDevice = { deviceId: string };
type MemberActivity = { deviceId: string; lastSignedAtUnixMs: number };

const ADVERTISEMENT_STATUS_INTERVAL_MS = 30_000;
const ADVERTISEMENT_RETRY_INTERVAL_MS = 5_000;
const INVITATION_EXPIRY_CHECK_INTERVAL_MS = 1_000;
const JOINED_GROUP_SYNC_INTERVAL_MS = 60_000;
const JOINED_GROUP_SYNC_START_DELAY_MS = 1_000;
const MESSAGE_REFRESH_INTERVAL_MS = 2_000;
const MEMBER_REFRESH_INTERVAL_MS = 5_000;
const MESSAGE_TEXT_LIMIT_BYTES = 16 * 1024;
const EVIDENCE_EVENT_LIMIT = 64;

const ERROR_MESSAGES: Record<string, string> = {
  identity_already_exists: "This device already has an identity.",
  identity_creation_failed: "The device identity could not be created.",
  identity_record_invalid: "The stored identity is damaged and cannot be opened.",
  identity_service_unavailable: "The identity service is unavailable.",
  identity_store_unavailable: "Protected device storage is unavailable.",
  identity_missing: "Create a device identity before connecting to peers.",
  group_creation_failed: "The group identity could not be created.",
  group_creation_event_failed: "The initial group event could not be created.",
  group_creation_rollback_failed: "Group setup failed and could not be safely rolled back.",
  group_option_unsupported: "This option is not available in the current secure group profile.",
  group_already_joined: "This device already belongs to that group.",
  group_identity_record_invalid: "A stored group identity is damaged.",
  group_identity_store_unavailable: "Protected group storage is unavailable.",
  group_service_unavailable: "Groups are temporarily unavailable.",
  group_store_unavailable: "The group could not be saved on this device.",
  group_not_found: "This local group is no longer available.",
  invitation_creation_failed: "The invitation could not be created.",
  invitation_already_exists: "This group already has an active invitation.",
  issued_invitation_record_invalid: "A saved group invitation is damaged.",
  issued_invitation_not_found: "Create an invitation before advertising this group.",
  issued_invitation_store_unavailable: "The invitation could not be saved securely.",
  invalid_group_icon: "Choose a supported group icon.",
  invalid_group_name: "Enter a shorter group name (up to 80 UTF-8 bytes).",
  invalid_history_policy: "Choose a valid history policy.",
  invalid_invitation_lifetime: "Choose a supported invitation expiry.",
  invitation_expired: "This invitation has expired.",
  invitation_owned_locally: "This device already owns that group.",
  invitation_invalid: "This is not a valid CharP2P invitation.",
  invitation_inviter_mismatch: "This device is not authorized to answer that invitation.",
  invitation_signature_invalid: "The invitation signature could not be verified.",
  invalid_device_name: "Enter 1–48 characters using no more than 80 UTF-8 bytes.",
  network_advertisement_timed_out: "Peer advertising timed out. Retrying…",
  network_bootstrap_required: "Configure a bootstrap node before connecting to peers.",
  network_configuration_invalid: "The peer network configuration is invalid.",
  network_join_failed: "The secure join exchange failed. Try again.",
  network_join_timed_out: "The group owner did not answer in time. Try again.",
  network_peer_not_found: "The invited group owner is not online yet.",
  network_peer_unreachable: "The invited group owner could not be reached.",
  network_search_timed_out: "The peer search timed out. Try again.",
  network_unavailable: "The peer network is unavailable.",
  owner_discovery_limit_reached: "This group has reached its safe invitation rotation limit.",
  advertised_discovery_limit_reached: "This device has reached its safe limit of advertised group invitations.",
  owner_discovery_record_invalid: "The saved group discovery record is damaged.",
  owner_discovery_store_unavailable: "Protected group discovery storage is unavailable.",
  mls_group_creation_failed: "Secure group setup failed.",
  mls_group_author_mismatch: "This device is not the authorized sender for that group.",
  mls_group_already_joined: "This device already belongs to that group.",
  mls_group_identity_invalid: "Stored secure group identity is damaged.",
  mls_group_profile_invalid: "Stored secure group profile is unsupported.",
  mls_joined_group_missing: "Stored secure membership for this group is missing.",
  mls_group_storage_unavailable: "Secure group storage is unavailable.",
  mls_group_members_invalid: "Stored group membership is damaged.",
  mls_provider_encryption_failed: "Secure group state could not be encrypted.",
  mls_provider_service_unavailable: "Secure group state is temporarily unavailable.",
  mls_provider_snapshot_invalid: "Stored secure group state is damaged.",
  mls_provider_store_unavailable: "Secure group state could not be saved.",
  mls_pending_join_invalid: "The saved secure join state is damaged.",
  mls_pending_join_missing: "The saved secure join state is missing.",
  mls_welcome_group_mismatch: "The response belongs to a different group.",
  mls_welcome_invalid: "The group owner returned an invalid secure response.",
  mls_wrapping_key_store_unavailable: "Protected secure-group storage is unavailable.",
  mls_message_creation_failed: "The message could not be protected for this group.",
  message_creation_failed: "The message could not be signed.",
  message_encryption_failed: "The local message copy could not be protected.",
  message_invalid: "Enter a message up to 16 KiB.",
  member_activity_unavailable: "Member activity could not be read.",
  message_delete_failed: "The local message copy could not be deleted.",
  message_delivery_state_unavailable: "The message was shared, but its delivery state could not be saved.",
  message_not_found: "That message is no longer stored on this device.",
  message_not_own: "Only messages sent from this device can be edited.",
  message_list_unavailable: "Saved messages are temporarily unavailable.",
  message_record_invalid: "A saved message is damaged and cannot be opened.",
  message_store_unavailable: "The encrypted message could not be saved.",
  pending_invitation_not_found: "This pending invitation is no longer available.",
  pending_invitation_service_unavailable: "Pending invitations are temporarily unavailable.",
  pending_invitation_record_invalid: "A saved invitation is damaged and cannot be opened.",
  pending_invitation_store_unavailable: "The invitation could not be saved securely.",
  pending_invitation_too_large: "This invitation is too large for protected device storage.",
  joined_group_not_found: "This joined group is no longer available.",
  joined_discovery_record_missing: "Peer discovery for this group is unavailable on this device.",
  joined_discovery_record_invalid: "Stored peer discovery information is damaged.",
  joined_discovery_store_unavailable: "Protected peer discovery storage is unavailable.",
  join_busy: "The group owner is busy. Try again shortly.",
  join_unauthorized: "The group owner did not accept this invitation.",
  join_unsupported_profile: "The group uses an unsupported security profile.",
  synchronization_busy: "The group peer is busy. Try again shortly.",
  synchronization_failed: "Group synchronization failed. Try again.",
  synchronization_limit_exceeded: "Group synchronization exceeded its safe exchange limit.",
  synchronization_peer_invalid: "The saved synchronization peer is invalid.",
  synchronization_state_store_unavailable: "Synchronization completed, but its time could not be saved.",
  synchronization_timed_out: "The group peer did not answer in time. Try again.",
  synchronization_unauthorized: "This device is no longer authorized to synchronize the group.",
  synchronization_unavailable: "Group synchronization is temporarily unavailable.",
  member_not_found: "That device is no longer a group member.",
  member_owner_cannot_remove: "The owner device cannot remove itself.",
  member_removal_failed: "The device could not be removed securely.",
  member_removal_not_allowed: "Only this group's owner can remove devices.",
  device_block_failed: "The block setting could not be saved on this device.",
  device_block_self: "This device cannot block itself.",
  device_block_unavailable: "Blocked devices could not be loaded.",
  member_removal_store_unavailable: "The removal could not be saved securely.",
  backup_passphrase_invalid: "Use a backup passphrase of at least 12 characters.",
  identity_backup_failed: "The encrypted backup could not be created.",
  backup_decryption_failed: "The backup could not be opened. Check the passphrase and that the backup is complete.",
  backup_unrecognized: "This is not a CharP2P identity backup this version can open.",
  backup_text_invalid: "The backup text is not valid. Paste the complete text copied from the backup screen.",
  identity_backup_invalid: "The backup does not contain a valid device identity.",
  evidence_selection_invalid: "Select between 1 and 64 messages to export as evidence.",
  system_clock_invalid: "The device clock must be corrected before validating invitations.",
};

function errorMessage(error: unknown) {
  const code = typeof error === "string" ? error : "";
  return ERROR_MESSAGES[code] ?? "Something went wrong. Try again.";
}

function shortPeerId(peerId: string) {
  if (peerId.length <= 18) return peerId;
  return `${peerId.slice(0, 9)}…${peerId.slice(-8)}`;
}

function messageTime(createdAtUnixMs: number) {
  return new Date(createdAtUnixMs).toLocaleString([], {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function messageAuthorLabel(
  message: StoredMessage,
  profile: DeviceProfile | null,
  joinedGroup?: JoinedGroup | null,
) {
  if (message.authorId === profile?.peerId) return "You";
  if (joinedGroup && message.authorId === joinedGroup.inviterDeviceId) {
    return joinedGroup.inviterName;
  }
  return `Peer ${shortPeerId(message.authorId)}`;
}

function messageDeliveryLabel(message: StoredMessage) {
  if (message.deliveryState === "observedByAll") {
    return "Observed by all known members";
  }
  return message.deliveryState === "sharedWithPeer"
    ? "Shared with a peer"
    : "Saved on this device";
}

function historyDescription(_policy: InvitationPreview["historyPolicy"]) {
  return "Messages shared after you join";
}

function expiryDescription(expiresAtUnix: number) {
  const remainingSeconds = expiresAtUnix - Math.floor(Date.now() / 1000);
  if (remainingSeconds <= 0) return "Expired";
  const hours = Math.ceil(remainingSeconds / 3600);
  if (hours < 48) return `Expires in ${hours} ${hours === 1 ? "hour" : "hours"}`;
  const days = Math.ceil(hours / 24);
  return `Expires in ${days} days`;
}

function synchronizationDescription(synchronizedAtUnix: number | null) {
  if (synchronizedAtUnix === null) return "Not yet";
  return new Date(synchronizedAtUnix * 1000).toLocaleString([], {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function signedActivityDescription(lastSignedAtUnixMs: number | undefined) {
  if (lastSignedAtUnixMs === undefined) return "No signed activity received";
  return `Last signed activity ${new Date(lastSignedAtUnixMs).toLocaleString([], {
    dateStyle: "medium",
    timeStyle: "short",
  })}`;
}

function connectionTypeDescription(connectionType: "direct" | "lan" | "relayed") {
  if (connectionType === "relayed") return "Relay";
  if (connectionType === "lan") return "Local network";
  return "Direct";
}

function groupConnectionDescription(state: GroupConnectionStateName) {
  if (state === "online") return "Online";
  if (state === "relayed") return "Relayed";
  if (state === "offline") return "Offline";
  return "Waiting for peers";
}

function peerSearchDescription(result: PeerSearchResult | null) {
  if (!result) return "Not searched";
  if (result.status === "bootstrapRequired") return "Bootstrap node needed";
  if (result.status === "peerReachable") {
    const route = result.connectionType === "relayed"
      ? "through relay"
      : result.connectionType === "lan"
        ? "on local network"
        : "directly";
    return `Reached ${result.reachablePeers} ${result.reachablePeers === 1 ? "peer" : "peers"} ${route}`;
  }
  if (result.status === "peersFound") {
    return `${result.discoveredPeers} ${result.discoveredPeers === 1 ? "peer" : "peers"} found`;
  }
  if (result.status === "noPeers") return "No peers online";
  return "Network unavailable";
}

function BrandMark({ decorative = false }: { decorative?: boolean }) {
  return (
    <svg
      aria-hidden={decorative}
      aria-label={decorative ? undefined : "CharP2P"}
      className="brand-mark"
      viewBox="0 0 64 64"
      role={decorative ? undefined : "img"}
    >
      <path d="M32 12v18M17 45l15-15 15 15" />
      <circle cx="32" cy="10" r="7" />
      <circle cx="15" cy="47" r="7" />
      <circle cx="49" cy="47" r="7" />
    </svg>
  );
}

function NetworkArtwork() {
  return (
    <div className="network-art" aria-hidden="true">
      <svg viewBox="0 0 500 500">
        <defs>
          <linearGradient id="networkLine" x1="0" x2="1">
            <stop offset="0" stopColor="#18d6c3" />
            <stop offset="1" stopColor="#238ea7" />
          </linearGradient>
        </defs>
        <path d="M250 125 116 353l282 46z" />
        <circle className="halo" cx="250" cy="125" r="79" />
        <circle className="halo" cx="116" cy="353" r="76" />
        <circle className="halo" cx="398" cy="399" r="84" />
        <circle className="node" cx="250" cy="125" r="35" />
        <circle className="node" cx="116" cy="353" r="35" />
        <circle className="node node-three" cx="398" cy="399" r="35" />
      </svg>
    </div>
  );
}

function Stepper({ step }: { step: SetupStep }) {
  const steps = ["Identity", "Recovery", "Ready"];

  return (
    <ol className="stepper" aria-label="Device setup progress">
      {steps.map((label, index) => {
        const number = (index + 1) as SetupStep;
        return (
          <li className={number <= step ? "active" : ""} key={label}>
            <span className="step-number">{number < step ? "✓" : number}</span>
            <span className="step-label">{label}</span>
          </li>
        );
      })}
    </ol>
  );
}

function MembersView({
  groupName,
  members,
  memberActivity,
  ownerDeviceId,
  ownerName,
  profile,
  error,
  canManageMembers,
  removingDeviceId,
  onRemove,
  blockedDeviceIds,
  blockingDeviceId,
  onToggleBlock,
  onRename,
  onLeave,
  leaving,
  onClose,
}: {
  groupName: string;
  members: GroupMemberDevice[];
  memberActivity: Record<string, number>;
  ownerDeviceId: string;
  ownerName: string;
  profile: DeviceProfile | null;
  error: string;
  canManageMembers: boolean;
  removingDeviceId: string;
  onRemove: (deviceId: string) => void;
  blockedDeviceIds: string[];
  blockingDeviceId: string;
  onToggleBlock: (deviceId: string, blocked: boolean) => void;
  onRename: (groupName: string) => Promise<void>;
  onLeave: (() => void) | null;
  leaving: boolean;
  onClose: () => void;
}) {
  const [renameInput, setRenameInput] = useState(groupName);
  const [renaming, setRenaming] = useState(false);
  const [renameError, setRenameError] = useState("");

  async function submitRename(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const requested = renameInput.trim();
    if (!requested || requested === groupName || renaming) return;
    setRenaming(true);
    setRenameError("");
    try {
      await onRename(requested);
    } catch (reason) {
      setRenameError(errorMessage(reason));
    } finally {
      setRenaming(false);
    }
  }

  const ordered = [...members].sort((left, right) => {
    if (left.deviceId === right.deviceId) return 0;
    if (left.deviceId === ownerDeviceId) return -1;
    if (right.deviceId === ownerDeviceId) return 1;
    if (left.deviceId === profile?.peerId) return -1;
    if (right.deviceId === profile?.peerId) return 1;
    return left.deviceId.localeCompare(right.deviceId);
  });

  return (
    <section className="setup-form members-card">
      <header className="members-header">
        <div>
          <p className="eyebrow">{groupName}</p>
          <h2>Members &amp; devices</h2>
          <p>{members.length > 0 ? `${members.length} verified ${members.length === 1 ? "device" : "devices"}` : "Loading verified membership…"}</p>
        </div>
        <button aria-label="Close members and devices" className="member-close" onClick={onClose} type="button">×</button>
      </header>
      {canManageMembers && (
        <form className="rename-group-form" onSubmit={submitRename}>
          <label htmlFor="rename-group">Group name</label>
          <div className="rename-group-row">
            <input
              id="rename-group"
              maxLength={80}
              onChange={(event) => setRenameInput(event.currentTarget.value)}
              value={renameInput}
            />
            <button
              className="secondary-button"
              disabled={renaming || !renameInput.trim() || renameInput.trim() === groupName}
              type="submit"
            >
              {renaming ? "Saving…" : "Rename"}
            </button>
          </div>
          <p className="preview-note">The new name is signed by this owner device and reaches members when they synchronize.</p>
          {renameError && <p className="form-error preview-error" role="alert">{renameError}</p>}
        </form>
      )}
      <p className="preview-note">Each membership belongs to one cryptographic device identity.</p>
      <div className="member-list" role="list">
        {ordered.map((member) => {
          const isOwner = member.deviceId === ownerDeviceId;
          const isLocal = member.deviceId === profile?.peerId;
          const isBlocked = blockedDeviceIds.includes(member.deviceId);
          const name = isLocal
            ? `${profile?.deviceName ?? "This device"} (You)`
            : isOwner
              ? ownerName
              : `Member ${shortPeerId(member.deviceId)}`;
          return (
            <article className={`member-row ${isLocal ? "local-member" : ""}`} key={member.deviceId} role="listitem">
              <div className="member-avatar" aria-hidden="true">{isOwner ? "♛" : "●"}</div>
              <div className="member-identity">
                <strong>{name}</strong>
                <span>{isOwner ? "Owner device" : "Member device"}</span>
                <code title={member.deviceId}>{shortPeerId(member.deviceId)}</code>
                <span className="member-activity">{signedActivityDescription(memberActivity[member.deviceId])}</span>
              </div>
              <div className="member-actions">
                <span className="status-chip">✓ {isLocal ? "This device" : "Verified"}</span>
                {isBlocked && <span className="status-chip blocked-chip">Blocked here</span>}
                {!isLocal && (
                  <button
                    className="member-block"
                    disabled={Boolean(blockingDeviceId)}
                    onClick={() => onToggleBlock(member.deviceId, !isBlocked)}
                    type="button"
                  >
                    {blockingDeviceId === member.deviceId ? "Saving…" : isBlocked ? "Unblock" : "Block on this device"}
                  </button>
                )}
                {canManageMembers && !isOwner && (
                  <button
                    className="member-remove"
                    disabled={Boolean(removingDeviceId)}
                    onClick={() => onRemove(member.deviceId)}
                    type="button"
                  >
                    {removingDeviceId === member.deviceId ? "Removing…" : "Remove device"}
                  </button>
                )}
              </div>
            </article>
          );
        })}
      </div>
      {error && <p className="form-error preview-error" role="alert">{error}</p>}
      <p className="preview-note">Activity times are the latest signed event this device holds from each member, as claimed by that member. They do not show whether a device is online.</p>
      <p className="preview-note">Blocking hides a device's messages only on this device. Its signed events are kept, it stays a group member, and other members still see its messages.</p>
      {canManageMembers && <p className="preview-note">Removing a device blocks future group messages and invitation reuse. Messages already saved on that device cannot be erased.</p>}
      {onLeave && (
        <div className="leave-group">
          <button className="member-remove" disabled={leaving} onClick={onLeave} type="button">
            {leaving ? "Leaving…" : "Leave group"}
          </button>
          <p className="preview-note">Leaving deletes this group's messages, keys, and discovery record from this device only. The owner still lists this device until it removes it, and other members keep their copies.</p>
        </div>
      )}
      <button className="secondary-button" onClick={onClose} type="button">Back to conversation</button>
    </section>
  );
}

function InformationView({
  view,
  onClose,
}: {
  view: "privacy" | "identity";
  onClose: () => void;
}) {
  const privacy = view === "privacy";

  return (
    <section className="setup-form information-card">
      <header>
        <p className="eyebrow">CharP2P</p>
        <h2>{privacy ? "Privacy" : "How identity works"}</h2>
        <p>
          {privacy
            ? "What the app stores and what other peers can observe."
            : "Your identity represents this installation and its cryptographic keys."}
        </p>
      </header>
      {privacy ? (
        <div className="information-sections">
          <section>
            <h3>Messages stay with group devices</h3>
            <p>Message contents are protected for authorized group devices and stored on participating devices. CharP2P has no central message archive.</p>
          </section>
          <section>
            <h3>Network metadata is visible</h3>
            <p>Peers, bootstrap nodes, and relays can observe connection metadata such as peer identifiers, network addresses, timing, and traffic volume. Relays forward encrypted streams without group keys.</p>
          </section>
          <section>
            <h3>Groups control their copies</h3>
            <p>Group owners can remove a device from future access. Removal cannot erase messages already stored by that device or by other members.</p>
          </section>
          <section>
            <h3>No account directory</h3>
            <p>The MVP does not use telephone numbers, email discovery, public group search, or a central identity account.</p>
          </section>
        </div>
      ) : (
        <div className="information-sections">
          <section>
            <h3>One key identity per installation</h3>
            <p>This device creates an Ed25519 key with the operating system’s secure random source. Its peer identifier is derived from the public key.</p>
          </section>
          <section>
            <h3>Private keys remain protected</h3>
            <p>Private identity and group material stays in platform-protected storage and is never returned to the app interface.</p>
          </section>
          <section>
            <h3>Membership verifies devices</h3>
            <p>MLS membership binds group access to cryptographic device credentials. A verified device identity proves key continuity, not a person’s legal identity.</p>
          </section>
          <section>
            <h3>Keep this installation</h3>
            <p>Reinstalling without a recovery copy creates a different identity. Export an encrypted identity backup and keep its passphrase; losing every authorized device and backup can permanently lose access.</p>
          </section>
        </div>
      )}
      <button className="secondary-button" onClick={onClose} type="button">Back</button>
    </section>
  );
}

const NETWORK_STATUS_REFRESH_MS = 5_000;

function networkConnectionDescription(status: NetworkStatus) {
  if (status.connectionType === null) return "Not connected yet";
  if (status.connectionType === "offline") return "Offline";
  const observed = new Date(status.connectionObservedAtUnix * 1000).toLocaleTimeString();
  return `${connectionTypeDescription(status.connectionType)} · last seen ${observed}`;
}

const DEFAULT_RELAY_CIRCUITS = 4;
const DEFAULT_RELAY_CIRCUIT_MIB = 8;
const MAX_RELAY_CIRCUITS = 32;
const MAX_RELAY_CIRCUIT_MIB = 32;

function ContributionSection({ networkStatus }: { networkStatus: NetworkStatus | null }) {
  const [status, setStatus] = useState<ContributionStatus | null>(null);
  const [routing, setRouting] = useState(false);
  const [relay, setRelay] = useState(false);
  const [circuits, setCircuits] = useState(DEFAULT_RELAY_CIRCUITS);
  const [circuitMib, setCircuitMib] = useState(DEFAULT_RELAY_CIRCUIT_MIB);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  function showPreference(next: ContributionStatus) {
    setStatus(next);
    setRouting(next.preference.routing);
    setRelay(next.preference.relay !== null);
    if (next.preference.relay) {
      setCircuits(next.preference.relay.maxCircuits);
      setCircuitMib(next.preference.relay.maxCircuitMib);
    }
  }

  useEffect(() => {
    if (!isTauri()) return;
    let active = true;
    invoke<ContributionStatus>("contribution_status")
      .then((next) => {
        if (active) showPreference(next);
      })
      .catch((caught) => {
        if (active) setError(errorMessage(caught));
      });
    return () => {
      active = false;
    };
  }, []);

  const limitsValid =
    Number.isInteger(circuits) && circuits >= 1 && circuits <= MAX_RELAY_CIRCUITS &&
    Number.isInteger(circuitMib) && circuitMib >= 1 && circuitMib <= MAX_RELAY_CIRCUIT_MIB;
  const relayEnabled = routing && relay;
  const worstCaseMib = relayEnabled && limitsValid ? circuits * circuitMib : 0;
  const circuitMinutes = Math.round((status?.circuitDurationSeconds ?? 300) / 60);
  const changed =
    status !== null &&
    (routing !== status.preference.routing ||
      relayEnabled !== (status.preference.relay !== null) ||
      (relayEnabled &&
        (circuits !== status.preference.relay?.maxCircuits || circuitMib !== status.preference.relay?.maxCircuitMib)));

  async function save(event: FormEvent) {
    event.preventDefault();
    setSaving(true);
    setError("");
    try {
      const preference: ContributionPreference = {
        routing,
        relay: relayEnabled ? { maxCircuits: circuits, maxCircuitMib: circuitMib } : null,
      };
      showPreference(await invoke<ContributionStatus>("set_contribution_preference", { preference }));
    } catch (caught) {
      setError(errorMessage(caught));
    } finally {
      setSaving(false);
    }
  }

  if (status && !status.available) {
    return (
      <section>
        <h3>Network contribution</h3>
        <p>This device stays a light peer. Routing and relay contribution are offered on desktop installations.</p>
      </section>
    );
  }

  const running = networkStatus?.contributionStatus ?? "inactive";
  return (
    <section className="contribution-section">
      <h3>Network contribution</h3>
      <p>
        Optional. Helps other peers find each other and, if enabled, relays encrypted traffic for peers that cannot
        connect directly. Contributing never gives access to group keys or messages, but relayed peers can see this
        device's address and traffic volume.
      </p>
      <p>
        {running === "routingAndRelay"
          ? "Contributing routing and relay capacity"
          : running === "routing"
            ? "Contributing routing"
            : status?.preference.routing && networkStatus?.bootstrapNodes.length === 0
              ? "Paused until a bootstrap node is configured"
              : "Not contributing"}
      </p>
      {error && <p className="form-error" role="alert">{error}</p>}
      <form onSubmit={(event) => void save(event)}>
        <label className="contribution-option">
          <input
            checked={routing}
            disabled={!status || saving}
            onChange={(event) => setRouting(event.target.checked)}
            type="checkbox"
          />
          Help route peer discovery
        </label>
        <label className="contribution-option">
          <input
            checked={relayEnabled}
            disabled={!status || saving || !routing}
            onChange={(event) => setRelay(event.target.checked)}
            type="checkbox"
          />
          Relay connections for other peers
        </label>
        {relayEnabled && (
          <div className="contribution-limits">
            <label>
              Simultaneous relayed connections (1–{MAX_RELAY_CIRCUITS})
              <input
                disabled={saving}
                max={MAX_RELAY_CIRCUITS}
                min={1}
                onChange={(event) => setCircuits(event.target.valueAsNumber)}
                type="number"
                value={Number.isNaN(circuits) ? "" : circuits}
              />
            </label>
            <label>
              Limit per connection in MiB (1–{MAX_RELAY_CIRCUIT_MIB})
              <input
                disabled={saving}
                max={MAX_RELAY_CIRCUIT_MIB}
                min={1}
                onChange={(event) => setCircuitMib(event.target.valueAsNumber)}
                type="number"
                value={Number.isNaN(circuitMib) ? "" : circuitMib}
              />
            </label>
            <p>
              {limitsValid
                ? `Worst case: ${worstCaseMib} MiB relayed every ${circuitMinutes} minutes (up to ${Math.round((worstCaseMib * 60) / circuitMinutes / 1024 * 10) / 10} GiB per hour).`
                : "Enter whole numbers within the limits shown."}
            </p>
          </div>
        )}
        <button
          className="secondary-button"
          disabled={!status || saving || !changed || (relayEnabled && !limitsValid)}
          type="submit"
        >
          {saving ? "Saving…" : "Save contribution settings"}
        </button>
      </form>
    </section>
  );
}

function NetworkView({ onClose }: { onClose: () => void }) {
  const [status, setStatus] = useState<NetworkStatus | null>(null);
  const [error, setError] = useState("");
  const [diagnosticsText, setDiagnosticsText] = useState("");
  const [diagnosticsCopied, setDiagnosticsCopied] = useState(false);

  async function exportDiagnostics() {
    setError("");
    setDiagnosticsCopied(false);
    try {
      const diagnostics = await invoke<NetworkDiagnostics>("network_diagnostics");
      const text = JSON.stringify(diagnostics, null, 2);
      const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = `charp2p-diagnostics-${diagnostics.generatedAtUnix}.json`;
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 0);
      setDiagnosticsText(text);
    } catch (caught) {
      setError(errorMessage(caught));
    }
  }

  async function copyDiagnostics() {
    try {
      await navigator.clipboard.writeText(diagnosticsText);
      setDiagnosticsCopied(true);
    } catch {
      setError("The report could not be copied. Select the text and copy it manually.");
    }
  }

  useEffect(() => {
    if (!isTauri()) return;
    let active = true;
    const refresh = async () => {
      try {
        const next = await invoke<NetworkStatus>("network_status");
        if (active) {
          setStatus(next);
          setError("");
        }
      } catch (caught) {
        if (active) setError(errorMessage(caught));
      }
    };
    void refresh();
    const timer = window.setInterval(() => void refresh(), NETWORK_STATUS_REFRESH_MS);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, []);

  return (
    <section className="setup-form information-card">
      <header>
        <p className="eyebrow">CharP2P</p>
        <h2>Network</h2>
        <p>How this device currently reaches peers. Group contents are never sent to bootstrap nodes.</p>
      </header>
      {error && <p className="form-error" role="alert">{error}</p>}
      <div className="information-sections">
        <section>
          <h3>Connection type</h3>
          <p>{status ? networkConnectionDescription(status) : "Unavailable outside the app"}</p>
        </section>
        <section>
          <h3>Group advertising</h3>
          <p>
            {status?.advertisingStatus === "advertising"
              ? `Advertising ${status.advertisedDiscoveryKeys} invitation ${status.advertisedDiscoveryKeys === 1 ? "key" : "keys"} for owned groups`
              : status?.advertisingStatus === "bootstrapRequired"
                ? "Paused until a bootstrap node is configured"
                : "Not advertising"}
          </p>
        </section>
        <section className="network-nodes">
          <h3>Bootstrap and community nodes</h3>
          {status && status.bootstrapNodes.length > 0 ? (
            <ul>
              {status.bootstrapNodes.map((node) => (
                <li key={`${node.peerId}-${node.address}`}>
                  <code>{node.address}</code>
                  <span>
                    {node.source === "builtIn" ? "Built in" : "Configured on this device"} · {node.peerId.slice(0, 12)}…{node.peerId.slice(-6)}
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <p>No nodes configured. Set CHARP2P_BOOTSTRAP_NODES to connect beyond the local network.</p>
          )}
        </section>
        <ContributionSection networkStatus={status} />
        <section>
          <h3>Diagnostics</h3>
          <p>Exports connection state, node addresses, app version and group counts. Keys, invitations, group names and messages are never included.</p>
          <button className="secondary-button" disabled={!isTauri()} onClick={() => void exportDiagnostics()} type="button">
            Export diagnostics
          </button>
          {diagnosticsText && (
            <>
              <textarea aria-label="Diagnostic report" className="backup-text" readOnly rows={8} value={diagnosticsText} />
              <button className="secondary-button" onClick={() => void copyDiagnostics()} type="button">
                {diagnosticsCopied ? "Copied" : "Copy report"}
              </button>
            </>
          )}
        </section>
      </div>
      <button className="secondary-button" onClick={onClose} type="button">Back</button>
    </section>
  );
}

function formatStorageBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

function SettingsView({ onClose }: { onClose: () => void }) {
  const [information, setInformation] = useState<AppInformation | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!isTauri()) return;
    let active = true;
    invoke<AppInformation>("app_information")
      .then((next) => {
        if (active) setInformation(next);
      })
      .catch((caught) => {
        if (active) setError(errorMessage(caught));
      });
    return () => {
      active = false;
    };
  }, []);

  return (
    <section className="setup-form information-card">
      <header>
        <p className="eyebrow">CharP2P</p>
        <h2>Settings</h2>
        <p>Information about this installation. Group contents stay on your devices.</p>
      </header>
      {error && <p className="form-error" role="alert">{error}</p>}
      <div className="information-sections">
        <section>
          <h3>Local storage</h3>
          <p>
            {information
              ? `${formatStorageBytes(information.storage.databaseBytes)} used by groups, messages and invitations on this device`
              : "Unavailable outside the app"}
          </p>
          <p>Messages are kept on this device until you hide them or leave the group. Hiding affects only this device.</p>
        </section>
        <section>
          <h3>Node policy</h3>
          <p>
            Bootstrap and relay nodes store only bounded routing records and relay reservations. They never store group
            events or message contents, reject group synchronization, and cannot remove groups or messages from your
            devices.
          </p>
        </section>
        <section>
          <h3>Licences and security contact</h3>
          <p>
            Licence terms, node operator details and a security contact will be published before project nodes accept
            public traffic.
          </p>
        </section>
        <section>
          <h3>Version</h3>
          <p>{information ? `CharP2P ${information.appVersion} · ${information.os} ${information.arch}` : "Unavailable outside the app"}</p>
        </section>
      </div>
      <button className="secondary-button" onClick={onClose} type="button">Back</button>
    </section>
  );
}

const MIN_BACKUP_PASSPHRASE_CHARS = 12;

function backupFileName(profile: DeviceProfile) {
  const suffix = profile.peerId.slice(-8).replace(/[^A-Za-z0-9]/g, "");
  return `charp2p-identity-${suffix}.charp2p-backup`;
}

function bytesToBase64(bytes: number[]) {
  return btoa(String.fromCharCode(...bytes));
}

const MAX_BACKUP_BYTES = 1024;

function base64ToBytes(text: string) {
  const compact = text.replace(/\s+/g, "");
  if (!compact || compact.length > Math.ceil(MAX_BACKUP_BYTES / 3) * 4) {
    throw "backup_text_invalid";
  }
  try {
    return Array.from(atob(compact), (character) => character.charCodeAt(0));
  } catch {
    throw "backup_text_invalid";
  }
}

function RestoreBackupView({
  onRestored,
  onClose,
}: {
  onRestored: (profile: DeviceProfile) => void;
  onClose: () => void;
}) {
  const [fileBytes, setFileBytes] = useState<number[] | null>(null);
  const [fileName, setFileName] = useState("");
  const [backupText, setBackupText] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [restoring, setRestoring] = useState(false);
  const [error, setError] = useState("");
  const hasBackup = fileBytes !== null || backupText.trim().length > 0;
  const tooShort = Array.from(passphrase).length < MIN_BACKUP_PASSPHRASE_CHARS;

  async function chooseFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    setError("");
    if (!file) {
      setFileBytes(null);
      setFileName("");
      return;
    }
    if (file.size > MAX_BACKUP_BYTES) {
      setFileBytes(null);
      setFileName("");
      setError(errorMessage("backup_unrecognized"));
      return;
    }
    setFileBytes(Array.from(new Uint8Array(await file.arrayBuffer())));
    setFileName(file.name);
  }

  async function restoreBackup(event: FormEvent) {
    event.preventDefault();
    if (!hasBackup || tooShort || restoring) return;
    setRestoring(true);
    setError("");
    try {
      const backup = fileBytes ?? base64ToBytes(backupText);
      const restored = await invoke<DeviceProfile>("restore_identity_backup", { backup, passphrase });
      setPassphrase("");
      onRestored(restored);
    } catch (restoreError) {
      setError(errorMessage(restoreError));
    } finally {
      setRestoring(false);
    }
  }

  return (
    <section className="setup-form information-card">
      <header>
        <p className="eyebrow">Identity backup</p>
        <h2>Restore from an encrypted backup</h2>
        <p>Restoring brings back this device's name and identity key. Group memberships and messages are not included; groups must re-admit or resynchronize this device.</p>
      </header>
      <form className="setup-form" onSubmit={restoreBackup}>
        <label htmlFor="restore-file">Backup file</label>
        <input accept=".charp2p-backup,application/octet-stream" id="restore-file" onChange={chooseFile} type="file" />
        {fileName ? (
          <p className="preview-note">Selected {fileName}.</p>
        ) : (
          <>
            <label htmlFor="restore-text">Or paste the backup text</label>
            <textarea
              className="backup-text"
              id="restore-text"
              onChange={(event) => setBackupText(event.target.value)}
              rows={5}
              spellCheck={false}
              value={backupText}
            />
          </>
        )}
        <label htmlFor="restore-passphrase">Passphrase</label>
        <input
          autoComplete="current-password"
          id="restore-passphrase"
          onChange={(event) => setPassphrase(event.target.value)}
          type="password"
          value={passphrase}
        />
        <p className="preview-note">Stop using the original device after restoring. Two installations with one identity will conflict.</p>
        <button
          className="primary-button"
          disabled={!hasBackup || tooShort || restoring || !isTauri()}
          type="submit"
        >
          {restoring ? "Decrypting backup…" : "Restore identity"}
        </button>
      </form>
      {error && <p className="form-error" role="alert">{error}</p>}
      <button className="secondary-button" disabled={restoring} onClick={onClose} type="button">Back</button>
    </section>
  );
}

function IdentityBackupView({
  profile,
  onClose,
}: {
  profile: DeviceProfile;
  onClose: () => void;
}) {
  const [passphrase, setPassphrase] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [exporting, setExporting] = useState(false);
  const [backupText, setBackupText] = useState("");
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState("");
  const tooShort = Array.from(passphrase).length < MIN_BACKUP_PASSPHRASE_CHARS;
  const mismatch = confirmation.length > 0 && confirmation !== passphrase;

  async function exportBackup(event: FormEvent) {
    event.preventDefault();
    if (tooShort || passphrase !== confirmation || exporting) return;
    setExporting(true);
    setError("");
    setCopied(false);
    try {
      const bytes = await invoke<number[]>("export_identity_backup", { passphrase });
      const blob = new Blob([new Uint8Array(bytes)], { type: "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = backupFileName(profile);
      link.click();
      setTimeout(() => URL.revokeObjectURL(url), 0);
      setBackupText(bytesToBase64(bytes));
      setPassphrase("");
      setConfirmation("");
    } catch (exportError) {
      setError(errorMessage(exportError));
    } finally {
      setExporting(false);
    }
  }

  async function copyBackup() {
    try {
      await navigator.clipboard.writeText(backupText);
      setCopied(true);
    } catch {
      setError("The backup could not be copied. Select the text and copy it manually.");
    }
  }

  return (
    <section className="setup-form information-card">
      <header>
        <p className="eyebrow">Identity backup</p>
        <h2>Create an encrypted recovery copy</h2>
        <p>The copy contains this device's name and private identity key, encrypted with your passphrase. Group memberships and messages are not included.</p>
      </header>
      {backupText ? (
        <>
          <p className="preview-note">The backup file was offered for download. If no file was saved, copy the text below and store it somewhere safe outside this device.</p>
          <textarea aria-label="Encrypted backup text" className="backup-text" readOnly rows={6} value={backupText} />
          <button className="secondary-button" onClick={copyBackup} type="button">
            {copied ? "Copied" : "Copy backup text"}
          </button>
          <p className="preview-note">Anyone with this copy and your passphrase can act as this device. Restore it on only one installation and stop using the original afterwards.</p>
        </>
      ) : (
        <form className="setup-form" onSubmit={exportBackup}>
          <label htmlFor="backup-passphrase">Passphrase</label>
          <input
            autoComplete="new-password"
            id="backup-passphrase"
            onChange={(event) => setPassphrase(event.target.value)}
            type="password"
            value={passphrase}
          />
          <label htmlFor="backup-confirmation">Repeat passphrase</label>
          <input
            autoComplete="new-password"
            id="backup-confirmation"
            onChange={(event) => setConfirmation(event.target.value)}
            type="password"
            value={confirmation}
          />
          <p className="preview-note">
            {mismatch
              ? "The passphrases do not match."
              : `Use at least ${MIN_BACKUP_PASSPHRASE_CHARS} characters. A lost passphrase cannot be recovered.`}
          </p>
          <button
            className="primary-button"
            disabled={tooShort || passphrase !== confirmation || exporting || !isTauri()}
            type="submit"
          >
            {exporting ? "Encrypting backup…" : "Export encrypted backup"}
          </button>
        </form>
      )}
      {error && <p className="form-error" role="alert">{error}</p>}
      <button className="secondary-button" onClick={onClose} type="button">Back</button>
    </section>
  );
}

function App() {
  const [step, setStep] = useState<SetupStep>(1);
  const [deviceName, setDeviceName] = useState("");
  const [profile, setProfile] = useState<DeviceProfile | null>(null);
  const [loading, setLoading] = useState(isTauri());
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [informationView, setInformationView] = useState<"privacy" | "identity" | null>(null);
  const [backupView, setBackupView] = useState(false);
  const [networkView, setNetworkView] = useState(false);
  const [settingsView, setSettingsView] = useState(false);
  const [restoreView, setRestoreView] = useState(false);
  const [joinMode, setJoinMode] = useState(false);
  const [inviteInput, setInviteInput] = useState("");
  const [invitationPreview, setInvitationPreview] = useState<InvitationPreview | null>(null);
  const [verifyingInvite, setVerifyingInvite] = useState(false);
  const [pendingGroup, setPendingGroup] = useState<PendingGroup | null>(null);
  const [joinedGroups, setJoinedGroups] = useState<JoinedGroup[]>([]);
  const [synchronizingGroup, setSynchronizingGroup] = useState(false);
  const [synchronizationResult, setSynchronizationResult] =
    useState<SynchronizeGroupResult | null>(null);
  const synchronizationInFlight = useRef(false);
  const [outgoingMessage, setOutgoingMessage] = useState("");
  const [sendingMessage, setSendingMessage] = useState(false);
  const [createdMessage, setCreatedMessage] = useState<CreatedMessage | null>(null);
  const [groupMessages, setGroupMessages] = useState<StoredMessage[]>([]);
  const [unreadCounts, setUnreadCounts] = useState<Record<string, number>>({});
  const [connectionStates, setConnectionStates] = useState<Record<string, GroupConnectionStateName>>({});
  const [hasEarlierMessages, setHasEarlierMessages] = useState(false);
  const [deletingMessage, setDeletingMessage] = useState("");
  const [editingMessage, setEditingMessage] = useState<{ eventId: string; text: string } | null>(null);
  const [replyingTo, setReplyingTo] = useState<StoredMessage | null>(null);
  const [evidenceSelection, setEvidenceSelection] = useState<string[] | null>(null);
  const [evidenceText, setEvidenceText] = useState("");
  const [exportingEvidence, setExportingEvidence] = useState(false);
  const [savingEdit, setSavingEdit] = useState(false);
  const [groupMembers, setGroupMembers] = useState<GroupMemberDevice[]>([]);
  const [membersError, setMembersError] = useState("");
  const [removingMember, setRemovingMember] = useState("");
  const [blockedDevices, setBlockedDevices] = useState<string[]>([]);
  const [memberActivity, setMemberActivity] = useState<Record<string, number>>({});
  const [blockingDevice, setBlockingDevice] = useState("");
  const [showMembers, setShowMembers] = useState(false);
  const outgoingMessageBytes = useMemo(
    () => new TextEncoder().encode(outgoingMessage).length,
    [outgoingMessage],
  );
  const [acceptingInvite, setAcceptingInvite] = useState(false);
  const [joiningGroup, setJoiningGroup] = useState(false);
  const [cancellingPending, setCancellingPending] = useState(false);
  const [leavingGroup, setLeavingGroup] = useState(false);
  const pendingExpiryCleanupRef = useRef("");
  const [peerSearchResult, setPeerSearchResult] = useState<PeerSearchResult | null>(null);
  const [searchingPeers, setSearchingPeers] = useState(false);
  const [localGroups, setLocalGroups] = useState<LocalGroup[]>([]);
  const [activeGroupId, setActiveGroupId] = useState("");
  const activeGroupIdRef = useRef("");
  const [issuedInvitations, setIssuedInvitations] = useState<IssuedInvitation[]>([]);
  const [createGroupMode, setCreateGroupMode] = useState(false);
  const [groupName, setGroupName] = useState("");
  const [groupIcon, setGroupIcon] = useState(0);
  const [invitationLifetime, setInvitationLifetime] = useState(604800);
  const [creatingGroup, setCreatingGroup] = useState(false);
  const [creatingInvitation, setCreatingInvitation] = useState(false);
  const [revokingInvitation, setRevokingInvitation] = useState(false);
  const [invitationCopied, setInvitationCopied] = useState(false);
  const [invitationQrCode, setInvitationQrCode] = useState("");
  const [invitationQrError, setInvitationQrError] = useState("");
  const [advertisement, setAdvertisement] = useState<AdvertisementResult | null>(null);
  const [advertisementError, setAdvertisementError] = useState("");
  const [advertisementRetrying, setAdvertisementRetrying] = useState(false);
  const suggestedName = useMemo(
    () => (/Android/i.test(navigator.userAgent) ? "My tablet" : "My PC"),
    [],
  );
  const joinedGroup = joinedGroups.find(({ groupId }) => groupId === activeGroupId) ?? null;
  const localGroup = localGroups.find(({ groupId }) => groupId === activeGroupId) ?? null;
  const issuedInvitation = localGroup
    ? issuedInvitations.find(({ groupId }) => groupId === localGroup.groupId) ?? null
    : null;
  const availableGroups = useMemo(
    () => [
      ...localGroups.map((group) => ({
        groupId: group.groupId,
        groupName: group.groupName,
        role: "Owner",
      })),
      ...joinedGroups.map((group) => ({
        groupId: group.groupId,
        groupName: group.groupName,
        role: "Member",
      })),
    ],
    [joinedGroups, localGroups],
  );

  useEffect(() => {
    activeGroupIdRef.current = activeGroupId;
  }, [activeGroupId]);

  useEffect(() => {
    if (!isTauri()) return;

    let active = true;
    Promise.allSettled([
      invoke<DeviceProfile | null>("identity_status"),
      invoke<PendingGroup[]>("pending_invitations"),
      invoke<JoinedGroup[]>("joined_groups"),
      invoke<LocalGroup[]>("local_groups"),
      invoke<IssuedInvitation[]>("issued_invitations"),
    ])
      .then(([identityResult, pendingResult, joinedResult, groupsResult, invitationsResult]) => {
        if (!active) return;
        if (identityResult.status === "fulfilled" && identityResult.value) {
          const storedProfile = identityResult.value;
          setProfile(storedProfile);
          setDeviceName(storedProfile.deviceName);
          setStep(3);
        } else if (identityResult.status === "rejected") {
          setError(errorMessage(identityResult.reason));
        }
        if (pendingResult.status === "fulfilled") {
          setPendingGroup(pendingResult.value[0] ?? null);
        } else {
          setError(errorMessage(pendingResult.reason));
        }
        if (joinedResult.status === "fulfilled") {
          setJoinedGroups(joinedResult.value);
        } else {
          setError(errorMessage(joinedResult.reason));
        }
        if (groupsResult.status === "fulfilled") {
          setLocalGroups(groupsResult.value);
        } else {
          setError(errorMessage(groupsResult.reason));
        }
        if (invitationsResult.status === "fulfilled") {
          setIssuedInvitations(invitationsResult.value);
        } else {
          setError(errorMessage(invitationsResult.reason));
        }
        if (joinedResult.status === "fulfilled" && groupsResult.status === "fulfilled") {
          setActiveGroupId(
            joinedResult.value[0]?.groupId ?? groupsResult.value[0]?.groupId ?? "",
          );
        }
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (!issuedInvitation) return;
    let active = true;
    let timer: number | undefined;
    const scheduleExpiry = () => {
      const remainingMs = issuedInvitation.expiresAtUnix * 1000 - Date.now();
      if (remainingMs <= 0) {
        const cleanup = isTauri()
          ? invoke<IssuedInvitation[]>("issued_invitations")
          : Promise.resolve([]);
        void cleanup
          .then((invitations) => {
            if (!active) return;
            const refreshed = invitations.find(
              (invitation) => invitation.invitationId === issuedInvitation.invitationId,
            );
            if (refreshed) {
              setIssuedInvitations((current) => current.map((invitation) =>
                invitation.invitationId === refreshed.invitationId ? refreshed : invitation));
              timer = window.setTimeout(scheduleExpiry, INVITATION_EXPIRY_CHECK_INTERVAL_MS);
            } else {
              setIssuedInvitations((current) => current.filter(
                ({ invitationId }) => invitationId !== issuedInvitation.invitationId,
              ));
              setInvitationCopied(false);
            }
          })
          .catch((reason) => {
            if (active) {
              setError(errorMessage(reason));
              timer = window.setTimeout(scheduleExpiry, INVITATION_EXPIRY_CHECK_INTERVAL_MS);
            }
          });
        return;
      }
      timer = window.setTimeout(
        scheduleExpiry,
        Math.min(remainingMs, INVITATION_EXPIRY_CHECK_INTERVAL_MS),
      );
    };
    scheduleExpiry();
    return () => {
      active = false;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [issuedInvitation]);

  useEffect(() => {
    if (!pendingGroup || !isTauri()) return;
    const groupId = pendingGroup.groupId;
    if (pendingExpiryCleanupRef.current === groupId) return;
    let active = true;
    let timer: number | undefined;
    const scheduleExpiry = () => {
      const remainingMs = pendingGroup.expiresAtUnix * 1000 - Date.now();
      if (remainingMs > 0) {
        timer = window.setTimeout(
          scheduleExpiry,
          Math.min(remainingMs, INVITATION_EXPIRY_CHECK_INTERVAL_MS),
        );
        return;
      }
      if (joiningGroup || pendingExpiryCleanupRef.current === groupId) return;
      pendingExpiryCleanupRef.current = groupId;
      setCancellingPending(true);
      void invoke("cancel_pending_invitation", { groupId })
        .then(() => {
          if (!active) return;
          setPendingGroup((current) => current?.groupId === groupId ? null : current);
          setPeerSearchResult(null);
          setError("");
        })
        .catch((reason) => {
          if (active) {
            pendingExpiryCleanupRef.current = "";
            setError(errorMessage(reason));
            timer = window.setTimeout(scheduleExpiry, INVITATION_EXPIRY_CHECK_INTERVAL_MS);
          }
        })
        .finally(() => {
          if (active) setCancellingPending(false);
        });
    };
    scheduleExpiry();
    return () => {
      active = false;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [pendingGroup, joiningGroup]);

  // One background advertisement covers every owned group, so members of a
  // group that is not open here can still join and synchronize.
  const ownedAdvertisementKey = [
    ...localGroups.map(({ groupId }) => groupId),
    ...issuedInvitations.map(({ invitationId }) => invitationId),
  ].join(",");

  useEffect(() => {
    if (!isTauri() || !ownedAdvertisementKey) {
      setAdvertisement(null);
      setAdvertisementError("");
      setAdvertisementRetrying(false);
      return;
    }
    let active = true;
    let timer: number | undefined;
    setAdvertisement(null);
    setAdvertisementError("");
    setAdvertisementRetrying(false);

    async function refreshAdvertisement() {
      try {
        const result = await invoke<AdvertisementResult>("advertise_owned_groups");
        if (!active) return;
        setAdvertisement(result);
        setAdvertisementError("");
        setAdvertisementRetrying(false);
        timer = window.setTimeout(refreshAdvertisement, ADVERTISEMENT_STATUS_INTERVAL_MS);
      } catch (reason) {
        if (!active) return;
        setAdvertisement(null);
        setAdvertisementError(errorMessage(reason));
        setAdvertisementRetrying(true);
        timer = window.setTimeout(refreshAdvertisement, ADVERTISEMENT_RETRY_INTERVAL_MS);
      }
    }

    void refreshAdvertisement();
    return () => {
      active = false;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [ownedAdvertisementKey]);

  useEffect(() => {
    if (!isTauri() || !joinedGroup) return;

    const groupId = joinedGroup.groupId;
    let active = true;
    let timer: number | undefined;

    async function synchronizePeriodically() {
      await performJoinedGroupSynchronization(groupId, false);
      if (active) {
        timer = window.setTimeout(synchronizePeriodically, JOINED_GROUP_SYNC_INTERVAL_MS);
      }
    }

    timer = window.setTimeout(synchronizePeriodically, JOINED_GROUP_SYNC_START_DELAY_MS);
    return () => {
      active = false;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [joinedGroup]);

  useEffect(() => {
    let active = true;
    setInvitationQrCode("");
    setInvitationQrError("");
    if (!issuedInvitation) return;

    void QRCode.toDataURL(issuedInvitation.link, {
      color: { dark: "#172044", light: "#ffffff" },
      errorCorrectionLevel: "M",
      margin: 2,
      width: 320,
    })
      .then((dataUrl) => {
        if (active) setInvitationQrCode(dataUrl);
      })
      .catch(() => {
        if (active) setInvitationQrError("The QR code could not be created. Copy the invitation link instead.");
      });

    return () => {
      active = false;
    };
  }, [issuedInvitation]);

  useEffect(() => {
    setEvidenceSelection(null);
    setEvidenceText("");
  }, [localGroup?.groupId, joinedGroup?.groupId]);

  useEffect(() => {
    const groupId = localGroup?.groupId ?? joinedGroup?.groupId;
    if (!isTauri() || !groupId) {
      setGroupMessages([]);
      setHasEarlierMessages(false);
      return;
    }

    let active = true;
    let firstLoad = true;
    let timer: number | undefined;

    async function refreshMessages() {
      try {
        const page = await invoke<StoredMessagePage>("group_messages", { groupId });
        if (active) {
          setGroupMessages(page.messages);
          setHasEarlierMessages(page.hasEarlier);
        }
      } catch (reason) {
        if (active && firstLoad) setError(errorMessage(reason));
      } finally {
        firstLoad = false;
        if (active) {
          timer = window.setTimeout(refreshMessages, MESSAGE_REFRESH_INTERVAL_MS);
        }
      }
    }

    void refreshMessages();
    return () => {
      active = false;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [joinedGroup, localGroup]);

  useEffect(() => {
    if (!isTauri() || availableGroups.length === 0) {
      setUnreadCounts({});
      setConnectionStates({});
      return;
    }

    let active = true;
    let timer: number | undefined;

    async function refreshUnreadCounts() {
      try {
        const counts = await invoke<UnreadMessageCount[]>("unread_message_counts");
        if (active) {
          setUnreadCounts(
            Object.fromEntries(counts.map(({ groupId, count }) => [groupId, count])),
          );
        }
      } catch {
        // Unread badges are advisory; the active timeline reports its own errors.
      }
      try {
        const states = await invoke<GroupConnectionState[]>("group_connection_states");
        if (active) {
          setConnectionStates(
            Object.fromEntries(states.map(({ groupId, state }) => [groupId, state])),
          );
        }
      } catch {
        // Connection states are advisory; synchronization reports its own errors.
      } finally {
        if (active) {
          timer = window.setTimeout(refreshUnreadCounts, MESSAGE_REFRESH_INTERVAL_MS);
        }
      }
    }

    void refreshUnreadCounts();
    return () => {
      active = false;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [availableGroups.length]);

  useEffect(() => {
    const groupId = localGroup?.groupId ?? joinedGroup?.groupId;
    setShowMembers(false);
    if (!isTauri() || !groupId) {
      setGroupMembers([]);
      setBlockedDevices([]);
      setMemberActivity({});
      setMembersError("");
      return;
    }

    let active = true;
    let firstLoad = true;
    let timer: number | undefined;

    async function refreshMembers() {
      try {
        const [members, blocked, activity] = await Promise.all([
          invoke<GroupMemberDevice[]>("group_members", { groupId }),
          invoke<string[]>("blocked_group_devices", { groupId }),
          invoke<MemberActivity[]>("group_member_activity", { groupId }),
        ]);
        if (active) {
          setGroupMembers(members);
          setBlockedDevices(blocked);
          setMemberActivity(Object.fromEntries(activity.map((entry) => [entry.deviceId, entry.lastSignedAtUnixMs])));
          setMembersError("");
        }
      } catch (reason) {
        if (active && firstLoad) setMembersError(errorMessage(reason));
      } finally {
        firstLoad = false;
        if (active) timer = window.setTimeout(refreshMembers, MEMBER_REFRESH_INTERVAL_MS);
      }
    }

    void refreshMembers();
    return () => {
      active = false;
      if (timer !== undefined) window.clearTimeout(timer);
    };
  }, [joinedGroup, localGroup]);

  useEffect(() => {
    if (!isTauri()) return;

    let active = true;
    let stopListening: (() => void) | undefined;

    async function openInvitation(urls: string[] | null) {
      const input = urls?.find((url) => url.startsWith("charp2p://join/"));
      if (!active || !input) return;

      setError("");
      setJoinMode(true);
      setCreateGroupMode(false);
      setInviteInput(input);
      setInvitationPreview(null);
      setVerifyingInvite(true);
      try {
        const preview = await invoke<InvitationPreview>("preview_invitation", { input });
        if (active) setInvitationPreview(preview);
      } catch (reason) {
        if (active) setError(errorMessage(reason));
      } finally {
        if (active) setVerifyingInvite(false);
      }
    }

    void getCurrent().then(openInvitation).catch(() => {
      if (active) setError("The invitation link could not be opened.");
    });
    void onOpenUrl((urls) => void openInvitation(urls))
      .then((unlisten) => {
        if (active) stopListening = unlisten;
        else unlisten();
      })
      .catch(() => {
        if (active) setError("Invitation links are unavailable on this device.");
      });

    return () => {
      active = false;
      stopListening?.();
    };
  }, []);

  async function createIdentity(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!deviceName.trim() || saving) return;

    setError("");
    setSaving(true);
    try {
      const createdProfile = isTauri()
        ? await invoke<DeviceProfile>("create_identity", { deviceName })
        : { deviceName: deviceName.trim(), peerId: "12D3KooWPreviewIdentity" };
      setProfile(createdProfile);
      setDeviceName(createdProfile.deviceName);
      setStep(2);
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setSaving(false);
    }
  }

  async function verifyInvitation(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!inviteInput.trim() || verifyingInvite || !isTauri()) return;

    setError("");
    setVerifyingInvite(true);
    try {
      const preview = await invoke<InvitationPreview>("preview_invitation", {
        input: inviteInput,
      });
      setInvitationPreview(preview);
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setVerifyingInvite(false);
    }
  }

  async function acceptInvitation() {
    if (!inviteInput.trim() || acceptingInvite || !isTauri()) return;

    setError("");
    setAcceptingInvite(true);
    try {
      const accepted = await invoke<PendingGroup>("accept_invitation", {
        input: inviteInput,
      });
      pendingExpiryCleanupRef.current = "";
      setPendingGroup(accepted);
      setPeerSearchResult(null);
      setInvitationPreview(null);
      setInviteInput("");
      setJoinMode(false);
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setAcceptingInvite(false);
    }
  }

  async function searchForPeers() {
    if (!pendingGroup || searchingPeers || !isTauri()) return;

    setError("");
    setSearchingPeers(true);
    try {
      const result = await invoke<PeerSearchResult>("search_group_peers", {
        groupId: pendingGroup.groupId,
      });
      setPeerSearchResult(result);
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setSearchingPeers(false);
    }
  }

  async function joinPendingGroup() {
    if (!pendingGroup || joiningGroup || !isTauri()) return;

    setError("");
    setJoiningGroup(true);
    try {
      const joined = await invoke<JoinedGroup>("join_group", {
        groupId: pendingGroup.groupId,
      });
      setJoinedGroups((groups) => [
        ...groups.filter(({ groupId }) => groupId !== joined.groupId),
        joined,
      ]);
      setActiveGroupId(joined.groupId);
      setSynchronizationResult(null);
      pendingExpiryCleanupRef.current = "";
      setPendingGroup(null);
      setPeerSearchResult(null);
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setJoiningGroup(false);
    }
  }

  async function cancelPendingInvitation() {
    if (!pendingGroup || cancellingPending || !isTauri()) return;
    if (!window.confirm("Remove this saved invitation from this device?")) return;

    setError("");
    pendingExpiryCleanupRef.current = pendingGroup.groupId;
    setCancellingPending(true);
    try {
      await invoke("cancel_pending_invitation", {
        groupId: pendingGroup.groupId,
      });
      pendingExpiryCleanupRef.current = "";
      setPendingGroup(null);
      setPeerSearchResult(null);
    } catch (reason) {
      pendingExpiryCleanupRef.current = "";
      setError(errorMessage(reason));
    } finally {
      setCancellingPending(false);
    }
  }

  async function performJoinedGroupSynchronization(groupId: string, reportErrors: boolean) {
    if (synchronizationInFlight.current || !isTauri()) return;

    synchronizationInFlight.current = true;
    if (reportErrors && activeGroupIdRef.current === groupId) {
      setError("");
      setSynchronizationResult(null);
    }
    if (activeGroupIdRef.current === groupId) setSynchronizingGroup(true);
    try {
      const result = await invoke<SynchronizeGroupResult>("synchronize_group", {
        groupId,
      });
      const refreshedGroups = await invoke<JoinedGroup[]>("joined_groups");
      setJoinedGroups((groups) => groups.map((group) => {
        const refreshed = refreshedGroups.find((candidate) => candidate.groupId === group.groupId);
        return group.groupId === groupId
          ? { ...group, groupName: refreshed?.groupName ?? group.groupName, lastSynchronizedAtUnix: result.synchronizedAtUnix }
          : group;
      }));
      if (activeGroupIdRef.current === groupId) {
        setSynchronizationResult(result);
        const page = await invoke<StoredMessagePage>("group_messages", { groupId });
        if (activeGroupIdRef.current === groupId) {
          setGroupMessages(page.messages);
          setHasEarlierMessages(page.hasEarlier);
        }
      }
    } catch (reason) {
      if (reportErrors && activeGroupIdRef.current === groupId) setError(errorMessage(reason));
    } finally {
      try {
        const states = await invoke<GroupConnectionState[]>("group_connection_states");
        setConnectionStates(
          Object.fromEntries(states.map(({ groupId: id, state }) => [id, state])),
        );
      } catch {
        // Connection states are advisory and refreshed periodically.
      }
      synchronizationInFlight.current = false;
      if (activeGroupIdRef.current === groupId) setSynchronizingGroup(false);
    }
  }

  async function synchronizeJoinedGroup() {
    if (!joinedGroup) return;
    await performJoinedGroupSynchronization(joinedGroup.groupId, true);
  }

  async function removeGroupMember(memberDeviceId: string) {
    if (!localGroup || removingMember || !isTauri()) return;
    if (!window.confirm("Remove this device from the group? It will lose access to future messages.")) return;
    setMembersError("");
    setRemovingMember(memberDeviceId);
    try {
      const members = await invoke<GroupMemberDevice[]>("remove_group_member", {
        groupId: localGroup.groupId,
        memberDeviceId,
      });
      setGroupMembers(members);
    } catch (reason) {
      setMembersError(errorMessage(reason));
    } finally {
      setRemovingMember("");
    }
  }

  async function setDeviceBlocked(deviceId: string, blocked: boolean) {
    const groupId = localGroup?.groupId ?? joinedGroup?.groupId;
    if (!groupId || blockingDevice || !isTauri()) return;
    if (blocked && !window.confirm("Block this device on this device only? Its messages will be hidden here, but it stays a member and others still see its messages.")) return;
    setMembersError("");
    setBlockingDevice(deviceId);
    try {
      setBlockedDevices(await invoke<string[]>("set_group_device_blocked", { groupId, deviceId, blocked }));
    } catch (reason) {
      setMembersError(errorMessage(reason));
    } finally {
      setBlockingDevice("");
    }
  }

  async function leaveJoinedGroup() {
    if (!joinedGroup || leavingGroup || !isTauri()) return;
    if (!window.confirm(`Leave ${joinedGroup.groupName}? Its messages and keys will be deleted from this device. You need a new invitation to join again.`)) return;
    const groupId = joinedGroup.groupId;
    setMembersError("");
    setLeavingGroup(true);
    try {
      await invoke("leave_joined_group", { groupId });
      const remaining = joinedGroups.filter((group) => group.groupId !== groupId);
      setJoinedGroups(remaining);
      setUnreadCounts((counts) => {
        const { [groupId]: _left, ...rest } = counts;
        return rest;
      });
      setShowMembers(false);
      setActiveGroupId(remaining[0]?.groupId ?? localGroups[0]?.groupId ?? "");
    } catch (reason) {
      setMembersError(errorMessage(reason));
    } finally {
      setLeavingGroup(false);
    }
  }

  async function renameLocalGroup(requested: string) {
    const groupId = localGroup?.groupId;
    if (!groupId || !isTauri()) return;
    await invoke("rename_group", { groupId, groupName: requested });
    setLocalGroups(await invoke<LocalGroup[]>("local_groups"));
  }

  async function sendGroupMessage(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const groupId = localGroup?.groupId ?? joinedGroup?.groupId;
    if (
      !groupId
      || !outgoingMessage.trim()
      || outgoingMessageBytes > MESSAGE_TEXT_LIMIT_BYTES
      || sendingMessage
      || !isTauri()
    ) return;

    setError("");
    setCreatedMessage(null);
    setSendingMessage(true);
    const text = outgoingMessage;
    const replyToEventId = replyingTo?.groupId === groupId ? replyingTo.eventId : null;
    try {
      const created = await invoke<CreatedMessage>("send_group_message", {
        groupId,
        message: text,
        replyToEventId,
      });
      setCreatedMessage(created);
      setGroupMessages((messages) => [
        ...messages,
        {
          eventId: created.eventId,
          groupId: created.groupId,
          authorId: created.authorId,
          authorSequence: created.authorSequence,
          createdAtUnixMs: created.createdAtUnixMs,
          text,
          edited: false,
          replyToEventId,
          deliveryState: "local",
        },
      ]);
      setOutgoingMessage("");
      setReplyingTo(null);
      if (joinedGroup?.groupId === groupId) {
        void performJoinedGroupSynchronization(groupId, false);
      }
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setSendingMessage(false);
    }
  }

  async function copyMessage(message: StoredMessage) {
    try {
      await navigator.clipboard.writeText(message.text);
    } catch {
      setError("The message could not be copied.");
    }
  }

  async function saveMessageEdit(message: StoredMessage) {
    if (!editingMessage || editingMessage.eventId !== message.eventId || savingEdit || !isTauri()) return;
    const text = editingMessage.text;
    if (!text.trim() || new TextEncoder().encode(text).length > MESSAGE_TEXT_LIMIT_BYTES) {
      setError(errorMessage("message_invalid"));
      return;
    }
    if (text === message.text) {
      setEditingMessage(null);
      return;
    }

    setError("");
    setSavingEdit(true);
    try {
      await invoke("edit_group_message", {
        groupId: message.groupId,
        eventId: message.eventId,
        message: text,
      });
      setGroupMessages((messages) => messages.map((candidate) => (
        candidate.eventId === message.eventId ? { ...candidate, text, edited: true } : candidate
      )));
      setEditingMessage(null);
      if (joinedGroup?.groupId === message.groupId) {
        void performJoinedGroupSynchronization(message.groupId, false);
      }
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setSavingEdit(false);
    }
  }

  function messageSnippet(text: string) {
    return text.length > 80 ? `${text.slice(0, 80)}…` : text;
  }

  function renderReplyQuote(message: StoredMessage) {
    if (!message.replyToEventId) return null;
    const target = groupMessages.find((candidate) => candidate.eventId === message.replyToEventId);
    return (
      <blockquote className="message-reply-quote">
        {target ? messageSnippet(target.text) : "Reply to a message not shown on this device"}
      </blockquote>
    );
  }

  function renderReplyDraft(groupId: string) {
    if (replyingTo?.groupId !== groupId) return null;
    return (
      <div className="message-reply-draft">
        <blockquote className="message-reply-quote">Replying to: {messageSnippet(replyingTo.text)}</blockquote>
        <button disabled={sendingMessage} onClick={() => setReplyingTo(null)} type="button">Cancel reply</button>
      </div>
    );
  }

  function renderMessageText(message: StoredMessage) {
    if (editingMessage?.eventId !== message.eventId) return <p>{message.text}</p>;
    return (
      <form className="message-edit" onSubmit={(event) => { event.preventDefault(); void saveMessageEdit(message); }}>
        <textarea
          aria-label="Edit message"
          maxLength={16384}
          onChange={(event) => setEditingMessage({ eventId: message.eventId, text: event.target.value })}
          value={editingMessage.text}
        />
        <div className="message-actions">
          <button disabled={savingEdit} onClick={() => setEditingMessage(null)} type="button">Cancel</button>
          <button disabled={savingEdit || !editingMessage.text.trim()} type="submit">
            {savingEdit ? "Saving…" : "Save edit"}
          </button>
        </div>
      </form>
    );
  }

  async function hideMessage(message: StoredMessage) {
    if (deletingMessage || !isTauri()) return;
    if (!window.confirm("Delete this message from this device? Other group members will keep their copies.")) return;

    setError("");
    setDeletingMessage(message.eventId);
    try {
      await invoke("hide_group_message", {
        groupId: message.groupId,
        eventId: message.eventId,
      });
      setGroupMessages((messages) => messages.filter(({ eventId }) => eventId !== message.eventId));
      if (createdMessage?.eventId === message.eventId) setCreatedMessage(null);
      if (replyingTo?.eventId === message.eventId) setReplyingTo(null);
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setDeletingMessage("");
    }
  }

  function toggleEvidenceMessage(eventId: string) {
    setEvidenceSelection((selection) => {
      if (!selection) return selection;
      if (selection.includes(eventId)) return selection.filter((candidate) => candidate !== eventId);
      return selection.length >= EVIDENCE_EVENT_LIMIT ? selection : [...selection, eventId];
    });
  }

  async function exportEvidence(groupId: string) {
    if (!evidenceSelection?.length || exportingEvidence || !isTauri()) return;
    setError("");
    setExportingEvidence(true);
    try {
      const evidence = await invoke<EvidenceExport>("export_message_evidence", {
        groupId,
        eventIds: evidenceSelection,
      });
      const text = JSON.stringify(evidence, null, 2);
      const url = URL.createObjectURL(new Blob([text], { type: "application/json" }));
      const link = document.createElement("a");
      link.href = url;
      link.download = `charp2p-evidence-${evidence.generatedAtUnixMs}.json`;
      link.click();
      URL.revokeObjectURL(url);
      setEvidenceText(text);
      setEvidenceSelection(null);
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setExportingEvidence(false);
    }
  }

  function renderEvidenceControls(groupId: string) {
    return (
      <div className="evidence-controls">
        {evidenceSelection ? (
          <>
            <span>{evidenceSelection.length} selected (up to {EVIDENCE_EVENT_LIMIT})</span>
            <button onClick={() => setEvidenceSelection(null)} type="button">Cancel</button>
            <button
              disabled={!evidenceSelection.length || exportingEvidence || !isTauri()}
              onClick={() => void exportEvidence(groupId)}
              type="button"
            >
              {exportingEvidence ? "Exporting…" : "Export evidence"}
            </button>
          </>
        ) : (
          <button onClick={() => { setEvidenceSelection([]); setEvidenceText(""); }} type="button">
            Select messages for evidence
          </button>
        )}
      </div>
    );
  }

  function renderEvidenceCheckbox(message: StoredMessage) {
    if (!evidenceSelection) return null;
    return (
      <label className="evidence-select">
        <input
          checked={evidenceSelection.includes(message.eventId)}
          onChange={() => toggleEvidenceMessage(message.eventId)}
          type="checkbox"
        />
        Include in evidence
      </label>
    );
  }

  function renderEvidenceResult() {
    if (!evidenceText) return null;
    return (
      <div className="evidence-result">
        <p className="preview-note">
          The export contains the signed events and the text shown here. Signatures prove which device sent each
          event; the readable text is your copy and is not covered by them. Share it only with people you choose.
        </p>
        <textarea aria-label="Evidence export" className="backup-text" readOnly rows={6} value={evidenceText} />
        <button
          className="secondary-button"
          onClick={() => void navigator.clipboard.writeText(evidenceText).catch(() => setError("The evidence could not be copied."))}
          type="button"
        >
          Copy evidence
        </button>
        <button className="secondary-button" onClick={() => setEvidenceText("")} type="button">Close</button>
      </div>
    );
  }

  async function createGroup(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!groupName.trim() || creatingGroup || !isTauri()) return;

    setError("");
    setCreatingGroup(true);
    try {
      const created = await invoke<LocalGroup>("create_group", {
        groupName,
        icon: groupIcon,
        historyPolicy: "none",
        approvalRequired: false,
        invitationLifetimeSeconds: invitationLifetime,
        reusableInvitation: true,
      });
      setLocalGroups((groups) => [
        ...groups.filter(({ groupId }) => groupId !== created.groupId),
        created,
      ]);
      setActiveGroupId(created.groupId);
      setInvitationCopied(false);
      setGroupName(created.groupName);
      setCreateGroupMode(false);
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setCreatingGroup(false);
    }
  }

  async function createInvitation() {
    if (!localGroup || creatingInvitation || !isTauri()) return;

    setError("");
    setInvitationCopied(false);
    setCreatingInvitation(true);
    try {
      const invitation = await invoke<IssuedInvitation>("create_group_invitation", {
        groupId: localGroup.groupId,
      });
      setIssuedInvitations((current) => [
        ...current.filter(({ groupId }) => groupId !== invitation.groupId),
        invitation,
      ]);
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setCreatingInvitation(false);
    }
  }

  async function copyInvitation() {
    if (!issuedInvitation) return;
    try {
      await navigator.clipboard.writeText(issuedInvitation.link);
      setInvitationCopied(true);
      setError("");
    } catch {
      setError("The invitation could not be copied. Select the link and copy it manually.");
    }
  }

  async function revokeInvitation() {
    if (!localGroup || !issuedInvitation || revokingInvitation || !isTauri()) return;
    if (!window.confirm("Revoke this invitation? Anyone who has not joined yet will lose access.")) return;
    setError("");
    setRevokingInvitation(true);
    try {
      const groupId = localGroup.groupId;
      await invoke("revoke_group_invitation", { groupId });
      setIssuedInvitations((current) => current.filter((invitation) => invitation.groupId !== groupId));
      setInvitationCopied(false);
      setAdvertisement(null);
      setAdvertisementError("");
      setAdvertisementRetrying(false);
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setRevokingInvitation(false);
    }
  }

  function closeJoinFlow() {
    setJoinMode(false);
    setInviteInput("");
    setInvitationPreview(null);
    setError("");
  }

  return (
    <main className="onboarding-shell">
      <section className="brand-panel" aria-labelledby="brand-title">
        <div className="brand-lockup">
          <BrandMark decorative />
          <h1 id="brand-title">Char<span>P2P</span></h1>
        </div>
        <p>Private groups. Direct connections.</p>
        <NetworkArtwork />
      </section>

      <section className="setup-panel">
        <div className="setup-content">
          {informationView ? (
            <InformationView view={informationView} onClose={() => setInformationView(null)} />
          ) : networkView ? (
            <NetworkView onClose={() => setNetworkView(false)} />
          ) : settingsView ? (
            <SettingsView onClose={() => setSettingsView(false)} />
          ) : backupView && profile ? (
            <IdentityBackupView profile={profile} onClose={() => setBackupView(false)} />
          ) : restoreView && !profile ? (
            <RestoreBackupView
              onClose={() => setRestoreView(false)}
              onRestored={(restored) => {
                setProfile(restored);
                setDeviceName(restored.deviceName);
                setRestoreView(false);
                setStep(3);
              }}
            />
          ) : (
            <>
              <Stepper step={step} />

          {loading && (
            <div className="loading-state" role="status">
              <span aria-hidden="true" />
              Opening protected device storage…
            </div>
          )}

          {!loading && step === 1 && (
            <form className="setup-form" onSubmit={createIdentity}>
              <header>
                <p className="eyebrow">Welcome to CharP2P</p>
                <h2>Set up this device</h2>
                <p>Your identity stays on this device.</p>
              </header>

              <label htmlFor="device-name">Device name</label>
              <input
                autoComplete="off"
                autoFocus
                id="device-name"
                maxLength={48}
                onChange={(event) => setDeviceName(event.target.value)}
                placeholder={suggestedName}
                value={deviceName}
              />

              {error && <p className="form-error" role="alert">{error}</p>}

              <button className="primary-button" disabled={!deviceName.trim() || saving} type="submit">
                <span aria-hidden="true">＋</span>
                {saving ? "Creating identity…" : "Create identity"}
              </button>
              <button className="secondary-button" disabled={saving} onClick={() => { setError(""); setRestoreView(true); }} type="button">
                <span aria-hidden="true">↶</span>
                Restore from backup
              </button>
            </form>
          )}

          {step === 2 && (
            <section className="setup-form recovery-card">
              <header>
                <p className="eyebrow">Identity created</p>
                <h2>Protect your identity</h2>
                <p>Save an encrypted recovery copy before joining a group.</p>
              </header>
              <div className="device-summary">
                <BrandMark decorative />
                <div>
                  <strong>{profile?.deviceName ?? deviceName}</strong>
                  <span>Protected by this device</span>
                  {profile && <code>{shortPeerId(profile.peerId)}</code>}
                </div>
              </div>
              <button className="primary-button" disabled={!profile} onClick={() => setBackupView(true)} type="button">
                Create recovery copy
              </button>
              <button className="text-button" onClick={() => setStep(3)} type="button">
                Do this later
              </button>
            </section>
          )}

          {step === 3 && pendingGroup && !joinMode && (
            <section className="setup-form pending-card">
              <div className="pending-icon" aria-hidden="true">⌁</div>
              <header>
                <p className="eyebrow">Pending group</p>
                <h2>Invitation saved</h2>
                <p>{pendingGroup.groupName} is ready for peer discovery.</p>
              </header>
              <div className="status-row" aria-label="Join status">
                <span className="status-chip">✓ Verified invitation</span>
                <span className="status-chip muted">○ {searchingPeers ? "Searching…" : peerSearchDescription(peerSearchResult)}</span>
              </div>
              <dl className="preview-facts">
                <div><dt>Invited by</dt><dd>{pendingGroup.inviterName}</dd></div>
                <div><dt>History</dt><dd>{historyDescription(pendingGroup.historyPolicy)}</dd></div>
                <div><dt>Invitation</dt><dd>{expiryDescription(pendingGroup.expiresAtUnix)}</dd></div>
                <div><dt>Group fingerprint</dt><dd><code title={pendingGroup.groupId}>{shortPeerId(pendingGroup.groupId)}</code></dd></div>
                <div><dt>Inviter device</dt><dd><code title={pendingGroup.inviterDeviceId}>{shortPeerId(pendingGroup.inviterDeviceId)}</code></dd></div>
              </dl>
              {error && <p className="form-error preview-error" role="alert">{error}</p>}
              <p className="preview-note">Your invitation is stored securely until the invited owner is online.</p>
              <button className="primary-button join-button" disabled={joiningGroup || searchingPeers || cancellingPending || !isTauri()} onClick={joinPendingGroup} type="button">
                {joiningGroup ? "Joining securely…" : "Connect and join"}
              </button>
              <button className="secondary-button" disabled={joiningGroup || searchingPeers || cancellingPending || !isTauri()} onClick={searchForPeers} type="button">
                {searchingPeers ? "Checking availability…" : "Check peer availability"}
              </button>
              <button className="text-button" disabled={joiningGroup || searchingPeers || cancellingPending || !isTauri()} onClick={cancelPendingInvitation} type="button">
                {cancellingPending ? "Removing…" : "Remove invitation"}
              </button>
            </section>
          )}

          {step === 3 && !pendingGroup && !joinMode && !createGroupMode && !showMembers && availableGroups.length > 0 && (
            <nav className="group-switcher" aria-label="Your groups">
              <div className="group-switcher-list">
                {availableGroups.map((group) => (
                  <button
                    aria-current={group.groupId === activeGroupId ? "page" : undefined}
                    className={group.groupId === activeGroupId ? "active" : ""}
                    key={group.groupId}
                    onClick={() => {
                      setActiveGroupId(group.groupId);
                      setError("");
                      setInvitationCopied(false);
                      setSynchronizationResult(null);
                      setSynchronizingGroup(false);
                      setCreatedMessage(null);
                    }}
                    type="button"
                  >
                    <strong>{group.groupName}</strong>
                    <span>
                      {group.role}
                      {connectionStates[group.groupId] && (
                        <i className={`group-connection ${connectionStates[group.groupId]}`}>
                          {groupConnectionDescription(connectionStates[group.groupId])}
                        </i>
                      )}
                      {group.groupId !== activeGroupId && (unreadCounts[group.groupId] ?? 0) > 0 && (
                        <em
                          aria-label={`${unreadCounts[group.groupId]} unread`}
                          className="unread-count"
                        >
                          {unreadCounts[group.groupId] > 99 ? "99+" : unreadCounts[group.groupId]}
                        </em>
                      )}
                    </span>
                  </button>
                ))}
              </div>
              <button
                className="group-switcher-join"
                onClick={() => {
                  setJoinMode(true);
                  setError("");
                }}
                type="button"
              >
                ＋ Join another group
              </button>
              <button
                className="group-switcher-join"
                onClick={() => {
                  setCreateGroupMode(true);
                  setError("");
                }}
                type="button"
              >
                ＋ Create a group
              </button>
            </nav>
          )}

          {step === 3 && showMembers && !pendingGroup && !joinMode && !createGroupMode && (joinedGroup || localGroup) && (
            <MembersView
              groupName={(joinedGroup ?? localGroup)!.groupName}
              members={groupMembers}
              memberActivity={memberActivity}
              error={membersError}
              canManageMembers={Boolean(localGroup)}
              removingDeviceId={removingMember}
              onRemove={removeGroupMember}
              blockedDeviceIds={blockedDevices}
              blockingDeviceId={blockingDevice}
              onToggleBlock={setDeviceBlocked}
              onRename={renameLocalGroup}
              onLeave={joinedGroup ? leaveJoinedGroup : null}
              leaving={leavingGroup}
              onClose={() => setShowMembers(false)}
              ownerDeviceId={joinedGroup?.inviterDeviceId ?? profile?.peerId ?? ""}
              ownerName={joinedGroup?.inviterName ?? profile?.deviceName ?? "Owner"}
              profile={profile}
            />
          )}

          {step === 3 && joinedGroup && !pendingGroup && !joinMode && !createGroupMode && !showMembers && (
            <section className="setup-form joined-card">
              <div className="ready-check" aria-hidden="true">✓</div>
              <header>
                <p className="eyebrow">Joined securely</p>
                <h2>{joinedGroup.groupName}</h2>
                <p>Your membership is protected on this device.</p>
              </header>
              <div className="status-row" aria-label="Group status">
                <span className="status-chip">✓ Secure membership ready</span>
                <span className={`status-chip ${synchronizationResult ? "" : "muted"}`}>
                  {synchronizingGroup
                    ? "○ Synchronizing…"
                    : synchronizationResult
                      ? `✓ ${synchronizationResult.synchronizedEvents} received · ${synchronizationResult.uploadedEvents} shared · ${connectionTypeDescription(synchronizationResult.connectionType)}`
                      : "○ Sync not checked"}
                </span>
              </div>
              <dl className="preview-facts">
                <div><dt>Invited by</dt><dd>{joinedGroup.inviterName}</dd></div>
                <div><dt>History</dt><dd>{historyDescription(joinedGroup.historyPolicy)}</dd></div>
                <div><dt>Group fingerprint</dt><dd><code title={joinedGroup.groupId}>{shortPeerId(joinedGroup.groupId)}</code></dd></div>
                <div><dt>Inviter device</dt><dd><code title={joinedGroup.inviterDeviceId}>{shortPeerId(joinedGroup.inviterDeviceId)}</code></dd></div>
                <div><dt>Last synchronized</dt><dd>{synchronizationDescription(joinedGroup.lastSynchronizedAtUnix)}</dd></div>
                <div><dt>Connection</dt><dd>{connectionStates[joinedGroup.groupId] ? groupConnectionDescription(connectionStates[joinedGroup.groupId]) : "Not checked"}</dd></div>
              </dl>
              <button className="secondary-button members-button" onClick={() => setShowMembers(true)} type="button">
                Members &amp; devices{groupMembers.length > 0 ? ` (${groupMembers.length})` : ""}
              </button>
              {groupMessages.length > 0 && (
                <section className="message-timeline" aria-label="Messages saved on this device">
                  <h3>Messages</h3>
                  {renderEvidenceControls(joinedGroup.groupId)}
                  {renderEvidenceResult()}
                  {groupMessages.map((message) => (
                    <article
                      className={`message-bubble ${message.authorId === profile?.peerId ? "own-message" : ""}`}
                      key={message.eventId}
                    >
                      {renderEvidenceCheckbox(message)}
                      {renderReplyQuote(message)}
                      {renderMessageText(message)}
                      <time dateTime={new Date(message.createdAtUnixMs).toISOString()}>
                        {messageAuthorLabel(message, profile, joinedGroup)}
                        {" · "}{messageTime(message.createdAtUnixMs)}
                        {message.edited && " · Edited"}
                        {message.authorId === profile?.peerId && (
                          <>{" · "}{messageDeliveryLabel(message)}</>
                        )}
                      </time>
                      <div className="message-actions">
                        <button onClick={() => setReplyingTo(message)} type="button">Reply</button>
                        <button onClick={() => void copyMessage(message)} type="button">Copy</button>
                        {message.authorId === profile?.peerId && editingMessage?.eventId !== message.eventId && (
                          <button
                            disabled={savingEdit}
                            onClick={() => setEditingMessage({ eventId: message.eventId, text: message.text })}
                            type="button"
                          >
                            Edit
                          </button>
                        )}
                        <button
                          disabled={Boolean(deletingMessage)}
                          onClick={() => void hideMessage(message)}
                          type="button"
                        >
                          {deletingMessage === message.eventId ? "Deleting…" : "Delete here"}
                        </button>
                      </div>
                    </article>
                  ))}
                  {hasEarlierMessages && (
                    <p className="preview-note">Showing the latest 256 messages stored on this device.</p>
                  )}
                </section>
              )}
              <form className="message-composer" onSubmit={sendGroupMessage}>
                {renderReplyDraft(joinedGroup.groupId)}
                <label htmlFor="joined-outgoing-message">Protected message</label>
                <textarea
                  aria-describedby="joined-message-size"
                  id="joined-outgoing-message"
                  maxLength={16384}
                  onChange={(event) => setOutgoingMessage(event.target.value)}
                  placeholder="Write a message for the group"
                  rows={3}
                  value={outgoingMessage}
                />
                <p
                  className={`message-size ${outgoingMessageBytes > MESSAGE_TEXT_LIMIT_BYTES ? "over-limit" : ""}`}
                  id="joined-message-size"
                >
                  {outgoingMessageBytes.toLocaleString()} / {MESSAGE_TEXT_LIMIT_BYTES.toLocaleString()} bytes
                </p>
                <button
                  className="secondary-button"
                  disabled={!outgoingMessage.trim() || outgoingMessageBytes > MESSAGE_TEXT_LIMIT_BYTES || sendingMessage || !isTauri()}
                  type="submit"
                >
                  {sendingMessage ? "Protecting message…" : "Protect and send"}
                </button>
                {createdMessage && (
                  <p className="message-receipt" role="status">
                    {(groupMessages.find(({ eventId }) => eventId === createdMessage.eventId)?.deliveryState ?? "local") !== "local"
                      ? `✓ Encrypted event ${createdMessage.authorSequence} shared with the owner.`
                      : `✓ Encrypted event ${createdMessage.authorSequence} saved. It will sync when the owner is reachable.`}
                  </p>
                )}
              </form>
              {error && <p className="form-error preview-error" role="alert">{error}</p>}
              <p className="preview-note">Secure membership and verified group state are stored on this device.</p>
              <button className="secondary-button" disabled={synchronizingGroup || !isTauri()} onClick={synchronizeJoinedGroup} type="button">
                {synchronizingGroup ? "Synchronizing securely…" : "Sync now"}
              </button>
            </section>
          )}

          {step === 3 && localGroup && !pendingGroup && !joinedGroup && !joinMode && !createGroupMode && !showMembers && (
            <section className="setup-form group-ready-card">
              <div className={`group-avatar icon-${localGroup.icon}`} aria-hidden="true">
                {['●●●', '◆', '▲', '♥', '★'][localGroup.icon]}
              </div>
              <header>
                <p className="eyebrow">Group created</p>
                <h2>{localGroup.groupName}</h2>
                <p>The owner identity is protected on this device.</p>
              </header>
              <dl className="preview-facts">
                <div><dt>History</dt><dd>{historyDescription(localGroup.historyPolicy)}</dd></div>
                <div><dt>Join mode</dt><dd>Valid invitation grants access</dd></div>
                <div><dt>Invitation expiry</dt><dd>{localGroup.invitationLifetimeSeconds / 86400} days</dd></div>
                <div><dt>Group fingerprint</dt><dd><code title={localGroup.groupId}>{shortPeerId(localGroup.groupId)}</code></dd></div>
              </dl>
              <button className="secondary-button members-button" onClick={() => setShowMembers(true)} type="button">
                Members &amp; devices{groupMembers.length > 0 ? ` (${groupMembers.length})` : ""}
              </button>
              <div className="status-row" aria-label="Member synchronization status">
                <span className={`status-chip ${advertisement?.status === "advertising" ? "" : "muted"}`}>
                  {advertisement?.status === "advertising"
                    ? "● Available for member sync"
                    : advertisement?.status === "bootstrapRequired"
                      ? "○ Bootstrap node needed"
                      : advertisementRetrying
                        ? "○ Peer advertising failed · Retrying…"
                        : "○ No member rendezvous key yet"}
                </span>
              </div>
              {advertisementError && <p className="form-error preview-error" role="alert">{advertisementError}</p>}
              <form className="message-composer" onSubmit={sendGroupMessage}>
                {renderReplyDraft(localGroup.groupId)}
                <label htmlFor="outgoing-message">Protected message</label>
                <textarea
                  aria-describedby="owner-message-size"
                  id="outgoing-message"
                  maxLength={16384}
                  onChange={(event) => setOutgoingMessage(event.target.value)}
                  placeholder="Write a message for the group"
                  rows={3}
                  value={outgoingMessage}
                />
                <p
                  className={`message-size ${outgoingMessageBytes > MESSAGE_TEXT_LIMIT_BYTES ? "over-limit" : ""}`}
                  id="owner-message-size"
                >
                  {outgoingMessageBytes.toLocaleString()} / {MESSAGE_TEXT_LIMIT_BYTES.toLocaleString()} bytes
                </p>
                <button
                  className="secondary-button"
                  disabled={!outgoingMessage.trim() || outgoingMessageBytes > MESSAGE_TEXT_LIMIT_BYTES || sendingMessage || !isTauri()}
                  type="submit"
                >
                  {sendingMessage ? "Protecting message…" : "Save encrypted message"}
                </button>
                {createdMessage && (
                  <p className="message-receipt" role="status">
                    ✓ Encrypted event {createdMessage.authorSequence} saved securely.
                  </p>
                )}
              </form>
              {groupMessages.length > 0 && (
                <section className="message-timeline" aria-label="Messages saved on this device">
                  <h3>Messages</h3>
                  {renderEvidenceControls(localGroup.groupId)}
                  {renderEvidenceResult()}
                  {groupMessages.map((message) => (
                    <article
                      className={`message-bubble ${message.authorId === profile?.peerId ? "own-message" : ""}`}
                      key={message.eventId}
                    >
                      {renderEvidenceCheckbox(message)}
                      {renderReplyQuote(message)}
                      {renderMessageText(message)}
                      <time dateTime={new Date(message.createdAtUnixMs).toISOString()}>
                        {messageAuthorLabel(message, profile)} · {messageTime(message.createdAtUnixMs)}
                        {message.edited && " · Edited"}
                        {message.authorId === profile?.peerId && (
                          <>{" · "}{messageDeliveryLabel(message)}</>
                        )}
                      </time>
                      <div className="message-actions">
                        <button onClick={() => setReplyingTo(message)} type="button">Reply</button>
                        <button onClick={() => void copyMessage(message)} type="button">Copy</button>
                        {message.authorId === profile?.peerId && editingMessage?.eventId !== message.eventId && (
                          <button
                            disabled={savingEdit}
                            onClick={() => setEditingMessage({ eventId: message.eventId, text: message.text })}
                            type="button"
                          >
                            Edit
                          </button>
                        )}
                        <button
                          disabled={Boolean(deletingMessage)}
                          onClick={() => void hideMessage(message)}
                          type="button"
                        >
                          {deletingMessage === message.eventId ? "Deleting…" : "Delete here"}
                        </button>
                      </div>
                    </article>
                  ))}
                  {hasEarlierMessages && (
                    <p className="preview-note">Showing the latest 256 messages stored on this device.</p>
                  )}
                </section>
              )}
              {issuedInvitation && issuedInvitation.groupId === localGroup.groupId ? (
                <>
                  <label htmlFor="issued-invitation">Invitation link</label>
                  <textarea
                    className="invitation-link-box"
                    id="issued-invitation"
                    readOnly
                    rows={3}
                    value={issuedInvitation.link}
                  />
                  <p className="preview-note">
                    {expiryDescription(issuedInvitation.expiresAtUnix)}
                    {" · Valid until expiry"}
                  </p>
                  {invitationQrCode && (
                    <figure className="invitation-qr">
                      <img
                        alt={`QR code invitation for ${localGroup.groupName}`}
                        height="320"
                        src={invitationQrCode}
                        width="320"
                      />
                      <figcaption>Scan with CharP2P to join</figcaption>
                    </figure>
                  )}
                  {invitationQrError && <p className="form-error preview-error" role="alert">{invitationQrError}</p>}
                  {error && <p className="form-error preview-error" role="alert">{error}</p>}
                  <button className="primary-button" onClick={copyInvitation} type="button">
                    {invitationCopied ? "Invitation copied" : "Copy invitation"}
                  </button>
                  <button className="danger-button" disabled={revokingInvitation} onClick={revokeInvitation} type="button">
                    {revokingInvitation ? "Revoking invitation…" : "Revoke invitation"}
                  </button>
                </>
              ) : (
                <>
                  <p className="preview-note">Create a signed invitation to share this group.</p>
                  {error && <p className="form-error preview-error" role="alert">{error}</p>}
                  <button className="primary-button" disabled={creatingInvitation || !isTauri()} onClick={createInvitation} type="button">
                    {creatingInvitation ? "Creating invitation…" : "Create invitation"}
                  </button>
                </>
              )}
            </section>
          )}

          {step === 3 && createGroupMode && !joinMode && (
            <form className="setup-form create-group-form" onSubmit={createGroup}>
              <header>
                <p className="eyebrow">New private group</p>
                <h2>Create a group</h2>
                <p>Set the local group identity and invitation defaults.</p>
              </header>

              <fieldset className="icon-picker">
                <legend>Group icon</legend>
                <div>
                  {['●●●', '◆', '▲', '♥', '★'].map((icon, index) => (
                    <button
                      aria-label={`Group icon ${index + 1}`}
                      aria-pressed={groupIcon === index}
                      className={groupIcon === index ? `selected icon-${index}` : `icon-${index}`}
                      key={icon}
                      onClick={() => setGroupIcon(index)}
                      type="button"
                    >{icon}</button>
                  ))}
                </div>
              </fieldset>

              <label htmlFor="group-name">Group name</label>
              <input
                autoFocus
                id="group-name"
                maxLength={80}
                onChange={(event) => setGroupName(event.target.value)}
                placeholder="Project Atlas"
                value={groupName}
              />

              <fieldset className="choice-group">
                <legend>Current secure group profile</legend>
                <p className="preview-note">A valid invitation grants access until it expires. New members receive messages sent after they join.</p>
              </fieldset>

              <div className="invitation-defaults">
                <label htmlFor="invitation-lifetime">Invitation expires after</label>
                <select id="invitation-lifetime" onChange={(event) => setInvitationLifetime(Number(event.target.value))} value={invitationLifetime}>
                  <option value={86400}>1 day</option>
                  <option value={604800}>7 days</option>
                  <option value={1209600}>14 days</option>
                  <option value={2592000}>30 days</option>
                </select>
                <p className="preview-note">Invitation links remain valid for their selected lifetime.</p>
              </div>

              {error && <p className="form-error preview-error" role="alert">{error}</p>}
              <button className="primary-button join-button" disabled={!groupName.trim() || creatingGroup || !isTauri()} type="submit">
                {creatingGroup ? "Creating group…" : "Create group"}
              </button>
              <button className="text-button" onClick={() => { setCreateGroupMode(false); setError(""); }} type="button">Cancel</button>
            </form>
          )}

          {step === 3 && !pendingGroup && availableGroups.length === 0 && !joinMode && !createGroupMode && (
            <section className="setup-form ready-card">
              <div className="ready-check" aria-hidden="true">✓</div>
              <header>
                <p className="eyebrow">This device is ready</p>
                <h2>Join your first group</h2>
                <p>Open a CharP2P invite or paste one into the app.</p>
              </header>
              {profile && (
                <div className="ready-identity">
                  <span>{profile.deviceName}</span>
                  <code title={profile.peerId}>{shortPeerId(profile.peerId)}</code>
                </div>
              )}
              <button className="primary-button" onClick={() => setJoinMode(true)} type="button">
                Paste invite link
              </button>
              <button className="secondary-button" onClick={() => setCreateGroupMode(true)} type="button">
                Create a group
              </button>
            </section>
          )}

          {step === 3 && joinMode && !invitationPreview && (
            <form className="setup-form join-form" onSubmit={verifyInvitation}>
              <header>
                <p className="eyebrow">Invitation</p>
                <h2>Join a group</h2>
                <p>Paste an invitation to verify who created it and what it permits.</p>
              </header>

              <label htmlFor="invite-link">Invitation link</label>
              <textarea
                autoFocus
                id="invite-link"
                onChange={(event) => setInviteInput(event.target.value)}
                placeholder="charp2p://join/…"
                rows={4}
                value={inviteInput}
              />

              {error && <p className="form-error" role="alert">{error}</p>}

              <button
                className="primary-button"
                disabled={!inviteInput.trim() || verifyingInvite || !isTauri()}
                title={isTauri() ? undefined : "Open the desktop or Android app to validate invitations"}
                type="submit"
              >
                {verifyingInvite ? "Verifying invitation…" : "Verify invitation"}
              </button>
              <button className="text-button" onClick={closeJoinFlow} type="button">Cancel</button>
            </form>
          )}

          {step === 3 && joinMode && invitationPreview && (
            <section className="setup-form join-preview">
              <div className="join-icon" aria-hidden="true"><BrandMark decorative /></div>
              <header>
                <p className="eyebrow">Invitation verified</p>
                <h2>Join {invitationPreview.groupName}</h2>
                <p>Invited by {invitationPreview.inviterName}</p>
              </header>

              <div className="status-row" aria-label="Invitation status">
                <span className="status-chip">✓ Verified invitation</span>
                <span className="status-chip muted">○ Connection not checked</span>
              </div>

              <dl className="preview-facts">
                <div><dt>Messages</dt><dd>You can send messages</dd></div>
                <div><dt>History</dt><dd>{historyDescription(invitationPreview.historyPolicy)}</dd></div>
                <div><dt>Invitation</dt><dd>{expiryDescription(invitationPreview.expiresAtUnix)}{invitationPreview.reusable ? " · Reusable" : " · Single use"}</dd></div>
                <div><dt>Group fingerprint</dt><dd><code title={invitationPreview.groupId}>{shortPeerId(invitationPreview.groupId)}</code></dd></div>
                <div><dt>Inviter device</dt><dd><code title={invitationPreview.inviterDeviceId}>{shortPeerId(invitationPreview.inviterDeviceId)}</code></dd></div>
              </dl>

              <p className="preview-note">Your peer identity will be visible to group members.</p>
              {error && <p className="form-error preview-error" role="alert">{error}</p>}
              <button className="primary-button join-button" disabled={acceptingInvite} onClick={acceptInvitation} type="button">
                {acceptingInvite ? "Saving invitation…" : "Join group"}
              </button>
              <button
                className="text-button"
                onClick={() => {
                  setInvitationPreview(null);
                  setError("");
                }}
                type="button"
              >
                Use another invitation
              </button>
            </section>
          )}
            </>
          )}
        </div>

        <footer className="setup-footer">
          <button onClick={() => setInformationView("privacy")} type="button">Privacy</button>
          <button
            onClick={() => {
              setInformationView(null);
              setBackupView(false);
              setSettingsView(false);
              setNetworkView(true);
            }}
            type="button"
          >
            Network
          </button>
          <button
            onClick={() => {
              setInformationView(null);
              setBackupView(false);
              setNetworkView(false);
              setSettingsView(true);
            }}
            type="button"
          >
            Settings
          </button>
          <button onClick={() => setInformationView("identity")} type="button">How identity works</button>
          {profile && (
            <button
              onClick={() => {
                setInformationView(null);
                setNetworkView(false);
                setSettingsView(false);
                setBackupView(true);
              }}
              type="button"
            >
              Identity backup
            </button>
          )}
        </footer>
      </section>
    </main>
  );
}

export default App;
