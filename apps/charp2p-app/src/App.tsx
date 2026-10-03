import { invoke, isTauri } from "@tauri-apps/api/core";
import { getCurrent, onOpenUrl } from "@tauri-apps/plugin-deep-link";
import { FormEvent, useEffect, useMemo, useState } from "react";
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
type JoinedGroup = Omit<InvitationPreview, "expiresAtUnix" | "reusable">;
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
};
type AdvertisementResult = {
  status: "advertising" | "bootstrapRequired";
  expiresAtUnix: number;
};

const ADVERTISEMENT_STATUS_INTERVAL_MS = 30_000;
const ADVERTISEMENT_RETRY_INTERVAL_MS = 5_000;
const INVITATION_EXPIRY_CHECK_INTERVAL_MS = 1_000;

const ERROR_MESSAGES: Record<string, string> = {
  identity_already_exists: "This device already has an identity.",
  identity_creation_failed: "The device identity could not be created.",
  identity_record_invalid: "The stored identity is damaged and cannot be opened.",
  identity_service_unavailable: "The identity service is unavailable.",
  identity_store_unavailable: "Protected device storage is unavailable.",
  identity_missing: "Create a device identity before searching for peers.",
  group_creation_failed: "The group identity could not be created.",
  group_creation_rollback_failed: "Group setup failed and could not be safely rolled back.",
  group_already_exists: "This version supports one local group at a time.",
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
  network_bootstrap_required: "Configure a bootstrap node before joining.",
  network_configuration_invalid: "The peer network configuration is invalid.",
  network_join_failed: "The secure join exchange failed. Try again.",
  network_join_timed_out: "The group owner did not answer in time. Try again.",
  network_peer_not_found: "The invited group owner is not online yet.",
  network_peer_unreachable: "The invited group owner could not be reached.",
  network_search_timed_out: "The peer search timed out. Try again.",
  network_unavailable: "The peer network is unavailable.",
  mls_group_creation_failed: "Secure group setup failed.",
  mls_group_already_joined: "This device already belongs to that group.",
  mls_group_storage_unavailable: "Secure group storage is unavailable.",
  mls_provider_encryption_failed: "Secure group state could not be encrypted.",
  mls_provider_service_unavailable: "Secure group state is temporarily unavailable.",
  mls_provider_snapshot_invalid: "Stored secure group state is damaged.",
  mls_provider_store_unavailable: "Secure group state could not be saved.",
  mls_pending_join_invalid: "The saved secure join state is damaged.",
  mls_pending_join_missing: "The saved secure join state is missing.",
  mls_welcome_group_mismatch: "The response belongs to a different group.",
  mls_welcome_invalid: "The group owner returned an invalid secure response.",
  mls_wrapping_key_store_unavailable: "Protected secure-group storage is unavailable.",
  pending_invitation_not_found: "This pending invitation is no longer available.",
  pending_invitation_service_unavailable: "Pending invitations are temporarily unavailable.",
  pending_invitation_record_invalid: "A saved invitation is damaged and cannot be opened.",
  pending_invitation_store_unavailable: "The invitation could not be saved securely.",
  pending_invitation_too_large: "This invitation is too large for protected device storage.",
  join_busy: "The group owner is busy. Try again shortly.",
  join_unauthorized: "The group owner did not accept this invitation.",
  join_unsupported_profile: "The group uses an unsupported security profile.",
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

function historyDescription(policy: InvitationPreview["historyPolicy"]) {
  if (policy === "none") return "Messages shared after you join";
  if (policy === "allRetained") return "All retained history shared";
  return "History shared from invitation";
}

function expiryDescription(expiresAtUnix: number) {
  const remainingSeconds = expiresAtUnix - Math.floor(Date.now() / 1000);
  if (remainingSeconds <= 0) return "Expired";
  const hours = Math.ceil(remainingSeconds / 3600);
  if (hours < 48) return `Expires in ${hours} ${hours === 1 ? "hour" : "hours"}`;
  const days = Math.ceil(hours / 24);
  return `Expires in ${days} days`;
}

function peerSearchDescription(result: PeerSearchResult | null) {
  if (!result) return "Not searched";
  if (result.status === "bootstrapRequired") return "Bootstrap node needed";
  if (result.status === "peerReachable") {
    return `Reached ${result.reachablePeers} ${result.reachablePeers === 1 ? "peer" : "peers"}`;
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

function App() {
  const [step, setStep] = useState<SetupStep>(1);
  const [deviceName, setDeviceName] = useState("");
  const [profile, setProfile] = useState<DeviceProfile | null>(null);
  const [loading, setLoading] = useState(isTauri());
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [joinMode, setJoinMode] = useState(false);
  const [inviteInput, setInviteInput] = useState("");
  const [invitationPreview, setInvitationPreview] = useState<InvitationPreview | null>(null);
  const [verifyingInvite, setVerifyingInvite] = useState(false);
  const [pendingGroup, setPendingGroup] = useState<PendingGroup | null>(null);
  const [joinedGroup, setJoinedGroup] = useState<JoinedGroup | null>(null);
  const [acceptingInvite, setAcceptingInvite] = useState(false);
  const [joiningGroup, setJoiningGroup] = useState(false);
  const [peerSearchResult, setPeerSearchResult] = useState<PeerSearchResult | null>(null);
  const [searchingPeers, setSearchingPeers] = useState(false);
  const [localGroup, setLocalGroup] = useState<LocalGroup | null>(null);
  const [issuedInvitation, setIssuedInvitation] = useState<IssuedInvitation | null>(null);
  const [createGroupMode, setCreateGroupMode] = useState(false);
  const [groupName, setGroupName] = useState("");
  const [groupIcon, setGroupIcon] = useState(0);
  const [groupHistory, setGroupHistory] = useState<InvitationPreview["historyPolicy"]>("fromInvitation");
  const [approvalRequired, setApprovalRequired] = useState(false);
  const [invitationLifetime, setInvitationLifetime] = useState(604800);
  const [reusableInvitation, setReusableInvitation] = useState(false);
  const [creatingGroup, setCreatingGroup] = useState(false);
  const [creatingInvitation, setCreatingInvitation] = useState(false);
  const [invitationCopied, setInvitationCopied] = useState(false);
  const [advertisement, setAdvertisement] = useState<AdvertisementResult | null>(null);
  const [advertisementError, setAdvertisementError] = useState("");
  const [advertisementRetrying, setAdvertisementRetrying] = useState(false);
  const suggestedName = useMemo(
    () => (/Android/i.test(navigator.userAgent) ? "My tablet" : "My PC"),
    [],
  );

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
          setJoinedGroup(joinedResult.value[0] ?? null);
        } else {
          setError(errorMessage(joinedResult.reason));
        }
        if (groupsResult.status === "fulfilled") {
          setLocalGroup(groupsResult.value[0] ?? null);
        } else {
          setError(errorMessage(groupsResult.reason));
        }
        if (invitationsResult.status === "fulfilled") {
          setIssuedInvitation(invitationsResult.value[0] ?? null);
        } else {
          setError(errorMessage(invitationsResult.reason));
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
              setIssuedInvitation(refreshed);
              timer = window.setTimeout(scheduleExpiry, INVITATION_EXPIRY_CHECK_INTERVAL_MS);
            } else {
              setIssuedInvitation(null);
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
    if (
      !isTauri()
      || !localGroup
      || !issuedInvitation
      || issuedInvitation.groupId !== localGroup.groupId
    ) {
      setAdvertisement(null);
      setAdvertisementError("");
      setAdvertisementRetrying(false);
      return;
    }
    const groupId = localGroup.groupId;
    let active = true;
    let timer: number | undefined;
    setAdvertisement(null);
    setAdvertisementError("");
    setAdvertisementRetrying(false);

    async function refreshAdvertisement() {
      try {
        const result = await invoke<AdvertisementResult>("advertise_group", {
          groupId,
        });
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
  }, [issuedInvitation, localGroup]);

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
      setPendingGroup(accepted);
      setJoinedGroup(null);
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
      setJoinedGroup(joined);
      setPendingGroup(null);
      setPeerSearchResult(null);
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setJoiningGroup(false);
    }
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
        historyPolicy: groupHistory,
        approvalRequired,
        invitationLifetimeSeconds: invitationLifetime,
        reusableInvitation,
      });
      setLocalGroup(created);
      setIssuedInvitation(null);
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
      setIssuedInvitation(invitation);
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
              <button className="secondary-button" disabled title="Encrypted backup restore is not available yet" type="button">
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
              <button className="primary-button" disabled title="Encrypted recovery export is not available yet" type="button">
                Create recovery copy
              </button>
              <button className="text-button" onClick={() => setStep(3)} type="button">
                Do this later
              </button>
            </section>
          )}

          {step === 3 && pendingGroup && !joinMode && !joinedGroup && (
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
              <button className="primary-button join-button" disabled={joiningGroup || searchingPeers || !isTauri()} onClick={joinPendingGroup} type="button">
                {joiningGroup ? "Joining securely…" : "Connect and join"}
              </button>
              <button className="secondary-button" disabled={joiningGroup || searchingPeers || !isTauri()} onClick={searchForPeers} type="button">
                {searchingPeers ? "Checking availability…" : "Check peer availability"}
              </button>
            </section>
          )}

          {step === 3 && joinedGroup && !pendingGroup && !joinMode && !createGroupMode && (
            <section className="setup-form joined-card">
              <div className="ready-check" aria-hidden="true">✓</div>
              <header>
                <p className="eyebrow">Joined securely</p>
                <h2>{joinedGroup.groupName}</h2>
                <p>Your membership is protected on this device.</p>
              </header>
              <div className="status-row" aria-label="Group status">
                <span className="status-chip">✓ Secure membership ready</span>
              </div>
              <dl className="preview-facts">
                <div><dt>Invited by</dt><dd>{joinedGroup.inviterName}</dd></div>
                <div><dt>History</dt><dd>{historyDescription(joinedGroup.historyPolicy)}</dd></div>
                <div><dt>Group fingerprint</dt><dd><code title={joinedGroup.groupId}>{shortPeerId(joinedGroup.groupId)}</code></dd></div>
                <div><dt>Inviter device</dt><dd><code title={joinedGroup.inviterDeviceId}>{shortPeerId(joinedGroup.inviterDeviceId)}</code></dd></div>
              </dl>
              <p className="preview-note">Secure membership and verified group state are stored on this device.</p>
            </section>
          )}

          {step === 3 && localGroup && !pendingGroup && !joinedGroup && !joinMode && !createGroupMode && (
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
                <div><dt>Join mode</dt><dd>{localGroup.approvalRequired ? "Owner approval required" : "Invite grants access"}</dd></div>
                <div><dt>Invitation expiry</dt><dd>{localGroup.invitationLifetimeSeconds / 86400} days</dd></div>
                <div><dt>Group fingerprint</dt><dd><code title={localGroup.groupId}>{shortPeerId(localGroup.groupId)}</code></dd></div>
              </dl>
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
                    {issuedInvitation.reusable ? " · Reusable" : " · Single use"}
                  </p>
                  <div className="status-row" aria-label="Invitation network status">
                    <span className={`status-chip ${advertisement?.status === "advertising" ? "" : "muted"}`}>
                      {advertisement?.status === "advertising"
                        ? "● Advertising to peers"
                        : advertisement?.status === "bootstrapRequired"
                          ? "○ Bootstrap node needed"
                          : advertisementRetrying
                            ? "○ Advertising failed · Retrying…"
                          : "○ Starting peer advertising…"}
                    </span>
                  </div>
                  {advertisementError && <p className="form-error preview-error" role="alert">{advertisementError}</p>}
                  {error && <p className="form-error preview-error" role="alert">{error}</p>}
                  <button className="primary-button" onClick={copyInvitation} type="button">
                    {invitationCopied ? "Invitation copied" : "Copy invitation"}
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
                <legend>History for new members</legend>
                <div className="segmented-options">
                  {([
                    ["none", "None"],
                    ["fromInvitation", "From invitation"],
                    ["allRetained", "All retained"],
                  ] as const).map(([value, label]) => (
                    <button
                      aria-pressed={groupHistory === value}
                      className={groupHistory === value ? "selected" : ""}
                      key={value}
                      onClick={() => setGroupHistory(value)}
                      type="button"
                    >{label}</button>
                  ))}
                </div>
              </fieldset>

              <fieldset className="choice-group">
                <legend>Join mode</legend>
                <div className="join-options">
                  <button aria-pressed={!approvalRequired} className={!approvalRequired ? "selected" : ""} onClick={() => setApprovalRequired(false)} type="button">
                    <strong>Invite grants access</strong><span>People can join with a valid invitation.</span>
                  </button>
                  <button aria-pressed={approvalRequired} className={approvalRequired ? "selected" : ""} onClick={() => setApprovalRequired(true)} type="button">
                    <strong>Owner approval required</strong><span>Join requests must be approved.</span>
                  </button>
                </div>
              </fieldset>

              <div className="invitation-defaults">
                <label htmlFor="invitation-lifetime">Invitation expires after</label>
                <select id="invitation-lifetime" onChange={(event) => setInvitationLifetime(Number(event.target.value))} value={invitationLifetime}>
                  <option value={86400}>1 day</option>
                  <option value={604800}>7 days</option>
                  <option value={1209600}>14 days</option>
                  <option value={2592000}>30 days</option>
                </select>
                <label className="toggle-row">
                  <span><strong>Reusable invitation</strong><small>Allow the link to be used multiple times.</small></span>
                  <input checked={reusableInvitation} onChange={(event) => setReusableInvitation(event.target.checked)} type="checkbox" />
                </label>
              </div>

              {error && <p className="form-error preview-error" role="alert">{error}</p>}
              <button className="primary-button join-button" disabled={!groupName.trim() || creatingGroup || !isTauri()} type="submit">
                {creatingGroup ? "Creating group…" : "Create group"}
              </button>
              <button className="text-button" onClick={() => { setCreateGroupMode(false); setError(""); }} type="button">Cancel</button>
            </form>
          )}

          {step === 3 && !pendingGroup && !joinedGroup && !localGroup && !joinMode && !createGroupMode && (
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
        </div>

        <footer className="setup-footer">
          <button type="button">Privacy</button>
          <button type="button">How identity works</button>
        </footer>
      </section>
    </main>
  );
}

export default App;
