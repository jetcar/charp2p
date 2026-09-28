import { invoke, isTauri } from "@tauri-apps/api/core";
import { FormEvent, useEffect, useMemo, useState } from "react";
import "./App.css";

type SetupStep = 1 | 2 | 3;
type DeviceProfile = { deviceName: string; peerId: string };
type InvitationPreview = {
  groupName: string;
  inviterName: string;
  groupId: string;
  expiresAtUnix: number;
  historyPolicy: "none" | "fromInvitation" | "allRetained";
  reusable: boolean;
};
type PendingGroup = InvitationPreview;

const ERROR_MESSAGES: Record<string, string> = {
  identity_already_exists: "This device already has an identity.",
  identity_creation_failed: "The device identity could not be created.",
  identity_record_invalid: "The stored identity is damaged and cannot be opened.",
  identity_service_unavailable: "The identity service is unavailable.",
  identity_store_unavailable: "Protected device storage is unavailable.",
  invitation_expired: "This invitation has expired.",
  invitation_invalid: "This is not a valid CharP2P invitation.",
  invitation_signature_invalid: "The invitation signature could not be verified.",
  invalid_device_name: "Enter a device name between 1 and 48 characters.",
  pending_invitation_service_unavailable: "Pending invitations are temporarily unavailable.",
  pending_invitation_record_invalid: "A saved invitation is damaged and cannot be opened.",
  pending_invitation_store_unavailable: "The invitation could not be saved securely.",
  pending_invitation_too_large: "This invitation is too large for protected device storage.",
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
  const [acceptingInvite, setAcceptingInvite] = useState(false);
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
    ])
      .then(([identityResult, pendingResult]) => {
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
      })
      .finally(() => {
        if (active) setLoading(false);
      });

    return () => {
      active = false;
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
      setInvitationPreview(null);
      setInviteInput("");
      setJoinMode(false);
    } catch (reason) {
      setError(errorMessage(reason));
    } finally {
      setAcceptingInvite(false);
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

          {step === 3 && pendingGroup && (
            <section className="setup-form pending-card">
              <div className="pending-icon" aria-hidden="true">⌁</div>
              <header>
                <p className="eyebrow">Pending group</p>
                <h2>Invitation saved</h2>
                <p>{pendingGroup.groupName} is ready for peer discovery.</p>
              </header>
              <div className="status-row" aria-label="Join status">
                <span className="status-chip">✓ Verified invitation</span>
                <span className="status-chip muted">○ Not connected</span>
              </div>
              <dl className="preview-facts">
                <div><dt>Invited by</dt><dd>{pendingGroup.inviterName}</dd></div>
                <div><dt>History</dt><dd>{historyDescription(pendingGroup.historyPolicy)}</dd></div>
                <div><dt>Invitation</dt><dd>{expiryDescription(pendingGroup.expiresAtUnix)}</dd></div>
                <div><dt>Group fingerprint</dt><dd><code title={pendingGroup.groupId}>{shortPeerId(pendingGroup.groupId)}</code></dd></div>
              </dl>
              <p className="preview-note">Your invitation is stored securely on this device.</p>
            </section>
          )}

          {step === 3 && !pendingGroup && !joinMode && (
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
              <button className="secondary-button" disabled title="Group creation is not available yet" type="button">
                Create a group
              </button>
            </section>
          )}

          {step === 3 && !pendingGroup && joinMode && !invitationPreview && (
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

          {step === 3 && !pendingGroup && joinMode && invitationPreview && (
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
