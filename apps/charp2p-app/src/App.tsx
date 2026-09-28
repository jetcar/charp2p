import { invoke, isTauri } from "@tauri-apps/api/core";
import { FormEvent, useEffect, useMemo, useState } from "react";
import "./App.css";

type SetupStep = 1 | 2 | 3;
type DeviceProfile = { deviceName: string; peerId: string };

const ERROR_MESSAGES: Record<string, string> = {
  identity_already_exists: "This device already has an identity.",
  identity_creation_failed: "The device identity could not be created.",
  identity_record_invalid: "The stored identity is damaged and cannot be opened.",
  identity_service_unavailable: "The identity service is unavailable.",
  identity_store_unavailable: "Protected device storage is unavailable.",
  invalid_device_name: "Enter a device name between 1 and 48 characters.",
};

function errorMessage(error: unknown) {
  const code = typeof error === "string" ? error : "";
  return ERROR_MESSAGES[code] ?? "Something went wrong. Try again.";
}

function shortPeerId(peerId: string) {
  if (peerId.length <= 18) return peerId;
  return `${peerId.slice(0, 9)}…${peerId.slice(-8)}`;
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
  const suggestedName = useMemo(
    () => (/Android/i.test(navigator.userAgent) ? "My tablet" : "My PC"),
    [],
  );

  useEffect(() => {
    if (!isTauri()) return;

    let active = true;
    invoke<DeviceProfile | null>("identity_status")
      .then((storedProfile) => {
        if (!active || !storedProfile) return;
        setProfile(storedProfile);
        setDeviceName(storedProfile.deviceName);
        setStep(3);
      })
      .catch((reason: unknown) => {
        if (active) setError(errorMessage(reason));
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

          {step === 3 && (
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
              <button className="primary-button" type="button">Paste invite link</button>
              <button className="secondary-button" type="button">Create a group</button>
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
