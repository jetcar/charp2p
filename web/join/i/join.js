// Fallback page for https://join.charp2p.example/i#<invitation>.
// The invitation never leaves the browser: the page loads no other resources,
// makes no requests, and only hands the fragment to the installed app.
"use strict";

// Matches the client's bound on the encoded invitation (base64url, no padding).
const MAX_INVITATION_ENCODED_BYTES = 8 * 1024;
const INVITATION_PATTERN = /^[A-Za-z0-9_-]+$/;

function invitationFromFragment(fragment) {
  const payload = fragment.startsWith("#") ? fragment.slice(1) : fragment;
  if (payload.length === 0 || payload.length > MAX_INVITATION_ENCODED_BYTES) return null;
  return INVITATION_PATTERN.test(payload) ? payload : null;
}

function show(invitation) {
  const ready = document.getElementById("invitation-ready");
  const missing = document.getElementById("invitation-missing");
  if (invitation === null) {
    ready.hidden = true;
    missing.hidden = false;
    return;
  }
  // The app parses and verifies the whole link again before using it.
  document.getElementById("open-app").href = `charp2p://join/${invitation}`;
  ready.hidden = false;
  missing.hidden = true;
}

async function copyInvitation() {
  const status = document.getElementById("copy-status");
  const invitation = invitationFromFragment(window.location.hash);
  if (invitation === null) return;
  try {
    await navigator.clipboard.writeText(`charp2p://join/${invitation}`);
    status.textContent = "Invitation copied.";
  } catch {
    status.textContent = "The invitation could not be copied. Copy this page's address instead.";
  }
}

document.addEventListener("DOMContentLoaded", () => {
  show(invitationFromFragment(window.location.hash));
  document.getElementById("copy-invitation").addEventListener("click", () => void copyInvitation());
  window.addEventListener("hashchange", () => show(invitationFromFragment(window.location.hash)));
});
