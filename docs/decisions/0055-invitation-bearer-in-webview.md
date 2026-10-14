# ADR-055: Pass encoded invitation bearers through the webview as opaque text

## Status

Accepted

## Date

2026-10-13

## Context

The technical design said the UI must not receive or display the discovery
secret. Every encoded invitation carries that secret, yet the user-facing
flows need the encoded form in the webview: the joiner pastes it into the join
field, the owner copies or shows it as a link and QR code to share it, and the
deep-link plugin delivers `charp2p:` links to the frontend. Moving all of these
into Rust behind opaque handles would still leave pasted text and shared links
in the webview, while adding handle lifetime and cold-start state for little
gain: the webview runs only the application's own bundled code.

## Decision

The webview may hold an encoded invitation only as opaque text that the user
pasted, opened through the operating system, or is sharing, and passes it
unchanged to Rust commands. Only the Rust invitation parser decodes it. No
command returns a decoded discovery secret, a derived discovery key, the
signed capability or the address hints to the UI; the join preview returns
only authenticated preview metadata. The UI never displays the bearer except
in the owner's sharing controls and in the join field holding the user's own
input, and does not persist or log it.

## Consequences

- Pasted, deep-linked and shared invitations keep one validation path in
  Rust; OS delivery is still not trust.
- The bearer's confidentiality in the webview rests on the bundled frontend
  and the application's Content Security Policy rather than on keeping it out
  of the webview.
- A future handle-based deep-link path remains compatible with this decision.

## Sources

- docs/technical-design.md (Invitations)
- docs/decisions/0008-protected-pending-invitations.md
