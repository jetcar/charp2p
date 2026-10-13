# Invitation fallback page

Static page served at `https://join.charp2p.example/i` (technical design,
"Invitations and links"). A browser shows it when the installed app does not
claim the HTTPS link. It explains installation and offers the invitation as a
`charp2p://join/` link and as copyable text.

The invitation stays in the URL fragment, which browsers do not send to the
server. The page loads only its own script and stylesheet, sets a
Content Security Policy and `no-referrer`, makes no requests, and does not
decode or display the invitation; the app verifies it.

Serve the `i/` directory as-is with no analytics, third-party resources, or
logging of full request URLs. The production host also needs the Android
`assetlinks.json` before the HTTPS link is registered as an App Link (ADR-010).
