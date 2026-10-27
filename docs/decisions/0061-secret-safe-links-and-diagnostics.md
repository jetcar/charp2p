# ADR-061: Keep invitation secrets out of links and diagnostics

## Status

Accepted

## Date

2026-10-27

## Context

An encoded invitation is a bearer credential. It contains the discovery secret
needed to find the owner, and the derived discovery key correlates private group
activity. The webview must temporarily hold invitation text for paste, deep-link
and sharing flows, while Rust protocol values may appear in test failures or
future diagnostics through `Debug` formatting.

## Decision

Accept invitation input only as a raw canonical payload, the exact
`charp2p://join/` form, or the exact HTTPS host and fragment form defined in the
technical design. Reject query credentials, lookalike hosts, credentials in the
authority, explicit ports and normalized path variants. The bundled webview
passes invitation text unchanged to the bounded Rust parser and does not log or
persist the raw deep-link value outside protected pending-invitation storage.

Secret-bearing protocol types do not expose their contents through diagnostics.
`Invitation` has no `Debug` implementation. Join and invite responses redact
invitation, KeyPackage and Welcome values. `DiscoveryKey` uses an explicit
redacted `Debug` implementation. Application failures exposed to the webview
are fixed error codes without request values.

## Alternatives considered

- Put the bearer in an HTTPS query: rejected because normal requests, access
  logs and referrers can retain it.
- Decode invitation fields in the webview: rejected because it expands the
  secret-bearing surface and creates a second parser.
- Rely on developers never to format secret types: rejected because derived
  `Debug` output can leak during routine troubleshooting.

## Consequences

- Operators and support tooling can diagnose sizes and rejection categories
  without receiving bearer credentials or rendezvous keys.
- The invitation remains visible where the user explicitly pastes or shares it;
  screen capture and clipboard handling remain user-controlled surfaces.
- Any new diagnostic or link form requires a secret-field review and a
  regression test before release.
