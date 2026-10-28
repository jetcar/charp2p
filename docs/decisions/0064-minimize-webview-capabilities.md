# ADR-064: Minimize the main webview's Tauri capabilities

## Status

Accepted

## Date

2026-10-28

## Context

Tauri capabilities bound the commands that bundled frontend code can invoke.
The generated `core:default` permission includes default access to app, event,
image, menu, path, resources, tray, webview, and window commands. CharP2P's
frontend uses none of those core command groups except listening for and
removing event listeners. Its deep-link flow reads the link delivered at cold
start and subscribes to later deliveries.

The Content Security Policy reduces script-injection risk, but unused IPC
permissions would still increase the impact if bundled frontend code or its
dependencies were compromised.

## Decision

Grant the main webview only:

- `core:event:allow-listen`;
- `core:event:allow-unlisten`; and
- `deep-link:allow-get-current`.

Do not grant frontend event emission, filesystem or path operations, window
mutation, menus, tray access, resource handles, image decoding, or other core
defaults. Rust application commands remain the narrow interface for identity,
storage, networking, synchronization, and exports.

Add a permission only when frontend code uses the corresponding API and its
scope and security effect have been reviewed.

## Alternatives considered

- Keep `core:default`: rejected because it grants several unused core command
  groups to the webview.
- Keep `core:event:default`: rejected because the frontend receives events but
  never emits them.
- Grant dynamic deep-link registration: rejected because the application uses
  its packaged scheme registration and only needs to read delivered links.

## Consequences

- A frontend compromise has fewer native Tauri commands available.
- New uses of Tauri JavaScript APIs fail until their exact permissions are
  intentionally added.
- Deep-link cold starts and already-running deliveries continue to use the
  maintained plugin and core event listener.

## Sources

- https://v2.tauri.app/reference/acl/core-permissions/
- https://v2.tauri.app/plugin/deep-linking/
- https://v2.tauri.app/security/capabilities/
