# Secondary-view generation prompts

The built-in image-generation tool produced one asset per screen. Each Windows
asset used `windows-chat.png` as a strict visual reference; each tablet asset
used `android-tablet-chat.png`.

## Shared Windows prompt

```text
Use case: ui-mockup
Asset type: high-fidelity CharP2P Windows 11 desktop application screen
Preserve the approved connected-nodes logo, deep navy navigation, warm
near-white surfaces, teal connection states, coral primary actions, typography,
icon style, corner radii, spacing, and Alex identity. Create a production-ready,
straight-on 16:10 native Windows screenshot with accessible contrast and an
implementable Fluent-inspired layout. Show only the application window. Avoid
browser chrome, hardware frames, cloud/crypto/torrent/blockchain imagery,
security clichés, watermarks, tiny text, and excessive gradients.
```

## Shared Android tablet prompt

```text
Use case: ui-mockup
Asset type: high-fidelity CharP2P Android tablet application screen
Preserve the approved connected-nodes logo, navy navigation rail, warm
near-white surfaces, teal connection states, coral primary actions, typography,
Material 3 icon style, rounded surfaces, touch targets, spacing, and Alex
identity. Create a production-ready, straight-on 16:10 adaptive tablet screen
with accessible contrast and an implementable layout. Show only the app screen.
Avoid desktop chrome, hardware frames, cloud/crypto/torrent/blockchain imagery,
security clichés, watermarks, tiny text, crowded controls, and gradients.
```

## Screen prompts

### Identity onboarding

```text
Create the first-launch "Set up this device" flow. Use a dark brand pane with
"Private groups. Direct connections." and an abstract three-node illustration.
The setup pane contains a three-step Identity / Recovery / Ready indicator, a
device-name field, "Create identity", "Restore from backup", Privacy, and How
identity works. Do not show an existing identity on first launch.
```

### Join group

```text
Create a valid-invitation preview for "Join Design Crew". Show Peer available,
Verified invitation, invited by Maya, four members, send permission, history
from today, expiry in two days, an abbreviated group fingerprint, and the note
that the peer identity is visible to members. Use Join group and Cancel actions.
Never display the invitation secret.
```

### Create group

```text
Create an adaptive form for Project Atlas. Include avatar selection, group name,
new-member history choices None / From joining / All retained, join choices
Invite grants access / Owner approval required, seven-day invitation expiry,
reusable-link switch off, Send messages permission, and a non-scannable invite
preview. Use Create group and Cancel actions. Do not include public visibility
or file-sharing controls.
```

### Offline waiting

```text
Reuse the conversation layout with an amber "No peers reachable" state. Show
"Waiting for a group member", explain that messages synchronize when another
member comes online, display the last synchronization time, and provide Retry
now. Keep the composer enabled while explaining that new messages remain local
until a peer connects. The group subtitle must say Offline, not Direct.
```

### Members and devices

```text
Create owner-facing member/device management for Design Crew. Show Alex, Maya,
Noah, and Priya; expand Alex to show this device and another authorized device;
provide fingerprints and device revocation. Show Maya in a detail pane with
role and devices plus a restrained Remove from group action. State that
previously received messages cannot be erased. On tablet, keep Chats selected
in the navigation rail.
```
