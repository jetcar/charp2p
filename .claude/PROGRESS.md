# CharP2P implementation progress

## Backlog

- [x] Groups page: unread message counts per group (device-local unread markers, cleared when the conversation is viewed).
- [x] Linux dev build: fix `src-tauri` clippy dead-code/unused-variable lints in identity.rs on non-Windows/Android targets.
- [x] Members: block a device locally (hide its messages on this device, keep signed events; product page 7).
- [x] Owner can create more than one local group (remove the "one local group at a time" limit).
- [x] Advertise every owned group's active invitation in the background, not only the group currently open in the UI.
- [ ] Group details: rename group by owner via signed `GroupMetadataChanged` event, applied by members on sync.
- [ ] Conversation: edit own message via signed `MessageEdited` event (MLS-protected), shown as edited.
- [ ] Conversation: reply to a message (reply reference inside the protected payload).
- [ ] Group details: leave group as a member (local removal of group state and discovery key).
- [ ] Settings: encrypted identity backup export (passphrase-derived key, ADR needed).
- [ ] Welcome: restore identity from encrypted backup.
- [ ] Network page: connection type, known bootstrap/community nodes, current advertising state.
- [ ] Network page: diagnostic export with secrets removed.
- [ ] Settings page: local storage use, version, licences, security contact, node policy.
- [ ] Evidence export of user-selected signed events.
- [ ] Delivery state "observed by all currently known members" from per-peer acknowledgements.

## Needs human

- [ ] Android emulator and physical-device validation of the arm64 build (implementation gate 1).
- [ ] Manual UI testing of cold-start and running-instance deep links on Windows and Android.
- [ ] Decide supported Windows and Android versions (implementation gate 6).
- [ ] Measure worst-case Welcome size to set the product group-size limit.

## Blocked

## Log
2026-10-05T18:38:43Z unread message counts: store schema v16 adds unread_local_messages (received copies only, cleared on timeline read and local hide); unread_message_counts command; badges in group switcher. Also applied pinned-toolchain rustfmt to crates (main was not fmt-clean). Pre-existing on HEAD, not fixed: src-tauri clippy fails on Linux (identity.rs unused `user`/CREDENTIAL_SERVICE); src-tauri network tests advertised_invitation_is_discoverable_through_a_routing_node and joined_member_rediscovers_the_owner_and_synchronizes fail in the container (connection_type not "lan"). No package-lock.json in repo; used npm install.
2026-10-05T19:28:48Z Linux src-tauri clippy lints: gated CREDENTIAL_SERVICE on keyring-backed cfgs and consumed `user` on the unsupported-platform path; src-tauri clippy -D warnings now clean on Linux (installed webkit2gtk/gtk dev libs via apt-get). Workspace fmt/clippy/test and npm build pass.
2026-10-05T20:32:22Z block device locally: store schema v17 adds blocked_local_devices (per group); blocked authors' messages still materialize (MLS ratchet advances) but are filtered from timeline and unread counts and never marked unread; blocked_group_devices/set_group_device_blocked commands; Block/Unblock in Members view. Workspace + src-tauri fmt/clippy/test and npm build pass.
2026-10-05T21:30:55Z multiple local groups: removed group_already_exists limit in GroupService::create; test covers two owned groups with separate roots/invitations and per-group revoke; frontend tracks issued invitations per group and adds "Create a group" to the group switcher. Workspace + src-tauri fmt/clippy and npm build pass; src-tauri tests pass except pre-existing container failure advertised_invitation_is_discoverable_through_a_routing_node. Follow-up: only the open group advertises (new backlog item).
2026-10-05T22:30:52Z background advertising of all owned groups: GroupService::all_owner_discovery_keys combines retained keys of every owned group (cap 256, enforced at invitation issuance as advertised_discovery_limit_reached); advertise_group replaced by advertise_owned_groups; frontend advertises whenever any owned group exists, keyed on owned group and invitation ids. Workspace + src-tauri fmt/clippy/test and npm build pass (routing-node network test passed this run; installed webkit2gtk/gtk dev libs via apt-get).
