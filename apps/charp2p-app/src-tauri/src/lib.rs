pub mod groups;
mod identity;
mod invitation;
mod mls_storage;
mod network;
mod pending;

use std::sync::{Arc, Mutex};

use groups::{CreateGroupSpec, GroupService, IssuedInvitation, LocalGroup};
use identity::{DeviceProfile, IdentityService};
use mls_storage::{
    CreatedMessage, GroupMemberDevice, MlsProviderService, StoredMessagePage, UnreadMessageCount,
};
use network::{AdvertisementResult, NetworkService, PeerSearchResult, SynchronizeGroupResult};
use pending::{JoinedGroup, PendingGroup, PendingInvitationService};
use tauri::Manager;

const MAX_GROUP_ID_TEXT_BYTES: usize = 256;
const EVENT_ID_HEX_BYTES: usize = 64;

#[tauri::command]
fn identity_status(
    service: tauri::State<'_, IdentityService>,
) -> Result<Option<DeviceProfile>, String> {
    service.status().map_err(str::to_owned)
}

#[tauri::command]
fn create_identity(
    device_name: String,
    service: tauri::State<'_, IdentityService>,
) -> Result<DeviceProfile, String> {
    service.create(&device_name).map_err(str::to_owned)
}

#[tauri::command]
fn preview_invitation(input: String) -> Result<invitation::InvitationPreview, String> {
    invitation::preview_invitation(&input).map_err(str::to_owned)
}

#[tauri::command]
fn accept_invitation(
    input: String,
    pending_service: tauri::State<'_, PendingInvitationService>,
    group_service: tauri::State<'_, Arc<GroupService>>,
) -> Result<PendingGroup, String> {
    let preview = invitation::preview_invitation(&input).map_err(str::to_owned)?;
    if group_service
        .list()
        .map_err(str::to_owned)?
        .iter()
        .any(|group| group.group_id == preview.group_id)
    {
        return Err("invitation_owned_locally".to_owned());
    }
    pending_service.accept(&input).map_err(str::to_owned)
}

#[tauri::command]
fn pending_invitations(
    pending_service: tauri::State<'_, PendingInvitationService>,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
) -> Result<Vec<PendingGroup>, String> {
    let (pending, expired) = pending_service.inspect().map_err(str::to_owned)?;
    for group_id in expired {
        mls_service
            .cancel_pending_join(group_id)
            .map_err(str::to_owned)?;
        match pending_service.cancel(group_id) {
            Ok(()) | Err("pending_invitation_not_found") => {}
            Err(error) => return Err(error.to_owned()),
        }
    }
    Ok(pending)
}

#[tauri::command]
fn cancel_pending_invitation(
    group_id: String,
    pending_service: tauri::State<'_, PendingInvitationService>,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
) -> Result<(), String> {
    let group_id = parse_group_id(&group_id, "pending_invitation_not_found")?;
    pending_service
        .ensure_pending(group_id)
        .map_err(str::to_owned)?;
    mls_service
        .cancel_pending_join(group_id)
        .map_err(str::to_owned)?;
    pending_service.cancel(group_id).map_err(str::to_owned)
}

#[tauri::command]
fn joined_groups(
    service: tauri::State<'_, PendingInvitationService>,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
) -> Result<Vec<JoinedGroup>, String> {
    let mut groups = service.joined().map_err(str::to_owned)?;
    let names = mls_service.current_group_names().map_err(str::to_owned)?;
    for group in &mut groups {
        apply_current_group_name(&names, &group.group_id, &mut group.group_name);
    }
    Ok(groups)
}

/// Leaves a joined group on this device only. Group state goes first so a
/// failed protected-storage cleanup is retried by leaving again.
#[tauri::command]
fn leave_joined_group(
    group_id: String,
    pending_service: tauri::State<'_, PendingInvitationService>,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
) -> Result<(), String> {
    let group_id = parse_group_id(&group_id, "joined_group_not_found")?;
    let left = mls_service.leave_joined_group(group_id);
    if let Err(error) = left {
        if error != "joined_group_not_found" {
            return Err(error.to_owned());
        }
    }
    pending_service
        .forget_joined_discovery(group_id)
        .map_err(str::to_owned)?;
    left.map_err(str::to_owned)
}

#[tauri::command]
fn local_groups(
    service: tauri::State<'_, Arc<GroupService>>,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
) -> Result<Vec<LocalGroup>, String> {
    let mut groups = service.list().map_err(str::to_owned)?;
    let names = mls_service.current_group_names().map_err(str::to_owned)?;
    for group in &mut groups {
        apply_current_group_name(&names, &group.group_id, &mut group.group_name);
    }
    Ok(groups)
}

#[tauri::command]
fn rename_group(
    group_id: String,
    group_name: String,
    identity_service: tauri::State<'_, IdentityService>,
    group_service: tauri::State<'_, Arc<GroupService>>,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
) -> Result<(), String> {
    let group_id = parse_group_id(&group_id, "group_not_found")?;
    if !group_service
        .list()
        .map_err(str::to_owned)?
        .iter()
        .any(|group| group.group_id == group_id.to_string())
    {
        return Err("group_not_owned".to_owned());
    }
    let group_name = groups::normalize_group_name(&group_name).map_err(str::to_owned)?;
    let metadata =
        charp2p_core::GroupMetadata::new(&group_name).map_err(|_| "invalid_group_name")?;
    let identity = identity_service
        .load_network_identity()
        .map_err(str::to_owned)?;
    mls_service
        .change_group_metadata(group_id, &identity, &metadata)
        .map_err(str::to_owned)
}

#[tauri::command]
fn issued_invitations(
    service: tauri::State<'_, Arc<GroupService>>,
) -> Result<Vec<IssuedInvitation>, String> {
    service.issued_invitations().map_err(str::to_owned)
}

#[tauri::command]
fn create_group_invitation(
    group_id: String,
    identity_service: tauri::State<'_, IdentityService>,
    group_service: tauri::State<'_, Arc<GroupService>>,
) -> Result<IssuedInvitation, String> {
    let group_id = parse_group_id(&group_id, "group_not_found")?;
    let profile = identity_service
        .status()
        .map_err(str::to_owned)?
        .ok_or_else(|| "identity_missing".to_owned())?;
    let inviter_name = identity::invitation_device_name(&profile.device_name);
    let inviter_device_id = parse_group_id(&profile.peer_id, "identity_record_invalid")?;
    group_service
        .issue_invitation(group_id, inviter_device_id, &inviter_name)
        .map_err(str::to_owned)
}

#[tauri::command]
async fn revoke_group_invitation(
    group_id: String,
    group_service: tauri::State<'_, Arc<GroupService>>,
) -> Result<(), String> {
    let group_id = parse_group_id(&group_id, "group_not_found")?;
    group_service
        .revoke_invitation(group_id)
        .map_err(str::to_owned)?;
    Ok(())
}

#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn create_group(
    group_name: String,
    icon: u8,
    history_policy: String,
    approval_required: bool,
    invitation_lifetime_seconds: u64,
    reusable_invitation: bool,
    identity_service: tauri::State<'_, IdentityService>,
    group_service: tauri::State<'_, Arc<GroupService>>,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
) -> Result<LocalGroup, String> {
    let owner_identity = identity_service
        .load_network_identity()
        .map_err(str::to_owned)?;
    let group = group_service
        .create(CreateGroupSpec {
            group_name: &group_name,
            icon,
            history_policy: &history_policy,
            approval_required,
            invitation_lifetime_seconds,
            reusable_invitation,
        })
        .map_err(str::to_owned)?;
    let group_id = parse_group_id(&group.group_id, "group_creation_failed")?;
    if let Err(error) = mls_service.initialize_owner_group(group_id, &owner_identity) {
        group_service
            .rollback_created_group(group_id)
            .map_err(|_| "group_creation_rollback_failed".to_owned())?;
        return Err(error.to_owned());
    }
    Ok(group)
}

#[tauri::command]
async fn search_group_peers(
    group_id: String,
    identity_service: tauri::State<'_, IdentityService>,
    pending_service: tauri::State<'_, PendingInvitationService>,
    network_service: tauri::State<'_, NetworkService>,
) -> Result<PeerSearchResult, String> {
    let group_id = parse_group_id(&group_id, "pending_invitation_not_found")?;
    let identity = identity_service
        .load_network_identity()
        .map_err(str::to_owned)?;
    let invitation = pending_service
        .load_invitation(group_id)
        .map_err(str::to_owned)?;
    network_service
        .search(identity, &invitation)
        .await
        .map_err(str::to_owned)
}

#[tauri::command]
async fn join_group(
    group_id: String,
    identity_service: tauri::State<'_, IdentityService>,
    pending_service: tauri::State<'_, PendingInvitationService>,
    network_service: tauri::State<'_, NetworkService>,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
) -> Result<JoinedGroup, String> {
    let group_id = parse_group_id(&group_id, "pending_invitation_not_found")?;
    if !mls_service.has_group(group_id).map_err(str::to_owned)? {
        let identity = identity_service
            .load_network_identity()
            .map_err(str::to_owned)?;
        let invitation = pending_service
            .load_invitation(group_id)
            .map_err(str::to_owned)?;
        network_service
            .join(identity, &invitation)
            .await
            .map_err(str::to_owned)?;
    }
    pending_service
        .complete_join(group_id)
        .map_err(str::to_owned)
}

#[tauri::command]
async fn synchronize_group(
    group_id: String,
    identity_service: tauri::State<'_, IdentityService>,
    pending_service: tauri::State<'_, PendingInvitationService>,
    network_service: tauri::State<'_, NetworkService>,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
) -> Result<SynchronizeGroupResult, String> {
    let group_id = parse_group_id(&group_id, "joined_group_not_found")?;
    if !mls_service.has_group(group_id).map_err(str::to_owned)? {
        return Err("mls_joined_group_missing".to_owned());
    }
    let identity = identity_service
        .load_network_identity()
        .map_err(str::to_owned)?;
    let (discovery_key, inviter_device_id) = pending_service
        .joined_sync_target(group_id)
        .map_err(str::to_owned)?;
    let result = network_service
        .synchronize(identity, discovery_key, group_id, inviter_device_id)
        .await
        .map_err(str::to_owned)?;
    pending_service
        .record_synchronization(group_id, result.synchronized_at_unix)
        .map_err(str::to_owned)?;
    Ok(result)
}

#[tauri::command]
fn send_group_message(
    group_id: String,
    message: String,
    reply_to_event_id: Option<String>,
    identity_service: tauri::State<'_, IdentityService>,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
) -> Result<CreatedMessage, String> {
    let group_id = parse_group_id(&group_id, "group_not_found")?;
    let reply_to = reply_to_event_id
        .as_deref()
        .map(parse_event_id)
        .transpose()?;
    let identity = identity_service
        .load_network_identity()
        .map_err(str::to_owned)?;
    mls_service
        .create_message(group_id, &identity, &message, reply_to.as_ref())
        .map_err(str::to_owned)
}

#[tauri::command]
fn edit_group_message(
    group_id: String,
    event_id: String,
    message: String,
    identity_service: tauri::State<'_, IdentityService>,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
) -> Result<(), String> {
    let group_id = parse_group_id(&group_id, "group_not_found")?;
    let event_id = parse_event_id(&event_id)?;
    let identity = identity_service
        .load_network_identity()
        .map_err(str::to_owned)?;
    mls_service
        .edit_message(group_id, &identity, &event_id, &message)
        .map_err(str::to_owned)
}

#[tauri::command]
fn group_messages(
    group_id: String,
    identity_service: tauri::State<'_, IdentityService>,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
) -> Result<StoredMessagePage, String> {
    let group_id = parse_group_id(&group_id, "group_not_found")?;
    let identity = identity_service
        .load_network_identity()
        .map_err(str::to_owned)?;
    mls_service
        .messages(group_id, identity.peer_id())
        .map_err(str::to_owned)
}

#[tauri::command]
fn unread_message_counts(
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
) -> Result<Vec<UnreadMessageCount>, String> {
    mls_service.unread_message_counts().map_err(str::to_owned)
}

#[tauri::command]
fn hide_group_message(
    group_id: String,
    event_id: String,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
) -> Result<(), String> {
    let group_id = parse_group_id(&group_id, "group_not_found")?;
    let event_id = parse_event_id(&event_id)?;
    mls_service
        .hide_message_locally(group_id, &event_id)
        .map_err(str::to_owned)
}

#[tauri::command]
fn group_members(
    group_id: String,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
) -> Result<Vec<GroupMemberDevice>, String> {
    let group_id = parse_group_id(&group_id, "group_not_found")?;
    mls_service.group_members(group_id).map_err(str::to_owned)
}

#[tauri::command]
fn blocked_group_devices(
    group_id: String,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
) -> Result<Vec<String>, String> {
    let group_id = parse_group_id(&group_id, "group_not_found")?;
    mls_service.blocked_devices(group_id).map_err(str::to_owned)
}

#[tauri::command]
fn set_group_device_blocked(
    group_id: String,
    device_id: String,
    blocked: bool,
    identity_service: tauri::State<'_, IdentityService>,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
) -> Result<Vec<String>, String> {
    let group_id = parse_group_id(&group_id, "group_not_found")?;
    let device_id = parse_group_id(&device_id, "member_not_found")?;
    let identity = identity_service
        .load_network_identity()
        .map_err(str::to_owned)?;
    if device_id == identity.peer_id() {
        return Err("device_block_self".to_owned());
    }
    mls_service
        .set_device_blocked_locally(group_id, device_id, blocked)
        .map_err(str::to_owned)
}

#[tauri::command]
fn remove_group_member(
    group_id: String,
    member_device_id: String,
    identity_service: tauri::State<'_, IdentityService>,
    group_service: tauri::State<'_, Arc<GroupService>>,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
) -> Result<Vec<GroupMemberDevice>, String> {
    let group_id = parse_group_id(&group_id, "group_not_found")?;
    let member_id = parse_group_id(&member_device_id, "member_not_found")?;
    if !group_service
        .list()
        .map_err(str::to_owned)?
        .iter()
        .any(|group| group.group_id == group_id.to_string())
    {
        return Err("member_removal_not_allowed".to_owned());
    }
    let identity = identity_service
        .load_network_identity()
        .map_err(str::to_owned)?;
    mls_service
        .remove_member(group_id, &identity, member_id)
        .map_err(str::to_owned)
}

/// Advertises every owned group from one background provider, independent of
/// the group currently open in the interface.
#[tauri::command]
async fn advertise_owned_groups(
    identity_service: tauri::State<'_, IdentityService>,
    group_service: tauri::State<'_, Arc<GroupService>>,
    network_service: tauri::State<'_, NetworkService>,
) -> Result<AdvertisementResult, String> {
    group_service.issued_invitations().map_err(str::to_owned)?;
    let keys = group_service
        .all_owner_discovery_keys()
        .map_err(str::to_owned)?;
    let identity = identity_service
        .load_network_identity()
        .map_err(str::to_owned)?;
    let owner_identity = identity_service
        .load_network_identity()
        .map_err(str::to_owned)?;
    network_service
        .advertise_owner_group(identity, owner_identity, keys)
        .await
        .map_err(str::to_owned)
}

fn parse_group_id(input: &str, error: &'static str) -> Result<charp2p_core::PeerId, String> {
    if input.is_empty() || input.len() > MAX_GROUP_ID_TEXT_BYTES {
        return Err(error.to_owned());
    }
    input.parse().map_err(|_| error.to_owned())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    identity::initialize_platform_store().expect("platform-protected identity store is available");
    let builder = tauri::Builder::default();
    #[cfg(windows)]
    let builder = builder.plugin(tauri_plugin_single_instance::init(|app, _, _| {
        if let Some(window) = app.get_webview_window("main") {
            let _ = window.show();
            let _ = window.set_focus();
        }
    }));

    builder
        .plugin(tauri_plugin_deep_link::init())
        .setup(|app| {
            #[cfg(all(debug_assertions, windows))]
            {
                use tauri_plugin_deep_link::DeepLinkExt;
                app.deep_link().register_all()?;
            }

            let data_directory = app.path().app_data_dir()?;
            std::fs::create_dir_all(&data_directory)?;
            let storage_operations = Arc::new(Mutex::new(()));
            let identity = IdentityService::new(Arc::clone(&storage_operations));
            let pending = PendingInvitationService::open(
                data_directory.join("charp2p.sqlite3"),
                Arc::clone(&storage_operations),
            )
            .map_err(std::io::Error::other)?;
            let database_path = data_directory.join("charp2p.sqlite3");
            let groups = Arc::new(
                GroupService::open(&database_path, Arc::clone(&storage_operations))
                    .map_err(std::io::Error::other)?,
            );
            let mls = Arc::new(
                MlsProviderService::open(&database_path, storage_operations)
                    .map_err(std::io::Error::other)?,
            );
            let local_groups = groups.list().map_err(std::io::Error::other)?;
            if !local_groups.is_empty() {
                let owner_identity = identity
                    .load_network_identity()
                    .map_err(std::io::Error::other)?;
                for group in &local_groups {
                    let group_id = group
                        .group_id
                        .parse()
                        .map_err(|_| std::io::Error::other("group_identity_record_invalid"))?;
                    mls.initialize_owner_group(group_id, &owner_identity)
                        .map_err(std::io::Error::other)?;
                }
            }
            let network = NetworkService::from_environment(groups.clone(), mls.clone())
                .map_err(std::io::Error::other)?;
            app.manage(identity);
            app.manage(pending);
            app.manage(groups);
            app.manage(mls);
            app.manage(network);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            identity_status,
            create_identity,
            preview_invitation,
            accept_invitation,
            pending_invitations,
            cancel_pending_invitation,
            joined_groups,
            leave_joined_group,
            local_groups,
            rename_group,
            issued_invitations,
            create_group,
            create_group_invitation,
            revoke_group_invitation,
            search_group_peers,
            join_group,
            synchronize_group,
            send_group_message,
            edit_group_message,
            group_messages,
            hide_group_message,
            unread_message_counts,
            group_members,
            remove_group_member,
            blocked_group_devices,
            set_group_device_blocked,
            advertise_owned_groups
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

/// Replaces invitation-time display names with the latest authenticated
/// owner rename applied on this device.
fn apply_current_group_name(
    names: &[(charp2p_core::PeerId, String)],
    group_id: &str,
    group_name: &mut String,
) {
    if let Some((_, name)) = names
        .iter()
        .find(|(candidate, _)| candidate.to_string() == group_id)
    {
        group_name.clone_from(name);
    }
}

fn parse_event_id(value: &str) -> Result<[u8; 32], String> {
    if value.len() != EVENT_ID_HEX_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("message_not_found".to_owned());
    }
    let mut result = [0u8; 32];
    for (index, byte) in result.iter_mut().enumerate() {
        let offset = index * 2;
        *byte = u8::from_str_radix(&value[offset..offset + 2], 16)
            .map_err(|_| "message_not_found".to_owned())?;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use charp2p_core::GroupIdentity;

    use super::{parse_event_id, parse_group_id};

    #[test]
    fn webview_group_identifiers_are_bounded_before_parsing() {
        let group_id = GroupIdentity::generate().group_id();
        assert_eq!(
            parse_group_id(&group_id.to_string(), "invalid").unwrap(),
            group_id
        );
        assert_eq!(
            parse_group_id(&"1".repeat(257), "invalid"),
            Err("invalid".to_owned())
        );
    }

    #[test]
    fn webview_event_identifiers_require_canonical_hex() {
        assert_eq!(parse_event_id(&"ab".repeat(32)).unwrap(), [0xab; 32]);
        assert_eq!(
            parse_event_id(&"AB".repeat(32)),
            Err("message_not_found".to_owned())
        );
        assert_eq!(
            parse_event_id(&"a".repeat(63)),
            Err("message_not_found".to_owned())
        );
        assert_eq!(
            parse_event_id(&"gg".repeat(32)),
            Err("message_not_found".to_owned())
        );
    }
}
