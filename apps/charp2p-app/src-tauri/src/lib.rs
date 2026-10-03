pub mod groups;
mod identity;
mod invitation;
mod mls_storage;
mod network;
mod pending;

use std::{
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use groups::{CreateGroupSpec, GroupService, IssuedInvitation, LocalGroup};
use identity::{DeviceProfile, IdentityService};
use mls_storage::{CreatedMessage, MlsProviderService};
use network::{AdvertisementResult, NetworkService, PeerSearchResult, SynchronizeGroupResult};
use pending::{JoinedGroup, PendingGroup, PendingInvitationService};
use tauri::Manager;

const MAX_GROUP_ID_TEXT_BYTES: usize = 256;

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
    service: tauri::State<'_, PendingInvitationService>,
) -> Result<Vec<PendingGroup>, String> {
    service.list().map_err(str::to_owned)
}

#[tauri::command]
fn joined_groups(
    service: tauri::State<'_, PendingInvitationService>,
) -> Result<Vec<JoinedGroup>, String> {
    service.joined().map_err(str::to_owned)
}

#[tauri::command]
fn local_groups(service: tauri::State<'_, Arc<GroupService>>) -> Result<Vec<LocalGroup>, String> {
    service.list().map_err(str::to_owned)
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
    let profile = identity_service
        .status()
        .map_err(str::to_owned)?
        .ok_or_else(|| "identity_missing".to_owned())?;
    let device_id = parse_group_id(&profile.peer_id, "identity_record_invalid")?;
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
    if let Err(error) = mls_service.initialize_owner_group(group_id, device_id) {
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
    network_service
        .synchronize(identity, discovery_key, group_id, inviter_device_id)
        .await
        .map_err(str::to_owned)
}

#[tauri::command]
fn send_group_message(
    group_id: String,
    message: String,
    identity_service: tauri::State<'_, IdentityService>,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
) -> Result<CreatedMessage, String> {
    let group_id = parse_group_id(&group_id, "group_not_found")?;
    let identity = identity_service
        .load_network_identity()
        .map_err(str::to_owned)?;
    mls_service
        .create_message(group_id, &identity, &message)
        .map_err(str::to_owned)
}

#[tauri::command]
async fn advertise_group(
    group_id: String,
    identity_service: tauri::State<'_, IdentityService>,
    group_service: tauri::State<'_, Arc<GroupService>>,
    network_service: tauri::State<'_, NetworkService>,
) -> Result<AdvertisementResult, String> {
    let group_id = parse_group_id(&group_id, "group_not_found")?;
    let issued = group_service.issued_invitations().map_err(str::to_owned)?;
    let issued = issued
        .into_iter()
        .find(|invitation| invitation.group_id == group_id.to_string())
        .ok_or_else(|| "issued_invitation_not_found".to_owned())?;
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system_clock_invalid".to_owned())?
        .as_secs();
    let invitation = charp2p_core::Invitation::decode_input(&issued.link, now_unix)
        .map_err(|_| "issued_invitation_record_invalid".to_owned())?;
    let identity = identity_service
        .load_network_identity()
        .map_err(str::to_owned)?;
    let owner_identity = identity_service
        .load_network_identity()
        .map_err(str::to_owned)?;
    network_service
        .advertise(identity, owner_identity, &invitation)
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
    let mut builder = tauri::Builder::default();
    #[cfg(windows)]
    {
        builder = builder.plugin(tauri_plugin_single_instance::init(|app, _, _| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.show();
                let _ = window.set_focus();
            }
        }));
    }

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
                let profile = identity
                    .status()
                    .map_err(std::io::Error::other)?
                    .ok_or_else(|| std::io::Error::other("identity_missing"))?;
                let device_id = profile
                    .peer_id
                    .parse()
                    .map_err(|_| std::io::Error::other("identity_record_invalid"))?;
                for group in &local_groups {
                    let group_id = group
                        .group_id
                        .parse()
                        .map_err(|_| std::io::Error::other("group_identity_record_invalid"))?;
                    mls.initialize_owner_group(group_id, device_id)
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
            joined_groups,
            local_groups,
            issued_invitations,
            create_group,
            create_group_invitation,
            search_group_peers,
            join_group,
            synchronize_group,
            send_group_message,
            advertise_group
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use charp2p_core::GroupIdentity;

    use super::parse_group_id;

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
}
