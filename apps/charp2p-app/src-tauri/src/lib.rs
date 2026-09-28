mod groups;
mod identity;
mod invitation;
mod network;
mod pending;

use std::sync::{Arc, Mutex};

use groups::{CreateGroupSpec, GroupService, LocalGroup};
use identity::{DeviceProfile, IdentityService};
use network::{NetworkService, PeerSearchResult};
use pending::{PendingGroup, PendingInvitationService};
use tauri::Manager;

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
    service: tauri::State<'_, PendingInvitationService>,
) -> Result<PendingGroup, String> {
    service.accept(&input).map_err(str::to_owned)
}

#[tauri::command]
fn pending_invitations(
    service: tauri::State<'_, PendingInvitationService>,
) -> Result<Vec<PendingGroup>, String> {
    service.list().map_err(str::to_owned)
}

#[tauri::command]
fn local_groups(service: tauri::State<'_, GroupService>) -> Result<Vec<LocalGroup>, String> {
    service.list().map_err(str::to_owned)
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
    group_service: tauri::State<'_, GroupService>,
) -> Result<LocalGroup, String> {
    if identity_service.status().map_err(str::to_owned)?.is_none() {
        return Err("identity_missing".to_owned());
    }
    group_service
        .create(CreateGroupSpec {
            group_name: &group_name,
            icon,
            history_policy: &history_policy,
            approval_required,
            invitation_lifetime_seconds,
            reusable_invitation,
        })
        .map_err(str::to_owned)
}

#[tauri::command]
async fn search_group_peers(
    group_id: String,
    identity_service: tauri::State<'_, IdentityService>,
    pending_service: tauri::State<'_, PendingInvitationService>,
    network_service: tauri::State<'_, NetworkService>,
) -> Result<PeerSearchResult, String> {
    let group_id = group_id
        .parse()
        .map_err(|_| "pending_invitation_not_found".to_owned())?;
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
            let groups =
                GroupService::open(data_directory.join("charp2p.sqlite3"), storage_operations)
                    .map_err(std::io::Error::other)?;
            let network = NetworkService::from_environment().map_err(std::io::Error::other)?;
            app.manage(identity);
            app.manage(pending);
            app.manage(groups);
            app.manage(network);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            identity_status,
            create_identity,
            preview_invitation,
            accept_invitation,
            pending_invitations,
            local_groups,
            create_group,
            search_group_peers
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
