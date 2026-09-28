mod identity;
mod invitation;
mod pending;

use identity::{DeviceProfile, IdentityService};
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    identity::initialize_platform_store().expect("platform-protected identity store is available");
    tauri::Builder::default()
        .manage(IdentityService::default())
        .setup(|app| {
            let data_directory = app.path().app_data_dir()?;
            std::fs::create_dir_all(&data_directory)?;
            let pending = PendingInvitationService::open(data_directory.join("charp2p.sqlite3"))
                .map_err(std::io::Error::other)?;
            app.manage(pending);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            identity_status,
            create_identity,
            preview_invitation,
            accept_invitation,
            pending_invitations
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
