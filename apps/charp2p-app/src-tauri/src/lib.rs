mod identity;

use identity::{DeviceProfile, IdentityService};

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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    identity::initialize_platform_store().expect("platform-protected identity store is available");
    tauri::Builder::default()
        .manage(IdentityService::default())
        .invoke_handler(tauri::generate_handler![identity_status, create_identity])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
