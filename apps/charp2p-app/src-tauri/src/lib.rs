mod background;
mod bandwidth;
mod community;
mod contribution;
pub mod groups;
mod identity;
mod invitation;
mod mls_storage;
mod network;
mod pending;
mod preference_file;
mod retention;
mod settings;

use std::sync::{Arc, Mutex};

use background::{BackgroundPreference, BackgroundService, BackgroundStatus};
use bandwidth::{BandwidthPreference, BandwidthService, BandwidthStatus};
use community::{CommunityNodesPreference, CommunityNodesService};
use contribution::{ContributionPreference, ContributionService, ContributionStatus};
use groups::{
    ApprovalDecision, ApprovalRequest, CreateGroupSpec, GroupService, IssuedInvitation, LocalGroup,
    MemberInvitationService, OwnerMemberAdmissionService, ReceivedInvitationCache,
};
use identity::{DeviceProfile, IdentityService};
use libp2p::Multiaddr;
use mls_storage::{
    CreatedMessage, DeviceSequenceConflict, EvidenceExport, GroupMemberDevice, GroupMessagePreview,
    MemberActivity, MlsProviderService, StoredMessagePage, UnreadMessageCount, MAX_EVIDENCE_EVENTS,
    MAX_PREVIEW_GROUPS,
};
use network::{
    AdvertisementResult, GroupConnectionState, NetworkDiagnostics, NetworkService, NetworkStatus,
    OwnedGroupDiscoveryStatus, PeerSearchResult, SynchronizeGroupResult,
};
use pending::{JoinedGroup, PendingGroup, PendingInvitationService};
use retention::{RetentionPreference, RetentionService};
use settings::{AppInformation, SettingsService};
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

/// Exports the device identity as a passphrase-encrypted backup (ADR-028).
/// Only the sealed bytes leave Rust; key derivation runs off the UI thread.
#[tauri::command]
async fn export_identity_backup(
    passphrase: String,
    service: tauri::State<'_, IdentityService>,
) -> Result<Vec<u8>, String> {
    let passphrase = zeroize::Zeroizing::new(passphrase);
    let (device_name, secret) = service.backup_material().map_err(str::to_owned)?;
    tauri::async_runtime::spawn_blocking(move || {
        identity::seal_backup(&device_name, &secret, &passphrase)
    })
    .await
    .map_err(|_| "identity_backup_failed".to_owned())?
    .map_err(str::to_owned)
}

/// Restores the device identity from a passphrase-encrypted backup (ADR-028)
/// on an installation that has none. Key derivation runs off the UI thread.
#[tauri::command]
async fn restore_identity_backup(
    backup: Vec<u8>,
    passphrase: String,
    service: tauri::State<'_, IdentityService>,
) -> Result<DeviceProfile, String> {
    let passphrase = zeroize::Zeroizing::new(passphrase);
    let restored =
        tauri::async_runtime::spawn_blocking(move || identity::open_backup(&backup, &passphrase))
            .await
            .map_err(|_| "identity_backup_invalid".to_owned())?
            .map_err(str::to_owned)?;
    service.restore(restored).map_err(str::to_owned)
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
    let icons = mls_service.current_group_icons().map_err(str::to_owned)?;
    for group in &mut groups {
        apply_current_group_name(&names, &group.group_id, &mut group.group_name);
        group.icon = current_group_icon(&icons, &group.group_id);
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
    let Some(icon) = group_service
        .list()
        .map_err(str::to_owned)?
        .into_iter()
        .find(|group| group.group_id == group_id.to_string())
        .map(|group| group.icon)
    else {
        return Err("group_not_owned".to_owned());
    };
    let group_name = groups::normalize_group_name(&group_name).map_err(str::to_owned)?;
    // Members learn the icon only from metadata, so every rename carries it.
    let metadata = charp2p_core::GroupMetadata::new(&group_name)
        .and_then(|metadata| metadata.with_icon(icon))
        .map_err(|_| "invalid_group_name")?;
    let identity = identity_service
        .load_network_identity()
        .map_err(str::to_owned)?;
    mls_service
        .change_group_metadata(group_id, &identity, &metadata)
        .map_err(str::to_owned)
}

/// Changes an owned group's icon and shares it with members first, so a
/// failed share leaves the owner's icon unchanged and the change retryable.
#[tauri::command]
fn change_group_icon(
    group_id: String,
    icon: u8,
    identity_service: tauri::State<'_, IdentityService>,
    group_service: tauri::State<'_, Arc<GroupService>>,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
) -> Result<LocalGroup, String> {
    let group_id = parse_group_id(&group_id, "group_not_found")?;
    let Some(group) = group_service
        .list()
        .map_err(str::to_owned)?
        .into_iter()
        .find(|group| group.group_id == group_id.to_string())
    else {
        return Err("group_not_owned".to_owned());
    };
    if icon > charp2p_core::MAX_GROUP_ICON {
        return Err("invalid_group_icon".to_owned());
    }
    let identity = identity_service
        .load_network_identity()
        .map_err(str::to_owned)?;
    mls_service
        .share_current_metadata(group_id, &identity, &group.group_name, icon)
        .map_err(str::to_owned)?;
    group_service
        .set_icon(group_id, icon)
        .map_err(str::to_owned)
}

#[tauri::command]
fn invite_permitted_devices(
    group_id: String,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
) -> Result<Vec<String>, String> {
    let group_id = parse_group_id(&group_id, "group_not_found")?;
    mls_service
        .invite_permitted_devices(group_id)
        .map(|devices| devices.iter().map(ToString::to_string).collect())
        .map_err(str::to_owned)
}

#[tauri::command]
fn set_member_invite_permission(
    group_id: String,
    member_device_id: String,
    granted: bool,
    identity_service: tauri::State<'_, IdentityService>,
    group_service: tauri::State<'_, Arc<GroupService>>,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
) -> Result<Vec<String>, String> {
    let group_id = parse_group_id(&group_id, "group_not_found")?;
    let member_id = parse_group_id(&member_device_id, "member_not_found")?;
    if !group_service
        .list()
        .map_err(str::to_owned)?
        .iter()
        .any(|group| group.group_id == group_id.to_string())
    {
        return Err("group_not_owned".to_owned());
    }
    let identity = identity_service
        .load_network_identity()
        .map_err(str::to_owned)?;
    if !granted {
        // Revoke first so a failed change still leaves no invitation the
        // member requested active (ADR-036).
        group_service
            .revoke_requested_invitations(group_id, member_id)
            .map_err(str::to_owned)?;
    }
    mls_service
        .change_invite_permission(group_id, &identity, member_id, granted)
        .map(|devices| devices.iter().map(ToString::to_string).collect())
        .map_err(str::to_owned)
}

/// Asks the pinned owner device for an invitation this member device may
/// share, when the owner granted it invite permission (ADR-036). The owner
/// caps the lifetime by the group maximum; the invitation is kept in memory
/// for display.
#[tauri::command]
async fn request_member_invitation(
    group_id: String,
    lifetime_seconds: Option<u32>,
    identity_service: tauri::State<'_, IdentityService>,
    pending_service: tauri::State<'_, PendingInvitationService>,
    network_service: tauri::State<'_, NetworkService>,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
    received_invitations: tauri::State<'_, ReceivedInvitationCache>,
) -> Result<IssuedInvitation, String> {
    let group_id = parse_group_id(&group_id, "joined_group_not_found")?;
    let identity = identity_service
        .load_network_identity()
        .map_err(str::to_owned)?;
    if !mls_service
        .may_request_invitation(group_id, identity.peer_id())
        .map_err(str::to_owned)?
    {
        return Err("invite_permission_missing".to_owned());
    }
    let (discovery_key, owner_device_id) = pending_service
        .joined_sync_target(group_id)
        .map_err(str::to_owned)?;
    let known_addresses = pending_service
        .known_peer_addresses(group_id, owner_device_id)
        .map_err(str::to_owned)?
        .into_iter()
        .filter_map(|address| Multiaddr::try_from(address).ok())
        .collect::<Vec<_>>();
    let invitation = network_service
        .request_member_invitation(
            identity,
            discovery_key,
            group_id,
            owner_device_id,
            &known_addresses,
            lifetime_seconds.unwrap_or(charp2p_core::MAX_INVITE_REQUEST_LIFETIME_SECONDS),
        )
        .await
        .map_err(str::to_owned)?;
    received_invitations
        .save(invitation.clone())
        .map_err(str::to_owned)?;
    Ok(invitation)
}

/// Lists invitations received from owners in this session while this
/// device still holds invite permission for their groups.
#[tauri::command]
fn received_member_invitations(
    identity_service: tauri::State<'_, IdentityService>,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
    received_invitations: tauri::State<'_, ReceivedInvitationCache>,
) -> Result<Vec<IssuedInvitation>, String> {
    let local_device = identity_service
        .load_network_identity()
        .map_err(str::to_owned)?
        .peer_id();
    received_invitations
        .list(|invitation| {
            invitation.group_id.parse().is_ok_and(|group_id| {
                mls_service
                    .may_request_invitation(group_id, local_device)
                    .unwrap_or(false)
            })
        })
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
    reusable: Option<bool>,
    lifetime_seconds: Option<u64>,
    identity_service: tauri::State<'_, IdentityService>,
    group_service: tauri::State<'_, Arc<GroupService>>,
    network_service: tauri::State<'_, NetworkService>,
) -> Result<IssuedInvitation, String> {
    let group_id = parse_group_id(&group_id, "group_not_found")?;
    let profile = identity_service
        .status()
        .map_err(str::to_owned)?
        .ok_or_else(|| "identity_missing".to_owned())?;
    let inviter_name = identity::invitation_device_name(&profile.device_name);
    let inviter_device_id = parse_group_id(&profile.peer_id, "identity_record_invalid")?;
    group_service
        .issue_invitation(
            group_id,
            inviter_device_id,
            &inviter_name,
            reusable,
            lifetime_seconds,
            &network_service.owner_address_hints(),
        )
        .map_err(str::to_owned)
}

#[tauri::command]
async fn revoke_group_invitation(
    group_id: String,
    invitation_id: String,
    group_service: tauri::State<'_, Arc<GroupService>>,
) -> Result<(), String> {
    let group_id = parse_group_id(&group_id, "group_not_found")?;
    let invitation_id = groups::parse_invitation_id(&invitation_id)
        .ok_or_else(|| "issued_invitation_not_found".to_owned())?;
    group_service
        .revoke_invitation(group_id, invitation_id)
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
async fn check_invitation_reachability(
    input: String,
    identity_service: tauri::State<'_, IdentityService>,
    network_service: tauri::State<'_, NetworkService>,
) -> Result<PeerSearchResult, String> {
    let invitation = invitation::decode_invitation(&input).map_err(str::to_owned)?;
    let identity = identity_service
        .load_network_identity()
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
    bandwidth_service: tauri::State<'_, Arc<BandwidthService>>,
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
    // Unparsable remembered addresses are skipped; the DHT lookup still runs.
    let known_addresses = pending_service
        .known_peer_addresses(group_id, inviter_device_id)
        .map_err(str::to_owned)?
        .into_iter()
        .filter_map(|address| Multiaddr::try_from(address).ok())
        .collect::<Vec<_>>();
    let owner_result = network_service
        .synchronize(
            identity,
            discovery_key,
            group_id,
            inviter_device_id,
            &known_addresses,
            &bandwidth_service,
        )
        .await;
    let result = match owner_result {
        Ok(result) => result,
        // While the owner is unreachable, another current member may serve
        // the history it holds (ADR-040); the owner's error is reported when
        // no member can.
        Err(error) if network::owner_unreachable(error) => {
            let members = mls_service
                .group_members(group_id)
                .map_err(str::to_owned)?
                .into_iter()
                .filter_map(|member| member.device_id.parse().ok())
                .collect::<Vec<_>>();
            let Ok(member_key) = mls_service.member_rendezvous_key(group_id) else {
                return Err(error.to_owned());
            };
            let identity = identity_service
                .load_network_identity()
                .map_err(str::to_owned)?;
            return network_service
                .pull_from_members(identity, member_key, group_id, &members, &bandwidth_service)
                .await
                .map_err(|_| error.to_owned());
        }
        Err(error) => return Err(error.to_owned()),
    };
    pending_service
        .record_synchronization(group_id, result.synchronized_at_unix)
        .map_err(str::to_owned)?;
    let peer_address = result.peer_address.to_vec();
    if !peer_address.is_empty() && peer_address.len() <= charp2p_store::MAX_PEER_ADDRESS_BYTES {
        pending_service
            .record_peer_address(
                group_id,
                inviter_device_id,
                &peer_address,
                result.synchronized_at_unix,
            )
            .map_err(str::to_owned)?;
    }
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

/// Sends a signed group-wide tombstone for one of this device's messages.
#[tauri::command]
fn delete_group_message(
    group_id: String,
    event_id: String,
    identity_service: tauri::State<'_, IdentityService>,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
) -> Result<(), String> {
    let group_id = parse_group_id(&group_id, "group_not_found")?;
    let event_id = parse_event_id(&event_id)?;
    let identity = identity_service
        .load_network_identity()
        .map_err(str::to_owned)?;
    mls_service
        .delete_message(group_id, &identity, &event_id)
        .map_err(str::to_owned)
}

#[tauri::command]
fn group_messages(
    group_id: String,
    identity_service: tauri::State<'_, IdentityService>,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
    retention_service: tauri::State<'_, RetentionService>,
) -> Result<StoredMessagePage, String> {
    let group_id = parse_group_id(&group_id, "group_not_found")?;
    apply_message_retention(&retention_service, &mls_service).map_err(str::to_owned)?;
    let identity = identity_service
        .load_network_identity()
        .map_err(str::to_owned)?;
    mls_service
        .messages(group_id, identity.peer_id())
        .map_err(str::to_owned)
}

/// Exports the signed envelopes of user-selected messages with the text shown
/// on this device (ADR-029).
#[tauri::command]
fn export_message_evidence(
    group_id: String,
    event_ids: Vec<String>,
    identity_service: tauri::State<'_, IdentityService>,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
) -> Result<EvidenceExport, String> {
    let group_id = parse_group_id(&group_id, "group_not_found")?;
    if event_ids.is_empty() || event_ids.len() > MAX_EVIDENCE_EVENTS {
        return Err("evidence_selection_invalid".to_owned());
    }
    let event_ids = event_ids
        .iter()
        .map(|event_id| parse_event_id(event_id))
        .collect::<Result<Vec<_>, _>>()?;
    let identity = identity_service
        .load_network_identity()
        .map_err(str::to_owned)?;
    let generated_at_unix_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or("system_clock_invalid")?;
    mls_service
        .evidence(
            group_id,
            identity.peer_id(),
            &event_ids,
            generated_at_unix_ms,
        )
        .map_err(str::to_owned)
}

#[tauri::command]
fn unread_message_counts(
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
    retention_service: tauri::State<'_, RetentionService>,
) -> Result<Vec<UnreadMessageCount>, String> {
    apply_message_retention(&retention_service, &mls_service).map_err(str::to_owned)?;
    mls_service.unread_message_counts().map_err(str::to_owned)
}

/// Returns the newest message of each listed group for the group list.
#[tauri::command]
fn group_message_previews(
    group_ids: Vec<String>,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
    retention_service: tauri::State<'_, RetentionService>,
) -> Result<Vec<GroupMessagePreview>, String> {
    if group_ids.len() > MAX_PREVIEW_GROUPS {
        return Err("group_selection_invalid".to_owned());
    }
    let group_ids = group_ids
        .iter()
        .map(|group_id| parse_group_id(group_id, "group_not_found"))
        .collect::<Result<Vec<_>, _>>()?;
    apply_message_retention(&retention_service, &mls_service).map_err(str::to_owned)?;
    mls_service
        .message_previews(&group_ids)
        .map_err(str::to_owned)
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
fn group_member_activity(
    group_id: String,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
) -> Result<Vec<MemberActivity>, String> {
    let group_id = parse_group_id(&group_id, "group_not_found")?;
    mls_service.member_activity(group_id).map_err(str::to_owned)
}

#[tauri::command]
fn group_sequence_conflicts(
    group_id: String,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
) -> Result<Vec<DeviceSequenceConflict>, String> {
    let group_id = parse_group_id(&group_id, "group_not_found")?;
    mls_service
        .sequence_conflicts(group_id)
        .map_err(str::to_owned)
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
    group_service
        .revoke_requested_invitations(group_id, member_id)
        .map_err(str::to_owned)?;
    mls_service
        .remove_member(group_id, &identity, member_id)
        .map_err(str::to_owned)
}

/// Advances a locally owned group to fresh MLS keys without changing its
/// membership (ADR-045).
#[tauri::command]
fn refresh_group_keys(
    group_id: String,
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
        return Err("key_refresh_not_allowed".to_owned());
    }
    let identity = identity_service
        .load_network_identity()
        .map_err(str::to_owned)?;
    mls_service
        .refresh_group_keys(group_id, &identity)
        .map_err(str::to_owned)
}

/// Lists join requests and declined devices for a locally owned group
/// created with approval required (ADR-041).
#[tauri::command]
fn group_approval_requests(
    group_id: String,
    group_service: tauri::State<'_, Arc<GroupService>>,
) -> Result<Vec<ApprovalRequest>, String> {
    let group_id = parse_group_id(&group_id, "group_not_found")?;
    group_service
        .approval_requests(group_id)
        .map_err(str::to_owned)
}

/// Approves or declines a join request, or allows a declined device to ask
/// again, and returns the updated requests.
#[tauri::command]
fn decide_group_approval_request(
    group_id: String,
    device_id: String,
    decision: String,
    group_service: tauri::State<'_, Arc<GroupService>>,
) -> Result<Vec<ApprovalRequest>, String> {
    let group_id = parse_group_id(&group_id, "group_not_found")?;
    let device_id = parse_group_id(&device_id, "approval_request_not_found")?;
    let decision = match decision.as_str() {
        "approve" => ApprovalDecision::Approve,
        "decline" => ApprovalDecision::Decline,
        "allow" => ApprovalDecision::Allow,
        _ => return Err("approval_decision_invalid".to_owned()),
    };
    group_service
        .decide_approval_request(group_id, device_id, decision)
        .map_err(str::to_owned)
}

/// Lists devices removed from a locally owned group that stay blocked from
/// joining again.
#[tauri::command]
fn removed_group_members(
    group_id: String,
    group_service: tauri::State<'_, Arc<GroupService>>,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
) -> Result<Vec<String>, String> {
    let group_id = parse_group_id(&group_id, "group_not_found")?;
    ensure_owned_group(&group_service, group_id, "member_readmission_not_allowed")?;
    mls_service.removed_members(group_id).map_err(str::to_owned)
}

/// Lets a removed device join a locally owned group again through an
/// active invitation (ADR-034).
#[tauri::command]
fn allow_group_member_readmission(
    group_id: String,
    member_device_id: String,
    identity_service: tauri::State<'_, IdentityService>,
    group_service: tauri::State<'_, Arc<GroupService>>,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
) -> Result<Vec<String>, String> {
    let group_id = parse_group_id(&group_id, "group_not_found")?;
    let member_id = parse_group_id(&member_device_id, "member_not_found")?;
    ensure_owned_group(&group_service, group_id, "member_readmission_not_allowed")?;
    let identity = identity_service
        .load_network_identity()
        .map_err(str::to_owned)?;
    mls_service
        .allow_member_readmission(group_id, &identity, member_id)
        .map_err(str::to_owned)
}

fn ensure_owned_group(
    group_service: &GroupService,
    group_id: charp2p_core::PeerId,
    error: &str,
) -> Result<(), String> {
    if group_service
        .list()
        .map_err(str::to_owned)?
        .iter()
        .any(|group| group.group_id == group_id.to_string())
    {
        Ok(())
    } else {
        Err(error.to_owned())
    }
}

/// Reports connection type, bootstrap nodes and advertising state for the
/// Network page. Contains no keys, invitations or group identifiers.
#[tauri::command]
async fn network_status(
    network_service: tauri::State<'_, NetworkService>,
) -> Result<NetworkStatus, String> {
    Ok(network_service.status().await)
}

/// Reports the Groups page connection state of each joined group from its
/// latest synchronization attempt in this session.
#[tauri::command]
fn group_connection_states(
    pending_service: tauri::State<'_, PendingInvitationService>,
    network_service: tauri::State<'_, NetworkService>,
) -> Result<Vec<GroupConnectionState>, String> {
    let group_ids = pending_service
        .joined()
        .map_err(str::to_owned)?
        .iter()
        .filter_map(|group| group.group_id.parse().ok())
        .collect::<Vec<_>>();
    Ok(network_service.group_connection_states(&group_ids))
}

/// Reports whether the background provider advertises an owned group's
/// retained rendezvous keys, for its group details.
#[tauri::command]
async fn owned_group_discovery_status(
    group_id: String,
    group_service: tauri::State<'_, Arc<GroupService>>,
    network_service: tauri::State<'_, NetworkService>,
) -> Result<OwnedGroupDiscoveryStatus, String> {
    let group_id = parse_group_id(&group_id, "group_not_found")?;
    let keys = group_service
        .owner_discovery_keys(group_id)
        .map_err(str::to_owned)?;
    Ok(network_service.owned_group_discovery_status(&keys).await)
}

/// Builds the Network page diagnostic export. Groups are reported only as
/// counts; identity, invitation and discovery secrets are never read.
#[tauri::command]
async fn network_diagnostics(
    group_service: tauri::State<'_, Arc<GroupService>>,
    pending_service: tauri::State<'_, PendingInvitationService>,
    network_service: tauri::State<'_, NetworkService>,
) -> Result<NetworkDiagnostics, String> {
    let owned_groups = group_service.list().map_err(str::to_owned)?.len();
    let joined_groups = pending_service.joined().map_err(str::to_owned)?.len();
    Ok(network_service
        .diagnostics(owned_groups, joined_groups)
        .await)
}

/// Reports version and local storage use for the Settings page.
#[tauri::command]
fn app_information(service: tauri::State<'_, SettingsService>) -> Result<AppInformation, String> {
    service.information().map_err(str::to_owned)
}

/// Reports the device-local background preference (ADR-032).
#[tauri::command]
fn background_status(
    service: tauri::State<'_, BackgroundService>,
) -> Result<BackgroundStatus, String> {
    service.status().map_err(str::to_owned)
}

/// Registers or removes the operating system login entry, then stores the
/// device-local background preference. Keeping running applies to the next
/// window close request. Refused on builds without background running.
#[tauri::command]
fn set_background_preference(
    app: tauri::AppHandle,
    preference: BackgroundPreference,
    service: tauri::State<'_, BackgroundService>,
) -> Result<BackgroundStatus, String> {
    if service.is_available() {
        set_launch_at_login(&app, preference.launch_at_login).map_err(str::to_owned)?;
    }
    service.set(preference).map_err(str::to_owned)
}

/// The login entry passes [`background::LOGIN_LAUNCH_ARGUMENT`] so the app can
/// tell a login launch from one the user started.
#[cfg(desktop)]
fn set_launch_at_login(app: &tauri::AppHandle, enabled: bool) -> Result<(), &'static str> {
    use tauri_plugin_autostart::ManagerExt;

    let launcher = app.autolaunch();
    let result = if enabled {
        launcher.enable()
    } else if launcher.is_enabled().unwrap_or(true) {
        launcher.disable()
    } else {
        Ok(())
    };
    result.map_err(|_| "launch_at_login_unavailable")
}

#[cfg(mobile)]
fn set_launch_at_login(_app: &tauri::AppHandle, _enabled: bool) -> Result<(), &'static str> {
    Err("launch_at_login_unavailable")
}

/// Reports the device-local synchronization data limit and the budget left
/// now (ADR-033).
#[tauri::command]
fn bandwidth_status(
    service: tauri::State<'_, Arc<BandwidthService>>,
) -> Result<BandwidthStatus, String> {
    service.status().map_err(str::to_owned)
}

/// Stores the device-local synchronization data limit; the next
/// synchronization exchange is metered against it.
#[tauri::command]
fn set_bandwidth_preference(
    preference: BandwidthPreference,
    service: tauri::State<'_, Arc<BandwidthService>>,
) -> Result<BandwidthStatus, String> {
    service.set(preference).map_err(str::to_owned)
}

/// Removes readable message copies older than the stored retention
/// (ADR-035). Messages synchronized later with old timestamps are removed
/// before they are next listed. Returns how many copies were removed.
fn apply_message_retention(
    retention: &RetentionService,
    mls: &MlsProviderService,
) -> Result<u64, &'static str> {
    match retention.current_cutoff_unix_ms() {
        Some(cutoff_unix_ms) => mls.hide_messages_created_before(cutoff_unix_ms),
        None => Ok(0),
    }
}

/// Reports the device-local message retention (ADR-035).
#[tauri::command]
fn retention_preference(
    service: tauri::State<'_, RetentionService>,
) -> Result<RetentionPreference, String> {
    service.preference().map_err(str::to_owned)
}

/// Stores the device-local message retention and applies it at once.
/// Returns how many readable message copies were removed.
#[tauri::command]
fn set_retention_preference(
    preference: RetentionPreference,
    service: tauri::State<'_, RetentionService>,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
) -> Result<u64, String> {
    service.set(preference).map_err(str::to_owned)?;
    apply_message_retention(&service, &mls_service).map_err(str::to_owned)
}

/// Exits the application, including when closing the window would only hide
/// it.
#[tauri::command]
fn quit_app(app: tauri::AppHandle) {
    app.exit(0);
}

/// Lists the community bootstrap nodes added on this device (ADR-038).
#[tauri::command]
fn community_nodes(
    service: tauri::State<'_, CommunityNodesService>,
) -> Result<Vec<String>, String> {
    service
        .preference()
        .map(|preference| preference.addresses)
        .map_err(str::to_owned)
}

/// Stores the community bootstrap nodes and uses them for new connections;
/// the owner advertising provider restarts on its next refresh.
#[tauri::command]
async fn set_community_nodes(
    addresses: Vec<String>,
    service: tauri::State<'_, CommunityNodesService>,
    network_service: tauri::State<'_, NetworkService>,
) -> Result<Vec<String>, String> {
    let preference = CommunityNodesPreference { addresses };
    preference.validate().map_err(str::to_owned)?;
    let peers = network_service
        .community_peers(&preference.addresses)
        .map_err(str::to_owned)?;
    service.set(&preference).map_err(str::to_owned)?;
    network_service.use_community_peers(peers).await;
    Ok(preference.addresses)
}

/// Reports the device-local contribution preference and its worst-case
/// relayed volume (ADR-031).
#[tauri::command]
fn contribution_status(
    service: tauri::State<'_, ContributionService>,
) -> Result<ContributionStatus, String> {
    service.status().map_err(str::to_owned)
}

/// Stores the device-local contribution preference after validating the relay
/// limits, then starts, restarts or stops the contribution node to match it.
/// Refused on builds that keep the light-peer role.
#[tauri::command]
async fn set_contribution_preference(
    preference: ContributionPreference,
    service: tauri::State<'_, ContributionService>,
    identity_service: tauri::State<'_, IdentityService>,
    network_service: tauri::State<'_, NetworkService>,
) -> Result<ContributionStatus, String> {
    let status = service.set(preference).map_err(str::to_owned)?;
    apply_contribution(preference, &identity_service, &network_service)
        .await
        .map_err(str::to_owned)?;
    Ok(status)
}

/// Runs the contribution node when routing contribution is enabled and stops
/// it otherwise (ADR-031).
async fn apply_contribution(
    preference: ContributionPreference,
    identity_service: &IdentityService,
    network_service: &NetworkService,
) -> Result<(), &'static str> {
    if !preference.routing {
        network_service.stop_contribution().await;
        return Ok(());
    }
    let relay = preference.relay_limits()?;
    let identity = identity_service.load_network_identity()?;
    network_service.start_contribution(identity, relay).await?;
    Ok(())
}

/// Serves the open joined group's history to its other current members
/// (ADR-040), advertising the member rendezvous key of the current MLS
/// epoch. Called again after each synchronization so a new epoch is
/// re-advertised; no group (or an owned one) stops the member serving node.
#[tauri::command]
async fn serve_joined_group(
    group_id: Option<String>,
    identity_service: tauri::State<'_, IdentityService>,
    pending_service: tauri::State<'_, PendingInvitationService>,
    network_service: tauri::State<'_, NetworkService>,
    mls_service: tauri::State<'_, Arc<MlsProviderService>>,
    bandwidth_service: tauri::State<'_, Arc<BandwidthService>>,
) -> Result<&'static str, String> {
    let Some(group_id) = group_id else {
        network_service.stop_member_serving().await;
        return Ok("inactive");
    };
    let group_id = parse_group_id(&group_id, "joined_group_not_found")?;
    if pending_service.joined_sync_target(group_id).is_err() {
        network_service.stop_member_serving().await;
        return Ok("inactive");
    }
    // A removed or unreadable group stops advertising its earlier epoch key.
    let key = match mls_service.member_rendezvous_key(group_id) {
        Ok(key) => key,
        Err(error) => {
            network_service.stop_member_serving().await;
            return Err(error.to_owned());
        }
    };
    let identity = identity_service
        .load_network_identity()
        .map_err(str::to_owned)?;
    network_service
        .serve_member_group(identity, group_id, key, Arc::clone(&bandwidth_service))
        .await
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
    let profile = identity_service
        .status()
        .map_err(str::to_owned)?
        .ok_or_else(|| "identity_missing".to_owned())?;
    let inviter_name = identity::invitation_device_name(&profile.device_name);
    network_service
        .advertise_owner_group(identity, owner_identity, inviter_name, keys)
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

    #[cfg(desktop)]
    let builder = builder.plugin(
        tauri_plugin_autostart::Builder::new()
            .arg(background::LOGIN_LAUNCH_ARGUMENT)
            .build(),
    );

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
            let network = NetworkService::from_environment(
                groups.clone(),
                Arc::new(OwnerMemberAdmissionService::new(
                    groups.clone(),
                    mls.clone(),
                )),
                mls.clone(),
                Arc::new(MemberInvitationService::new(groups.clone(), mls.clone())),
            )
            .map_err(std::io::Error::other)?;
            // An unreadable or invalid community node list is reported on the
            // Network page and leaves only built-in and environment nodes.
            let community = CommunityNodesService::new(data_directory.join("community-nodes.json"));
            if let Ok(peers) = community
                .preference()
                .and_then(|preference| network.community_peers(&preference.addresses))
            {
                network.replace_community_peers(peers);
            }
            app.manage(community);
            app.manage(identity);
            app.manage(pending);
            app.manage(groups);
            app.manage(mls);
            app.manage(network);
            app.manage(ReceivedInvitationCache::default());
            app.manage(BackgroundService::new(
                data_directory.join("background.json"),
            ));
            // A launch at login starts hidden only when closing the window
            // would keep running too (ADR-032); a later launch shows it.
            let launched_at_login =
                std::env::args().any(|argument| argument == background::LOGIN_LAUNCH_ARGUMENT);
            if app
                .state::<BackgroundService>()
                .starts_hidden(launched_at_login)
            {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            }
            app.manage(ContributionService::new(
                data_directory.join("contribution.json"),
            ));
            app.manage(Arc::new(BandwidthService::new(
                data_directory.join("bandwidth.json"),
            )));
            app.manage(RetentionService::new(data_directory.join("retention.json")));
            app.manage(SettingsService::new(database_path));

            // Resume an opted-in contribution from the stored preference; a
            // missing identity or invalid preference leaves contribution off.
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let Ok(status) = handle.state::<ContributionService>().status() else {
                    return;
                };
                if status.available && status.preference.routing {
                    let _ = apply_contribution(
                        status.preference,
                        &handle.state::<IdentityService>(),
                        &handle.state::<NetworkService>(),
                    )
                    .await;
                }
            });
            Ok(())
        })
        .on_window_event(|window, event| {
            // Keep advertising and synchronizing while the window is hidden
            // when the user chose to; a second launch shows it again.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window
                    .state::<BackgroundService>()
                    .keeps_running_when_closed()
                {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            identity_status,
            create_identity,
            export_identity_backup,
            restore_identity_backup,
            preview_invitation,
            accept_invitation,
            pending_invitations,
            cancel_pending_invitation,
            joined_groups,
            leave_joined_group,
            local_groups,
            rename_group,
            change_group_icon,
            invite_permitted_devices,
            set_member_invite_permission,
            request_member_invitation,
            received_member_invitations,
            issued_invitations,
            create_group,
            create_group_invitation,
            revoke_group_invitation,
            search_group_peers,
            check_invitation_reachability,
            join_group,
            synchronize_group,
            send_group_message,
            edit_group_message,
            delete_group_message,
            group_messages,
            export_message_evidence,
            hide_group_message,
            unread_message_counts,
            group_message_previews,
            group_members,
            remove_group_member,
            refresh_group_keys,
            removed_group_members,
            group_approval_requests,
            decide_group_approval_request,
            allow_group_member_readmission,
            group_member_activity,
            group_sequence_conflicts,
            blocked_group_devices,
            set_group_device_blocked,
            advertise_owned_groups,
            serve_joined_group,
            network_status,
            group_connection_states,
            owned_group_discovery_status,
            network_diagnostics,
            app_information,
            background_status,
            set_background_preference,
            quit_app,
            bandwidth_status,
            set_bandwidth_preference,
            retention_preference,
            set_retention_preference,
            community_nodes,
            set_community_nodes,
            contribution_status,
            set_contribution_preference
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

/// Returns the icon of the latest authenticated owner metadata applied on
/// this device, if any carried one.
fn current_group_icon(icons: &[(charp2p_core::PeerId, u8)], group_id: &str) -> Option<u8> {
    icons
        .iter()
        .find(|(candidate, _)| candidate.to_string() == group_id)
        .map(|(_, icon)| *icon)
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

    use super::{current_group_icon, parse_event_id, parse_group_id};

    #[test]
    fn joined_group_icons_come_from_matching_metadata_only() {
        let group_id = GroupIdentity::generate().group_id();
        let other = GroupIdentity::generate().group_id();
        let icons = [(other, 1), (group_id, 4)];
        assert_eq!(current_group_icon(&icons, &group_id.to_string()), Some(4));
        assert_eq!(current_group_icon(&icons[..1], &group_id.to_string()), None);
    }

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
