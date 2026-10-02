use std::time::{SystemTime, UNIX_EPOCH};

use charp2p_core::{HistoryPolicy, Invitation, InvitationError};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvitationPreview {
    pub group_name: String,
    pub inviter_name: String,
    pub inviter_device_id: String,
    pub group_id: String,
    pub expires_at_unix: u64,
    pub history_policy: &'static str,
    pub reusable: bool,
}

pub fn preview_invitation(input: &str) -> Result<InvitationPreview, &'static str> {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system_clock_invalid")?
        .as_secs();
    preview_invitation_at(input, now_unix)
}

fn preview_invitation_at(input: &str, now_unix: u64) -> Result<InvitationPreview, &'static str> {
    let invitation = Invitation::decode_input(input, now_unix).map_err(public_error_code)?;
    let history_policy = match invitation.history_policy() {
        HistoryPolicy::None => "none",
        HistoryPolicy::FromInvitation => "fromInvitation",
        HistoryPolicy::AllRetained => "allRetained",
    };

    Ok(InvitationPreview {
        group_name: invitation.group_name().to_owned(),
        inviter_name: invitation.inviter_name().to_owned(),
        inviter_device_id: invitation.inviter_device_id().to_string(),
        group_id: invitation.group_id().to_string(),
        expires_at_unix: invitation.expires_at_unix(),
        history_policy,
        reusable: invitation.is_reusable(),
    })
}

pub(crate) fn public_error_code(error: InvitationError) -> &'static str {
    match error {
        InvitationError::Expired => "invitation_expired",
        InvitationError::InvalidSignature => "invitation_signature_invalid",
        _ => "invitation_invalid",
    }
}

#[cfg(test)]
mod tests {
    use super::preview_invitation_at;
    use charp2p_core::{
        DeviceIdentity, GroupIdentity, HistoryPolicy, Invitation, InvitationSpec,
    };

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn preview_exposes_authenticated_metadata_without_the_discovery_secret() {
        let owner = GroupIdentity::generate();
        let inviter_device_id = DeviceIdentity::generate().peer_id();
        let encoded = Invitation::issue(
            &owner,
            inviter_device_id,
            InvitationSpec {
                group_name: "Design Crew",
                inviter_name: "Maya",
                expires_at_unix: NOW + 3_600,
                history_policy: HistoryPolicy::FromInvitation,
                reusable: false,
            },
            NOW,
        )
        .unwrap()
        .encode()
        .unwrap();

        let preview = preview_invitation_at(&format!("charp2p://join/{encoded}"), NOW).unwrap();
        assert_eq!(preview.group_name, "Design Crew");
        assert_eq!(preview.inviter_name, "Maya");
        assert_eq!(preview.inviter_device_id, inviter_device_id.to_string());
        assert_eq!(preview.group_id, owner.group_id().to_string());
        assert_eq!(preview.history_policy, "fromInvitation");
        assert!(!preview.reusable);
    }

    #[test]
    fn expired_invitation_has_a_stable_public_error() {
        let owner = GroupIdentity::generate();
        let encoded = Invitation::issue(
            &owner,
            DeviceIdentity::generate().peer_id(),
            InvitationSpec {
                group_name: "Design Crew",
                inviter_name: "Maya",
                expires_at_unix: NOW + 1,
                history_policy: HistoryPolicy::None,
                reusable: false,
            },
            NOW,
        )
        .unwrap()
        .encode()
        .unwrap();

        assert_eq!(
            preview_invitation_at(&encoded, NOW + 1).unwrap_err(),
            "invitation_expired"
        );
    }
}
