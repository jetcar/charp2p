use std::{
    path::Path,
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use charp2p_core::{HistoryPolicy, Invitation, PeerId};
use charp2p_store::{EventStore, PendingInvitationMetadata};
use keyring_core::Error as KeyringError;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::{identity::protected_entry, invitation::public_error_code};

const MAX_PROTECTED_INVITATION_BYTES: usize = 2 * 1024;
const CREDENTIAL_PREFIX: &str = "pending-invitation-v1-";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingGroup {
    pub group_name: String,
    pub inviter_name: String,
    pub group_id: String,
    pub expires_at_unix: u64,
    pub history_policy: &'static str,
    pub reusable: bool,
}

trait InvitationSecretStore: Send + Sync {
    fn put(&self, group_id: PeerId, encoded: &[u8]) -> Result<(), &'static str>;
    fn get(&self, group_id: PeerId) -> Result<Zeroizing<Vec<u8>>, &'static str>;
    fn remove(&self, group_id: PeerId) -> Result<(), &'static str>;
}

struct PlatformInvitationSecretStore;

impl InvitationSecretStore for PlatformInvitationSecretStore {
    fn put(&self, group_id: PeerId, encoded: &[u8]) -> Result<(), &'static str> {
        protected_entry(&credential_user(group_id))?
            .set_secret(encoded)
            .map_err(|_| "pending_invitation_store_unavailable")
    }

    fn get(&self, group_id: PeerId) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        protected_entry(&credential_user(group_id))?
            .get_secret()
            .map(Zeroizing::new)
            .map_err(|_| "pending_invitation_store_unavailable")
    }

    fn remove(&self, group_id: PeerId) -> Result<(), &'static str> {
        match protected_entry(&credential_user(group_id))?.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(_) => Err("pending_invitation_store_unavailable"),
        }
    }
}

pub struct PendingInvitationService {
    metadata: Mutex<EventStore>,
    secrets: Box<dyn InvitationSecretStore>,
}

impl PendingInvitationService {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, &'static str> {
        Ok(Self {
            metadata: Mutex::new(
                EventStore::open(path).map_err(|_| "pending_invitation_store_unavailable")?,
            ),
            secrets: Box::new(PlatformInvitationSecretStore),
        })
    }

    pub fn accept(&self, input: &str) -> Result<PendingGroup, &'static str> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system_clock_invalid")?
            .as_secs();
        self.accept_at(input, now_unix)
    }

    pub fn list(&self) -> Result<Vec<PendingGroup>, &'static str> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system_clock_invalid")?
            .as_secs();
        self.list_at(now_unix)
    }

    fn list_at(&self, now_unix: u64) -> Result<Vec<PendingGroup>, &'static str> {
        let metadata = self
            .metadata
            .lock()
            .map_err(|_| "pending_invitation_service_unavailable")?
            .pending_invitations()
            .map_err(|_| "pending_invitation_store_unavailable")?;
        let mut pending = Vec::with_capacity(metadata.len());
        for stored in metadata {
            let encoded = self.secrets.get(stored.group_id)?;
            let encoded = std::str::from_utf8(encoded.as_slice())
                .map_err(|_| "pending_invitation_record_invalid")?;
            let invitation =
                Invitation::decode(encoded, 0).map_err(|_| "pending_invitation_record_invalid")?;
            if !metadata_matches_invitation(&stored, &invitation) {
                return Err("pending_invitation_record_invalid");
            }
            if invitation.expires_at_unix() <= now_unix {
                self.secrets.remove(stored.group_id)?;
                self.metadata
                    .lock()
                    .map_err(|_| "pending_invitation_service_unavailable")?
                    .remove_pending_invitation(stored.group_id)
                    .map_err(|_| "pending_invitation_store_unavailable")?;
                continue;
            }
            pending.push(stored.into());
        }
        Ok(pending)
    }

    fn accept_at(&self, input: &str, now_unix: u64) -> Result<PendingGroup, &'static str> {
        let invitation = Invitation::decode_input(input, now_unix).map_err(public_error_code)?;
        let encoded = invitation.encode().map_err(public_error_code)?;
        if encoded.len() > MAX_PROTECTED_INVITATION_BYTES {
            return Err("pending_invitation_too_large");
        }

        let metadata = PendingInvitationMetadata {
            group_id: invitation.group_id(),
            group_name: invitation.group_name().to_owned(),
            inviter_name: invitation.inviter_name().to_owned(),
            expires_at_unix: invitation.expires_at_unix(),
            history_policy: invitation.history_policy(),
            reusable: invitation.is_reusable(),
        };
        self.secrets.put(metadata.group_id, encoded.as_bytes())?;
        self.metadata
            .lock()
            .map_err(|_| "pending_invitation_service_unavailable")?
            .put_pending_invitation(&metadata)
            .map_err(|_| "pending_invitation_store_unavailable")?;
        Ok(metadata.into())
    }
}

impl From<PendingInvitationMetadata> for PendingGroup {
    fn from(metadata: PendingInvitationMetadata) -> Self {
        Self {
            group_name: metadata.group_name,
            inviter_name: metadata.inviter_name,
            group_id: metadata.group_id.to_string(),
            expires_at_unix: metadata.expires_at_unix,
            history_policy: history_policy_name(metadata.history_policy),
            reusable: metadata.reusable,
        }
    }
}

fn credential_user(group_id: PeerId) -> String {
    format!("{CREDENTIAL_PREFIX}{group_id}")
}

fn history_policy_name(policy: HistoryPolicy) -> &'static str {
    match policy {
        HistoryPolicy::None => "none",
        HistoryPolicy::FromInvitation => "fromInvitation",
        HistoryPolicy::AllRetained => "allRetained",
    }
}

fn metadata_matches_invitation(
    metadata: &PendingInvitationMetadata,
    invitation: &Invitation,
) -> bool {
    metadata.group_id == invitation.group_id()
        && metadata.group_name == invitation.group_name()
        && metadata.inviter_name == invitation.inviter_name()
        && metadata.expires_at_unix == invitation.expires_at_unix()
        && metadata.history_policy == invitation.history_policy()
        && metadata.reusable == invitation.is_reusable()
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use charp2p_core::{GroupIdentity, HistoryPolicy, Invitation, InvitationSpec, PeerId};
    use charp2p_store::EventStore;

    use super::{InvitationSecretStore, PendingInvitationService};

    const NOW: u64 = 1_800_000_000;

    #[derive(Default)]
    struct MemorySecretStore {
        saved: Mutex<Vec<(PeerId, Vec<u8>)>>,
    }

    impl InvitationSecretStore for MemorySecretStore {
        fn put(&self, group_id: PeerId, encoded: &[u8]) -> Result<(), &'static str> {
            self.saved
                .lock()
                .unwrap()
                .push((group_id, encoded.to_vec()));
            Ok(())
        }

        fn get(&self, group_id: PeerId) -> Result<zeroize::Zeroizing<Vec<u8>>, &'static str> {
            self.saved
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find(|(stored_group, _)| *stored_group == group_id)
                .map(|(_, encoded)| zeroize::Zeroizing::new(encoded.clone()))
                .ok_or("pending_invitation_store_unavailable")
        }

        fn remove(&self, group_id: PeerId) -> Result<(), &'static str> {
            self.saved
                .lock()
                .unwrap()
                .retain(|(stored_group, _)| *stored_group != group_id);
            Ok(())
        }
    }

    fn service() -> PendingInvitationService {
        PendingInvitationService {
            metadata: Mutex::new(EventStore::in_memory().unwrap()),
            secrets: Box::<MemorySecretStore>::default(),
        }
    }

    fn invitation() -> (String, PeerId) {
        let owner = GroupIdentity::generate();
        let encoded = Invitation::issue(
            &owner,
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
        (encoded, owner.group_id())
    }

    #[test]
    fn accepting_an_invitation_persists_safe_metadata() {
        let service = service();
        let (encoded, group_id) = invitation();

        let accepted = service.accept_at(&encoded, NOW).unwrap();
        assert_eq!(accepted.group_name, "Design Crew");
        assert_eq!(accepted.group_id, group_id.to_string());
        assert_eq!(service.list_at(NOW).unwrap(), vec![accepted]);
    }

    #[test]
    fn invalid_invitation_is_not_added_to_the_pending_list() {
        let service = service();

        assert_eq!(service.accept_at("invalid", NOW), Err("invitation_invalid"));
        assert!(service.list_at(NOW).unwrap().is_empty());
    }

    #[test]
    fn changed_metadata_is_rejected_on_restart_load() {
        let service = service();
        let (encoded, group_id) = invitation();
        service.accept_at(&encoded, NOW).unwrap();
        service
            .metadata
            .lock()
            .unwrap()
            .put_pending_invitation(&charp2p_store::PendingInvitationMetadata {
                group_id,
                group_name: "Changed locally".to_owned(),
                inviter_name: "Maya".to_owned(),
                expires_at_unix: NOW + 3_600,
                history_policy: HistoryPolicy::FromInvitation,
                reusable: false,
            })
            .unwrap();

        assert_eq!(
            service.list_at(NOW),
            Err("pending_invitation_record_invalid")
        );
    }

    #[test]
    fn expired_invitation_is_removed_from_both_stores() {
        let service = service();
        let (encoded, _) = invitation();
        service.accept_at(&encoded, NOW).unwrap();

        assert!(service.list_at(NOW + 3_600).unwrap().is_empty());
        assert!(service
            .metadata
            .lock()
            .unwrap()
            .pending_invitations()
            .unwrap()
            .is_empty());
    }
}
