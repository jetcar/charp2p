use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use charp2p_core::{DiscoveryKey, HistoryPolicy, Invitation, PeerId};
use charp2p_store::{EventStore, JoinedGroupMetadata, PendingInvitationMetadata};
use keyring_core::Error as KeyringError;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::{identity::protected_entry, invitation::public_error_code};

const MAX_PROTECTED_INVITATION_BYTES: usize = 2 * 1024;
const CREDENTIAL_PREFIX: &str = "pending-invitation-v1-";
const DISCOVERY_CREDENTIAL_PREFIX: &str = "joined-discovery-v1-";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingGroup {
    pub group_name: String,
    pub inviter_name: String,
    pub inviter_device_id: String,
    pub group_id: String,
    pub expires_at_unix: u64,
    pub history_policy: &'static str,
    pub reusable: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinedGroup {
    pub group_name: String,
    pub inviter_name: String,
    pub inviter_device_id: String,
    pub group_id: String,
    pub history_policy: &'static str,
}

trait InvitationSecretStore: Send + Sync {
    fn put(&self, group_id: PeerId, encoded: &[u8]) -> Result<(), &'static str>;
    fn get_optional(&self, group_id: PeerId) -> Result<Option<Zeroizing<Vec<u8>>>, &'static str>;
    fn remove(&self, group_id: PeerId) -> Result<(), &'static str>;
}

trait JoinedDiscoveryStore: Send + Sync {
    fn put(&self, group_id: PeerId, key: &DiscoveryKey) -> Result<(), &'static str>;
    fn get_optional(&self, group_id: PeerId) -> Result<Option<DiscoveryKey>, &'static str>;
    fn remove(&self, group_id: PeerId) -> Result<(), &'static str>;
}

struct PlatformInvitationSecretStore;

struct PlatformJoinedDiscoveryStore;

impl InvitationSecretStore for PlatformInvitationSecretStore {
    fn put(&self, group_id: PeerId, encoded: &[u8]) -> Result<(), &'static str> {
        protected_entry(&credential_user(group_id))?
            .set_secret(encoded)
            .map_err(|_| "pending_invitation_store_unavailable")
    }

    fn get_optional(&self, group_id: PeerId) -> Result<Option<Zeroizing<Vec<u8>>>, &'static str> {
        match protected_entry(&credential_user(group_id))?.get_secret() {
            Ok(encoded) => Ok(Some(Zeroizing::new(encoded))),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(_) => Err("pending_invitation_store_unavailable"),
        }
    }

    fn remove(&self, group_id: PeerId) -> Result<(), &'static str> {
        match protected_entry(&credential_user(group_id))?.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(_) => Err("pending_invitation_store_unavailable"),
        }
    }
}

impl JoinedDiscoveryStore for PlatformJoinedDiscoveryStore {
    fn put(&self, group_id: PeerId, key: &DiscoveryKey) -> Result<(), &'static str> {
        protected_entry(&discovery_credential_user(group_id))?
            .set_secret(key.as_bytes())
            .map_err(|_| "joined_discovery_store_unavailable")
    }

    fn get_optional(&self, group_id: PeerId) -> Result<Option<DiscoveryKey>, &'static str> {
        let bytes = match protected_entry(&discovery_credential_user(group_id))?.get_secret() {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(KeyringError::NoEntry) => return Ok(None),
            Err(_) => return Err("joined_discovery_store_unavailable"),
        };
        let bytes: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| "joined_discovery_record_invalid")?;
        Ok(Some(DiscoveryKey::from_bytes(bytes)))
    }

    fn remove(&self, group_id: PeerId) -> Result<(), &'static str> {
        match protected_entry(&discovery_credential_user(group_id))?.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(_) => Err("joined_discovery_store_unavailable"),
        }
    }
}

pub struct PendingInvitationService {
    operations: Arc<Mutex<()>>,
    metadata: Mutex<EventStore>,
    secrets: Box<dyn InvitationSecretStore>,
    discovery: Box<dyn JoinedDiscoveryStore>,
}

impl PendingInvitationService {
    pub fn open(path: impl AsRef<Path>, operations: Arc<Mutex<()>>) -> Result<Self, &'static str> {
        Ok(Self {
            operations,
            metadata: Mutex::new(
                EventStore::open(path).map_err(|_| "pending_invitation_store_unavailable")?,
            ),
            secrets: Box::new(PlatformInvitationSecretStore),
            discovery: Box::new(PlatformJoinedDiscoveryStore),
        })
    }

    pub fn accept(&self, input: &str) -> Result<PendingGroup, &'static str> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system_clock_invalid")?
            .as_secs();
        self.accept_at(input, now_unix)
    }

    pub(crate) fn inspect(&self) -> Result<(Vec<PendingGroup>, Vec<PeerId>), &'static str> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system_clock_invalid")?
            .as_secs();
        self.inspect_at(now_unix)
    }

    pub fn joined(&self) -> Result<Vec<JoinedGroup>, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "pending_invitation_service_unavailable")?;
        let groups = self
            .metadata
            .lock()
            .map_err(|_| "pending_invitation_service_unavailable")?
            .joined_groups()
            .map_err(|_| "pending_invitation_store_unavailable")?;
        for group in &groups {
            if self.discovery.get_optional(group.group_id)?.is_none() {
                if let Some(encoded) = self.secrets.get_optional(group.group_id)? {
                    let invitation = decode_stored_invitation(&encoded, 0)?;
                    if !joined_metadata_matches_invitation(group, &invitation) {
                        return Err("pending_invitation_record_invalid");
                    }
                    self.discovery
                        .put(group.group_id, &DiscoveryKey::from_invitation(&invitation))?;
                }
            }
            self.secrets.remove(group.group_id)?;
        }
        Ok(groups.into_iter().map(JoinedGroup::from_metadata).collect())
    }

    pub fn cancel(&self, group_id: PeerId) -> Result<(), &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "pending_invitation_service_unavailable")?;
        let mut metadata = self
            .metadata
            .lock()
            .map_err(|_| "pending_invitation_service_unavailable")?;
        let exists = metadata
            .pending_invitations()
            .map_err(|_| "pending_invitation_store_unavailable")?
            .iter()
            .any(|pending| pending.group_id == group_id);
        if !exists {
            return Err("pending_invitation_not_found");
        }
        self.secrets.remove(group_id)?;
        if !metadata
            .remove_pending_invitation(group_id)
            .map_err(|_| "pending_invitation_store_unavailable")?
        {
            return Err("pending_invitation_not_found");
        }
        Ok(())
    }

    pub(crate) fn ensure_pending(&self, group_id: PeerId) -> Result<(), &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "pending_invitation_service_unavailable")?;
        let exists = self
            .metadata
            .lock()
            .map_err(|_| "pending_invitation_service_unavailable")?
            .pending_invitations()
            .map_err(|_| "pending_invitation_store_unavailable")?
            .iter()
            .any(|pending| pending.group_id == group_id);
        exists.then_some(()).ok_or("pending_invitation_not_found")
    }

    pub(crate) fn complete_join(&self, group_id: PeerId) -> Result<JoinedGroup, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "pending_invitation_service_unavailable")?;
        let mut metadata = self
            .metadata
            .lock()
            .map_err(|_| "pending_invitation_service_unavailable")?;
        if let Some(joined) = metadata
            .joined_groups()
            .map_err(|_| "pending_invitation_store_unavailable")?
            .into_iter()
            .find(|joined| joined.group_id == group_id)
        {
            if self.discovery.get_optional(group_id)?.is_none() {
                if let Some(encoded) = self.secrets.get_optional(group_id)? {
                    let invitation = decode_stored_invitation(&encoded, 0)?;
                    if invitation.group_id() != group_id {
                        return Err("pending_invitation_record_invalid");
                    }
                    self.discovery
                        .put(group_id, &DiscoveryKey::from_invitation(&invitation))?;
                }
            }
            self.secrets.remove(group_id)?;
            return Ok(JoinedGroup::from_metadata(joined));
        }
        let stored = metadata
            .pending_invitations()
            .map_err(|_| "pending_invitation_store_unavailable")?
            .into_iter()
            .find(|pending| pending.group_id == group_id)
            .ok_or("pending_invitation_not_found")?;
        let encoded = self
            .secrets
            .get_optional(group_id)?
            .ok_or("pending_invitation_record_invalid")?;
        let invitation = decode_stored_invitation(&encoded, 0)?;
        if !metadata_matches_invitation(&stored, &invitation) {
            return Err("pending_invitation_record_invalid");
        }
        let previous_discovery = self.discovery.get_optional(group_id)?;
        self.discovery
            .put(group_id, &DiscoveryKey::from_invitation(&invitation))?;
        if metadata
            .promote_pending_invitation_to_joined_group(group_id, invitation.inviter_device_id())
            .is_err()
        {
            match previous_discovery {
                Some(previous) => self.discovery.put(group_id, &previous)?,
                None => self.discovery.remove(group_id)?,
            }
            return Err("pending_invitation_store_unavailable");
        }
        let joined = metadata
            .joined_groups()
            .map_err(|_| "pending_invitation_store_unavailable")?
            .into_iter()
            .find(|joined| joined.group_id == group_id)
            .ok_or("pending_invitation_store_unavailable")?;
        self.secrets.remove(group_id)?;
        Ok(JoinedGroup::from_metadata(joined))
    }

    pub(crate) fn load_invitation(&self, group_id: PeerId) -> Result<Invitation, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "pending_invitation_service_unavailable")?;
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system_clock_invalid")?
            .as_secs();
        let stored = self
            .metadata
            .lock()
            .map_err(|_| "pending_invitation_service_unavailable")?
            .pending_invitations()
            .map_err(|_| "pending_invitation_store_unavailable")?
            .into_iter()
            .find(|pending| pending.group_id == group_id)
            .ok_or("pending_invitation_not_found")?;
        let encoded = self
            .secrets
            .get_optional(group_id)?
            .ok_or("pending_invitation_record_invalid")?;
        let invitation = decode_stored_invitation(&encoded, now_unix)?;
        if !metadata_matches_invitation(&stored, &invitation) {
            return Err("pending_invitation_record_invalid");
        }
        Ok(invitation)
    }

    pub(crate) fn joined_sync_target(
        &self,
        group_id: PeerId,
    ) -> Result<(DiscoveryKey, PeerId), &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "pending_invitation_service_unavailable")?;
        let joined = self
            .metadata
            .lock()
            .map_err(|_| "pending_invitation_service_unavailable")?
            .joined_groups()
            .map_err(|_| "pending_invitation_store_unavailable")?
            .into_iter()
            .find(|joined| joined.group_id == group_id)
            .ok_or("joined_group_not_found")?;
        let discovery = self
            .discovery
            .get_optional(group_id)?
            .ok_or("joined_discovery_record_missing")?;
        Ok((discovery, joined.inviter_device_id))
    }

    #[cfg(test)]
    fn list_at(&self, now_unix: u64) -> Result<Vec<PendingGroup>, &'static str> {
        let (pending, expired) = self.inspect_at(now_unix)?;
        for group_id in expired {
            self.cancel(group_id)?;
        }
        Ok(pending)
    }

    fn inspect_at(
        &self,
        now_unix: u64,
    ) -> Result<(Vec<PendingGroup>, Vec<PeerId>), &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "pending_invitation_service_unavailable")?;
        let metadata = self
            .metadata
            .lock()
            .map_err(|_| "pending_invitation_service_unavailable")?
            .pending_invitations()
            .map_err(|_| "pending_invitation_store_unavailable")?;
        let mut pending = Vec::with_capacity(metadata.len());
        let mut expired = Vec::new();
        for stored in metadata {
            let encoded = self
                .secrets
                .get_optional(stored.group_id)?
                .ok_or("pending_invitation_record_invalid")?;
            let invitation = decode_stored_invitation(&encoded, 0)?;
            if !metadata_matches_invitation(&stored, &invitation) {
                return Err("pending_invitation_record_invalid");
            }
            if invitation.expires_at_unix() <= now_unix {
                expired.push(stored.group_id);
                continue;
            }
            pending.push(PendingGroup::from_metadata(
                stored,
                invitation.inviter_device_id(),
            ));
        }
        Ok((pending, expired))
    }

    fn accept_at(&self, input: &str, now_unix: u64) -> Result<PendingGroup, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "pending_invitation_service_unavailable")?;
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
        if self
            .metadata
            .lock()
            .map_err(|_| "pending_invitation_service_unavailable")?
            .joined_groups()
            .map_err(|_| "pending_invitation_store_unavailable")?
            .iter()
            .any(|joined| joined.group_id == metadata.group_id)
        {
            return Err("group_already_joined");
        }
        let previous = self.secrets.get_optional(metadata.group_id)?;
        self.secrets.put(metadata.group_id, encoded.as_bytes())?;
        let stored = self
            .metadata
            .lock()
            .map_err(|_| "pending_invitation_service_unavailable")?
            .put_pending_invitation(&metadata);
        if stored.is_err() {
            match previous {
                Some(previous) => self.secrets.put(metadata.group_id, previous.as_slice())?,
                None => self.secrets.remove(metadata.group_id)?,
            }
            return Err("pending_invitation_store_unavailable");
        }
        Ok(PendingGroup::from_metadata(
            metadata,
            invitation.inviter_device_id(),
        ))
    }
}

fn decode_stored_invitation(
    encoded: &Zeroizing<Vec<u8>>,
    now_unix: u64,
) -> Result<Invitation, &'static str> {
    if encoded.is_empty() || encoded.len() > MAX_PROTECTED_INVITATION_BYTES {
        return Err("pending_invitation_record_invalid");
    }
    let encoded =
        std::str::from_utf8(encoded.as_slice()).map_err(|_| "pending_invitation_record_invalid")?;
    Invitation::decode(encoded, now_unix).map_err(|_| "pending_invitation_record_invalid")
}

impl PendingGroup {
    fn from_metadata(metadata: PendingInvitationMetadata, inviter_device_id: PeerId) -> Self {
        Self {
            group_name: metadata.group_name,
            inviter_name: metadata.inviter_name,
            inviter_device_id: inviter_device_id.to_string(),
            group_id: metadata.group_id.to_string(),
            expires_at_unix: metadata.expires_at_unix,
            history_policy: history_policy_name(metadata.history_policy),
            reusable: metadata.reusable,
        }
    }
}

impl JoinedGroup {
    fn from_metadata(metadata: JoinedGroupMetadata) -> Self {
        Self {
            group_name: metadata.group_name,
            inviter_name: metadata.inviter_name,
            inviter_device_id: metadata.inviter_device_id.to_string(),
            group_id: metadata.group_id.to_string(),
            history_policy: history_policy_name(metadata.history_policy),
        }
    }
}

fn credential_user(group_id: PeerId) -> String {
    format!("{CREDENTIAL_PREFIX}{group_id}")
}

fn discovery_credential_user(group_id: PeerId) -> String {
    format!("{DISCOVERY_CREDENTIAL_PREFIX}{group_id}")
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

fn joined_metadata_matches_invitation(
    metadata: &JoinedGroupMetadata,
    invitation: &Invitation,
) -> bool {
    metadata.group_id == invitation.group_id()
        && metadata.group_name == invitation.group_name()
        && metadata.inviter_name == invitation.inviter_name()
        && metadata.inviter_device_id == invitation.inviter_device_id()
        && metadata.history_policy == invitation.history_policy()
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use charp2p_core::{
        DeviceIdentity, GroupIdentity, HistoryPolicy, Invitation, InvitationSpec, PeerId,
    };
    use charp2p_store::EventStore;

    use super::{InvitationSecretStore, JoinedDiscoveryStore, PendingInvitationService};

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

        fn get_optional(
            &self,
            group_id: PeerId,
        ) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, &'static str> {
            Ok(self
                .saved
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find(|(stored_group, _)| *stored_group == group_id)
                .map(|(_, encoded)| zeroize::Zeroizing::new(encoded.clone())))
        }

        fn remove(&self, group_id: PeerId) -> Result<(), &'static str> {
            self.saved
                .lock()
                .unwrap()
                .retain(|(stored_group, _)| *stored_group != group_id);
            Ok(())
        }
    }

    #[derive(Default)]
    struct MemoryDiscoveryStore {
        saved: Mutex<Vec<(PeerId, charp2p_core::DiscoveryKey)>>,
    }

    impl JoinedDiscoveryStore for MemoryDiscoveryStore {
        fn put(
            &self,
            group_id: PeerId,
            key: &charp2p_core::DiscoveryKey,
        ) -> Result<(), &'static str> {
            self.saved.lock().unwrap().push((group_id, *key));
            Ok(())
        }

        fn get_optional(
            &self,
            group_id: PeerId,
        ) -> Result<Option<charp2p_core::DiscoveryKey>, &'static str> {
            Ok(self
                .saved
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find(|(stored_group, _)| *stored_group == group_id)
                .map(|(_, key)| *key))
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
            operations: Arc::new(Mutex::new(())),
            metadata: Mutex::new(EventStore::in_memory().unwrap()),
            secrets: Box::<MemorySecretStore>::default(),
            discovery: Box::<MemoryDiscoveryStore>::default(),
        }
    }

    fn invitation() -> (String, PeerId) {
        let owner = GroupIdentity::generate();
        let encoded = Invitation::issue(
            &owner,
            DeviceIdentity::generate().peer_id(),
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
    fn completed_join_moves_safe_metadata_and_removes_the_bearer() {
        let service = service();
        let (encoded, group_id) = invitation();
        let invitation = Invitation::decode(&encoded, NOW).unwrap();
        let expected_key = charp2p_core::DiscoveryKey::from_invitation(&invitation);
        let pending = service.accept_at(&encoded, NOW).unwrap();

        let joined = service.complete_join(group_id).unwrap();
        assert_eq!(joined.group_id, pending.group_id);
        assert_eq!(joined.group_name, pending.group_name);
        assert_eq!(joined.inviter_device_id, pending.inviter_device_id);
        assert!(service.list_at(NOW).unwrap().is_empty());
        assert_eq!(service.joined().unwrap(), vec![joined.clone()]);
        assert_eq!(service.complete_join(group_id).unwrap(), joined);
        assert!(service.secrets.get_optional(group_id).unwrap().is_none());
        assert_eq!(
            service.discovery.get_optional(group_id),
            Ok(Some(expected_key))
        );
        assert_eq!(
            service.joined_sync_target(group_id),
            Ok((expected_key, invitation.inviter_device_id()))
        );
        assert_eq!(
            service.accept_at(&encoded, NOW),
            Err("group_already_joined")
        );
    }

    #[test]
    fn cancellation_removes_pending_metadata_and_bearer() {
        let service = service();
        let (encoded, group_id) = invitation();
        service.accept_at(&encoded, NOW).unwrap();

        service.cancel(group_id).unwrap();

        assert!(service.list_at(NOW).unwrap().is_empty());
        assert!(service.secrets.get_optional(group_id).unwrap().is_none());
        assert_eq!(service.cancel(group_id), Err("pending_invitation_not_found"));
    }

    #[test]
    fn joined_listing_recovers_discovery_before_interrupted_bearer_cleanup() {
        let service = service();
        let (encoded, group_id) = invitation();
        let invitation = Invitation::decode(&encoded, NOW).unwrap();
        let expected_key = charp2p_core::DiscoveryKey::from_invitation(&invitation);
        service.accept_at(&encoded, NOW).unwrap();
        service
            .metadata
            .lock()
            .unwrap()
            .promote_pending_invitation_to_joined_group(group_id, invitation.inviter_device_id())
            .unwrap();

        assert_eq!(service.discovery.get_optional(group_id), Ok(None));
        assert_eq!(service.joined().unwrap().len(), 1);
        assert_eq!(
            service.discovery.get_optional(group_id),
            Ok(Some(expected_key))
        );
        assert!(service.secrets.get_optional(group_id).unwrap().is_none());
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
    fn oversized_protected_invitation_is_rejected_before_decoding() {
        let service = service();
        let (encoded, group_id) = invitation();
        service.accept_at(&encoded, NOW).unwrap();
        service
            .secrets
            .put(
                group_id,
                &vec![b'A'; super::MAX_PROTECTED_INVITATION_BYTES + 1],
            )
            .unwrap();

        assert_eq!(
            service.list_at(NOW),
            Err("pending_invitation_record_invalid")
        );
    }

    #[test]
    fn expired_invitation_is_removed_from_both_stores() {
        let service = service();
        let (encoded, group_id) = invitation();
        service.accept_at(&encoded, NOW).unwrap();

        let (active, expired) = service.inspect_at(NOW + 3_600).unwrap();
        assert!(active.is_empty());
        assert_eq!(expired, vec![group_id]);
        assert!(service.secrets.get_optional(group_id).unwrap().is_some());
        assert_eq!(
            service
                .metadata
                .lock()
                .unwrap()
                .pending_invitations()
                .unwrap()
                .len(),
            1
        );

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
