use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use charp2p_core::{
    GroupIdentity, GroupIdentitySecret, HistoryPolicy, Invitation, InvitationId, InvitationSpec,
    JoinRequest, PeerId,
};
use charp2p_store::{EventStore, IssuedInvitationMetadata, LocalGroupMetadata};
use keyring_core::Error as KeyringError;
use serde::Serialize;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::identity::protected_entry;
use crate::network::{JoinRequestAuthorization, JoinRequestAuthorizer};

const CREDENTIAL_PREFIX: &str = "group-identity-v1-";
const INVITATION_CREDENTIAL_PREFIX: &str = "issued-invitation-v1-";
const MAX_GROUP_NAME_CHARS: usize = 80;
const MAX_GROUP_NAME_BYTES: usize = 80;
const MAX_GROUP_SECRET_BYTES: usize = 512;
const MAX_PROTECTED_INVITATION_BYTES: usize = 2 * 1024;
const ALLOWED_INVITATION_LIFETIMES: [u64; 4] = [86_400, 604_800, 1_209_600, 2_592_000];

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalGroup {
    pub group_id: String,
    pub group_name: String,
    pub icon: u8,
    pub history_policy: &'static str,
    pub approval_required: bool,
    pub invitation_lifetime_seconds: u64,
    pub reusable_invitation: bool,
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuedInvitation {
    pub invitation_id: String,
    pub group_id: String,
    pub link: String,
    pub expires_at_unix: u64,
    pub reusable: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizedJoinInvitation {
    invitation_id: InvitationId,
    group_id: PeerId,
    reusable: bool,
}

impl AuthorizedJoinInvitation {
    pub fn invitation_id(self) -> InvitationId {
        self.invitation_id
    }

    pub fn group_id(self) -> PeerId {
        self.group_id
    }

    pub fn is_reusable(self) -> bool {
        self.reusable
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JoinInvitationAuthorizationError {
    Unauthorized,
    Unavailable,
}

pub struct CreateGroupSpec<'a> {
    pub group_name: &'a str,
    pub icon: u8,
    pub history_policy: &'a str,
    pub approval_required: bool,
    pub invitation_lifetime_seconds: u64,
    pub reusable_invitation: bool,
}

trait GroupSecretStore: Send + Sync {
    fn put(&self, group_id: PeerId, secret: &[u8]) -> Result<(), &'static str>;
    fn get(&self, group_id: PeerId) -> Result<GroupIdentitySecret, &'static str>;
    fn remove(&self, group_id: PeerId) -> Result<(), &'static str>;
}

trait IssuedInvitationSecretStore: Send + Sync {
    fn put(&self, invitation_id: InvitationId, encoded: &[u8]) -> Result<(), &'static str>;
    fn get_optional(
        &self,
        invitation_id: InvitationId,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, &'static str>;
    fn remove(&self, invitation_id: InvitationId) -> Result<(), &'static str>;
}

struct PlatformGroupSecretStore;
struct PlatformIssuedInvitationSecretStore;

impl GroupSecretStore for PlatformGroupSecretStore {
    fn put(&self, group_id: PeerId, secret: &[u8]) -> Result<(), &'static str> {
        protected_entry(&credential_user(group_id))?
            .set_secret(secret)
            .map_err(|_| "group_identity_store_unavailable")
    }

    fn get(&self, group_id: PeerId) -> Result<GroupIdentitySecret, &'static str> {
        let encoded = match protected_entry(&credential_user(group_id))?.get_secret() {
            Ok(encoded) => encoded,
            Err(KeyringError::NoEntry) => return Err("group_identity_missing"),
            Err(_) => return Err("group_identity_store_unavailable"),
        };
        let encoded = Zeroizing::new(encoded);
        if encoded.is_empty() || encoded.len() > MAX_GROUP_SECRET_BYTES {
            return Err("group_identity_record_invalid");
        }
        Ok(GroupIdentitySecret::from_protected_zeroizing(encoded))
    }

    fn remove(&self, group_id: PeerId) -> Result<(), &'static str> {
        match protected_entry(&credential_user(group_id))?.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(_) => Err("group_identity_store_unavailable"),
        }
    }
}

impl IssuedInvitationSecretStore for PlatformIssuedInvitationSecretStore {
    fn put(&self, invitation_id: InvitationId, encoded: &[u8]) -> Result<(), &'static str> {
        protected_entry(&invitation_credential_user(invitation_id))?
            .set_secret(encoded)
            .map_err(|_| "issued_invitation_store_unavailable")
    }

    fn get_optional(
        &self,
        invitation_id: InvitationId,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, &'static str> {
        match protected_entry(&invitation_credential_user(invitation_id))?.get_secret() {
            Ok(encoded) => Ok(Some(Zeroizing::new(encoded))),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(_) => Err("issued_invitation_store_unavailable"),
        }
    }

    fn remove(&self, invitation_id: InvitationId) -> Result<(), &'static str> {
        match protected_entry(&invitation_credential_user(invitation_id))?.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(_) => Err("issued_invitation_store_unavailable"),
        }
    }
}

pub struct GroupService {
    operations: Arc<Mutex<()>>,
    metadata: Mutex<EventStore>,
    secrets: Box<dyn GroupSecretStore>,
    invitation_secrets: Box<dyn IssuedInvitationSecretStore>,
}

impl GroupService {
    pub fn open(path: impl AsRef<Path>, operations: Arc<Mutex<()>>) -> Result<Self, &'static str> {
        Ok(Self {
            operations,
            metadata: Mutex::new(EventStore::open(path).map_err(|_| "group_store_unavailable")?),
            secrets: Box::new(PlatformGroupSecretStore),
            invitation_secrets: Box::new(PlatformIssuedInvitationSecretStore),
        })
    }

    pub fn create(&self, spec: CreateGroupSpec<'_>) -> Result<LocalGroup, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "group_service_unavailable")?;
        let group_name = normalize_group_name(spec.group_name)?;
        if spec.icon > 4 {
            return Err("invalid_group_icon");
        }
        let history_policy = parse_history_policy(spec.history_policy)?;
        if history_policy != HistoryPolicy::None
            || spec.approval_required
            || !spec.reusable_invitation
        {
            return Err("group_option_unsupported");
        }
        if !ALLOWED_INVITATION_LIFETIMES.contains(&spec.invitation_lifetime_seconds) {
            return Err("invalid_invitation_lifetime");
        }
        let mut store = self
            .metadata
            .lock()
            .map_err(|_| "group_service_unavailable")?;
        if !store
            .local_groups()
            .map_err(|_| "group_store_unavailable")?
            .is_empty()
        {
            return Err("group_already_exists");
        }

        let (identity, secret) =
            GroupIdentity::generate_persistable().map_err(|_| "group_creation_failed")?;
        if secret.expose_for_protected_storage().len() > MAX_GROUP_SECRET_BYTES {
            return Err("group_creation_failed");
        }
        let metadata = LocalGroupMetadata {
            group_id: identity.group_id(),
            group_name,
            icon: spec.icon,
            history_policy,
            approval_required: spec.approval_required,
            invitation_lifetime_seconds: spec.invitation_lifetime_seconds,
            reusable_invitation: spec.reusable_invitation,
        };

        store
            .put_local_group(&metadata)
            .map_err(|_| "group_store_unavailable")?;
        if let Err(error) = self
            .secrets
            .put(metadata.group_id, secret.expose_for_protected_storage())
        {
            store
                .remove_local_group(metadata.group_id)
                .map_err(|_| "group_store_unavailable")?;
            return Err(error);
        }
        Ok(metadata.into())
    }

    pub(crate) fn rollback_created_group(&self, group_id: PeerId) -> Result<(), &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "group_service_unavailable")?;
        let mut store = self
            .metadata
            .lock()
            .map_err(|_| "group_service_unavailable")?;
        if !store
            .local_groups()
            .map_err(|_| "group_store_unavailable")?
            .iter()
            .any(|group| group.group_id == group_id)
        {
            return Err("group_not_found");
        }
        if store
            .issued_invitations()
            .map_err(|_| "group_store_unavailable")?
            .iter()
            .any(|invitation| invitation.group_id == group_id)
        {
            return Err("group_creation_rollback_unsafe");
        }
        self.secrets.remove(group_id)?;
        store
            .remove_local_group(group_id)
            .map(|_| ())
            .map_err(|_| "group_store_unavailable")
    }

    pub fn list(&self) -> Result<Vec<LocalGroup>, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "group_service_unavailable")?;
        let mut store = self
            .metadata
            .lock()
            .map_err(|_| "group_service_unavailable")?;
        let metadata = store
            .local_groups()
            .map_err(|_| "group_store_unavailable")?;
        let mut groups = Vec::with_capacity(metadata.len());
        for stored in metadata {
            let secret = match self.secrets.get(stored.group_id) {
                Ok(secret) => secret,
                Err("group_identity_missing") => {
                    store
                        .remove_local_group(stored.group_id)
                        .map_err(|_| "group_store_unavailable")?;
                    continue;
                }
                Err(error) => return Err(error),
            };
            if secret.expose_for_protected_storage().is_empty()
                || secret.expose_for_protected_storage().len() > MAX_GROUP_SECRET_BYTES
            {
                return Err("group_identity_record_invalid");
            }
            let identity = GroupIdentity::from_persisted_secret(&secret)
                .map_err(|_| "group_identity_record_invalid")?;
            if identity.group_id() != stored.group_id {
                return Err("group_identity_record_invalid");
            }
            groups.push(stored.into());
        }
        Ok(groups)
    }

    pub fn issue_invitation(
        &self,
        group_id: PeerId,
        inviter_device_id: PeerId,
        inviter_name: &str,
    ) -> Result<IssuedInvitation, &'static str> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system_clock_invalid")?
            .as_secs();
        self.issue_invitation_at(group_id, inviter_device_id, inviter_name, now_unix)
    }

    pub fn issued_invitations(&self) -> Result<Vec<IssuedInvitation>, &'static str> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system_clock_invalid")?
            .as_secs();
        self.issued_invitations_at(now_unix)
    }

    /// Revokes the active invitation for one locally owned group.
    ///
    /// The protected bearer is removed before its index so any interrupted
    /// operation fails closed during authorization.
    pub fn revoke_invitation(&self, group_id: PeerId) -> Result<(), &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "group_service_unavailable")?;
        let mut store = self
            .metadata
            .lock()
            .map_err(|_| "group_service_unavailable")?;
        let owns_group = store
            .local_groups()
            .map_err(|_| "group_store_unavailable")?
            .into_iter()
            .any(|group| group.group_id == group_id);
        if !owns_group {
            return Err("group_not_found");
        }
        let invitations = store
            .issued_invitations()
            .map_err(|_| "group_store_unavailable")?
            .into_iter()
            .filter(|invitation| invitation.group_id == group_id)
            .collect::<Vec<_>>();
        if invitations.is_empty() {
            return Err("issued_invitation_not_found");
        }
        for invitation in invitations {
            self.invitation_secrets.remove(invitation.invitation_id)?;
            store
                .remove_issued_invitation(invitation.invitation_id)
                .map_err(|_| "group_store_unavailable")?;
        }
        Ok(())
    }

    /// Verifies that an inbound bearer invitation is active and was issued by
    /// this owner. This does not consume single-use invitations; consumption
    /// requires the signed membership event that commits the new member.
    pub fn authorize_join_request(
        &self,
        request: &JoinRequest,
    ) -> Result<AuthorizedJoinInvitation, JoinInvitationAuthorizationError> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| JoinInvitationAuthorizationError::Unavailable)?
            .as_secs();
        self.authorize_join_request_at(request, now_unix)
    }

    fn authorize_join_request_at(
        &self,
        request: &JoinRequest,
        now_unix: u64,
    ) -> Result<AuthorizedJoinInvitation, JoinInvitationAuthorizationError> {
        use JoinInvitationAuthorizationError::{Unauthorized, Unavailable};

        let invitation = Invitation::decode(request.invitation(), now_unix)
            .map_err(|_| Unauthorized)?;
        if invitation.group_id() != request.group_id() {
            return Err(Unauthorized);
        }

        let _operation = self.operations.lock().map_err(|_| Unavailable)?;
        let store = self.metadata.lock().map_err(|_| Unavailable)?;
        let owns_group = store
            .local_groups()
            .map_err(|_| Unavailable)?
            .into_iter()
            .any(|group| group.group_id == invitation.group_id());
        if !owns_group {
            return Err(Unauthorized);
        }

        let group_secret = match self.secrets.get(invitation.group_id()) {
            Ok(secret) => secret,
            Err("group_identity_missing") => return Err(Unauthorized),
            Err(_) => return Err(Unavailable),
        };
        let group_identity =
            GroupIdentity::from_persisted_secret(&group_secret).map_err(|_| Unavailable)?;
        if group_identity.group_id() != invitation.group_id() {
            return Err(Unavailable);
        }

        let indexed = store
            .issued_invitations()
            .map_err(|_| Unavailable)?
            .into_iter()
            .find(|indexed| indexed.invitation_id == invitation.invitation_id())
            .ok_or(Unauthorized)?;
        if indexed.group_id != invitation.group_id()
            || indexed.expires_at_unix != invitation.expires_at_unix()
            || indexed.expires_at_unix <= now_unix
        {
            return Err(Unauthorized);
        }

        let encoded = self
            .invitation_secrets
            .get_optional(indexed.invitation_id)
            .map_err(|_| Unavailable)?
            .ok_or(Unauthorized)?;
        let (stored_invitation, stored_encoded) =
            decode_issued_invitation(&encoded).map_err(|_| Unavailable)?;
        if stored_invitation.invitation_id() != indexed.invitation_id
            || stored_invitation.group_id() != indexed.group_id
            || stored_invitation.expires_at_unix() != indexed.expires_at_unix
            || stored_invitation.is_reusable() != invitation.is_reusable()
        {
            return Err(Unavailable);
        }
        let presented = request.invitation().as_bytes();
        if presented.len() != stored_encoded.len()
            || !bool::from(presented.ct_eq(stored_encoded.as_bytes()))
        {
            return Err(Unauthorized);
        }

        Ok(AuthorizedJoinInvitation {
            invitation_id: indexed.invitation_id,
            group_id: indexed.group_id,
            reusable: stored_invitation.is_reusable(),
        })
    }

    fn issue_invitation_at(
        &self,
        group_id: PeerId,
        inviter_device_id: PeerId,
        inviter_name: &str,
        now_unix: u64,
    ) -> Result<IssuedInvitation, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "group_service_unavailable")?;
        let mut store = self
            .metadata
            .lock()
            .map_err(|_| "group_service_unavailable")?;
        let group = store
            .local_groups()
            .map_err(|_| "group_store_unavailable")?
            .into_iter()
            .find(|group| group.group_id == group_id)
            .ok_or("group_not_found")?;
        for existing in store
            .issued_invitations()
            .map_err(|_| "group_store_unavailable")?
            .into_iter()
            .filter(|invitation| invitation.group_id == group_id)
        {
            let Some(encoded) = self
                .invitation_secrets
                .get_optional(existing.invitation_id)?
            else {
                store
                    .remove_issued_invitation(existing.invitation_id)
                    .map_err(|_| "group_store_unavailable")?;
                continue;
            };
            let (invitation, _) = decode_issued_invitation(&encoded)?;
            if invitation.invitation_id() != existing.invitation_id
                || invitation.group_id() != existing.group_id
                || invitation.expires_at_unix() != existing.expires_at_unix
            {
                return Err("issued_invitation_record_invalid");
            }
            if invitation.expires_at_unix() > now_unix {
                return Err("invitation_already_exists");
            }
            self.invitation_secrets.remove(existing.invitation_id)?;
            store
                .remove_issued_invitation(existing.invitation_id)
                .map_err(|_| "group_store_unavailable")?;
        }
        let secret = self.secrets.get(group_id)?;
        let identity = GroupIdentity::from_persisted_secret(&secret)
            .map_err(|_| "group_identity_record_invalid")?;
        if identity.group_id() != group_id {
            return Err("group_identity_record_invalid");
        }
        let expires_at_unix = now_unix
            .checked_add(group.invitation_lifetime_seconds)
            .ok_or("system_clock_invalid")?;
        let invitation = Invitation::issue(
            &identity,
            inviter_device_id,
            InvitationSpec {
                group_name: &group.group_name,
                inviter_name,
                expires_at_unix,
                history_policy: group.history_policy,
                reusable: group.reusable_invitation,
            },
            now_unix,
        )
        .map_err(|_| "invitation_creation_failed")?;
        let encoded = Zeroizing::new(
            invitation
                .encode()
                .map_err(|_| "invitation_creation_failed")?,
        );
        if encoded.len() > MAX_PROTECTED_INVITATION_BYTES {
            return Err("invitation_creation_failed");
        }
        let indexed = IssuedInvitationMetadata {
            invitation_id: invitation.invitation_id(),
            group_id,
            expires_at_unix,
        };
        store
            .put_issued_invitation(&indexed)
            .map_err(|_| "group_store_unavailable")?;
        if let Err(error) = self
            .invitation_secrets
            .put(indexed.invitation_id, encoded.as_bytes())
        {
            store
                .remove_issued_invitation(indexed.invitation_id)
                .map_err(|_| "group_store_unavailable")?;
            return Err(error);
        }
        Ok(issued_invitation(&invitation, encoded.as_str()))
    }

    fn issued_invitations_at(&self, now_unix: u64) -> Result<Vec<IssuedInvitation>, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "group_service_unavailable")?;
        let mut store = self
            .metadata
            .lock()
            .map_err(|_| "group_service_unavailable")?;
        let indexed = store
            .issued_invitations()
            .map_err(|_| "group_store_unavailable")?;
        let local_group_ids: Vec<_> = store
            .local_groups()
            .map_err(|_| "group_store_unavailable")?
            .into_iter()
            .map(|group| group.group_id)
            .collect();
        let mut invitations = Vec::with_capacity(indexed.len());
        for indexed in indexed {
            if !local_group_ids.contains(&indexed.group_id) {
                self.invitation_secrets.remove(indexed.invitation_id)?;
                store
                    .remove_issued_invitation(indexed.invitation_id)
                    .map_err(|_| "group_store_unavailable")?;
                continue;
            }
            let group_secret = match self.secrets.get(indexed.group_id) {
                Ok(secret) => secret,
                Err("group_identity_missing") => {
                    self.invitation_secrets.remove(indexed.invitation_id)?;
                    store
                        .remove_issued_invitation(indexed.invitation_id)
                        .map_err(|_| "group_store_unavailable")?;
                    continue;
                }
                Err(error) => return Err(error),
            };
            let group_identity = GroupIdentity::from_persisted_secret(&group_secret)
                .map_err(|_| "group_identity_record_invalid")?;
            if group_identity.group_id() != indexed.group_id {
                return Err("issued_invitation_record_invalid");
            }
            let Some(encoded) = self
                .invitation_secrets
                .get_optional(indexed.invitation_id)?
            else {
                store
                    .remove_issued_invitation(indexed.invitation_id)
                    .map_err(|_| "group_store_unavailable")?;
                continue;
            };
            let (invitation, encoded) = decode_issued_invitation(&encoded)?;
            if invitation.invitation_id() != indexed.invitation_id
                || invitation.group_id() != indexed.group_id
                || invitation.expires_at_unix() != indexed.expires_at_unix
            {
                return Err("issued_invitation_record_invalid");
            }
            if indexed.expires_at_unix <= now_unix {
                self.invitation_secrets.remove(indexed.invitation_id)?;
                store
                    .remove_issued_invitation(indexed.invitation_id)
                    .map_err(|_| "group_store_unavailable")?;
                continue;
            }
            invitations.push(issued_invitation(&invitation, encoded));
        }
        Ok(invitations)
    }
}

impl JoinRequestAuthorizer for GroupService {
    fn authorize_join_request(&self, request: &JoinRequest) -> JoinRequestAuthorization {
        match GroupService::authorize_join_request(self, request) {
            Ok(_) => JoinRequestAuthorization::Authorized,
            Err(JoinInvitationAuthorizationError::Unauthorized) => {
                JoinRequestAuthorization::Unauthorized
            }
            Err(JoinInvitationAuthorizationError::Unavailable) => {
                JoinRequestAuthorization::Unavailable
            }
        }
    }
}

impl From<LocalGroupMetadata> for LocalGroup {
    fn from(metadata: LocalGroupMetadata) -> Self {
        Self {
            group_id: metadata.group_id.to_string(),
            group_name: metadata.group_name,
            icon: metadata.icon,
            history_policy: history_policy_name(metadata.history_policy),
            approval_required: metadata.approval_required,
            invitation_lifetime_seconds: metadata.invitation_lifetime_seconds,
            reusable_invitation: metadata.reusable_invitation,
        }
    }
}

fn credential_user(group_id: PeerId) -> String {
    format!("{CREDENTIAL_PREFIX}{group_id}")
}

fn invitation_credential_user(invitation_id: InvitationId) -> String {
    format!(
        "{INVITATION_CREDENTIAL_PREFIX}{}",
        encode_identifier(invitation_id)
    )
}

fn encode_identifier(invitation_id: InvitationId) -> String {
    invitation_id
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn decode_issued_invitation(
    encoded: &Zeroizing<Vec<u8>>,
) -> Result<(Invitation, &str), &'static str> {
    if encoded.is_empty() || encoded.len() > MAX_PROTECTED_INVITATION_BYTES {
        return Err("issued_invitation_record_invalid");
    }
    let encoded =
        std::str::from_utf8(encoded.as_slice()).map_err(|_| "issued_invitation_record_invalid")?;
    let invitation =
        Invitation::decode(encoded, 0).map_err(|_| "issued_invitation_record_invalid")?;
    Ok((invitation, encoded))
}

fn issued_invitation(invitation: &Invitation, encoded: &str) -> IssuedInvitation {
    IssuedInvitation {
        invitation_id: encode_identifier(invitation.invitation_id()),
        group_id: invitation.group_id().to_string(),
        link: format!("charp2p://join/{encoded}"),
        expires_at_unix: invitation.expires_at_unix(),
        reusable: invitation.is_reusable(),
    }
}

fn normalize_group_name(requested: &str) -> Result<String, &'static str> {
    let name = requested.trim();
    if name.is_empty()
        || name.chars().count() > MAX_GROUP_NAME_CHARS
        || name.len() > MAX_GROUP_NAME_BYTES
        || name.chars().any(char::is_control)
    {
        return Err("invalid_group_name");
    }
    Ok(name.to_owned())
}

fn parse_history_policy(value: &str) -> Result<HistoryPolicy, &'static str> {
    match value {
        "none" => Ok(HistoryPolicy::None),
        "fromInvitation" => Ok(HistoryPolicy::FromInvitation),
        "allRetained" => Ok(HistoryPolicy::AllRetained),
        _ => Err("invalid_history_policy"),
    }
}

fn history_policy_name(policy: HistoryPolicy) -> &'static str {
    match policy {
        HistoryPolicy::None => "none",
        HistoryPolicy::FromInvitation => "fromInvitation",
        HistoryPolicy::AllRetained => "allRetained",
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use charp2p_core::{
        DeviceIdentity, GroupIdentity, GroupIdentitySecret, HistoryPolicy, Invitation,
        InvitationId, InvitationSpec, JoinRequest, PeerId,
    };
    use charp2p_store::{EventStore, LocalGroupMetadata};

    use super::{
        CreateGroupSpec, GroupSecretStore, GroupService, IssuedInvitationSecretStore,
        JoinInvitationAuthorizationError,
    };
    use crate::network::{JoinRequestAuthorization, JoinRequestAuthorizer};

    #[derive(Default)]
    struct MemorySecretStore {
        saved: Mutex<Vec<(PeerId, Vec<u8>)>>,
    }

    struct FailingSecretStore;

    #[derive(Default)]
    struct MemoryInvitationStore {
        saved: Mutex<Vec<(InvitationId, Vec<u8>)>>,
    }

    impl GroupSecretStore for FailingSecretStore {
        fn put(&self, _group_id: PeerId, _secret: &[u8]) -> Result<(), &'static str> {
            Err("group_identity_store_unavailable")
        }

        fn get(&self, _group_id: PeerId) -> Result<GroupIdentitySecret, &'static str> {
            Err("group_identity_missing")
        }

        fn remove(&self, _group_id: PeerId) -> Result<(), &'static str> {
            Ok(())
        }
    }

    impl GroupSecretStore for MemorySecretStore {
        fn put(&self, group_id: PeerId, secret: &[u8]) -> Result<(), &'static str> {
            self.saved.lock().unwrap().push((group_id, secret.to_vec()));
            Ok(())
        }

        fn get(&self, group_id: PeerId) -> Result<GroupIdentitySecret, &'static str> {
            self.saved
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find(|(saved_id, _)| *saved_id == group_id)
                .map(|(_, secret)| GroupIdentitySecret::from_protected_bytes(secret.clone()))
                .ok_or("group_identity_missing")
        }

        fn remove(&self, group_id: PeerId) -> Result<(), &'static str> {
            self.saved
                .lock()
                .unwrap()
                .retain(|(saved_id, _)| *saved_id != group_id);
            Ok(())
        }
    }

    impl IssuedInvitationSecretStore for MemoryInvitationStore {
        fn put(&self, invitation_id: InvitationId, encoded: &[u8]) -> Result<(), &'static str> {
            self.saved
                .lock()
                .unwrap()
                .push((invitation_id, encoded.to_vec()));
            Ok(())
        }

        fn get_optional(
            &self,
            invitation_id: InvitationId,
        ) -> Result<Option<zeroize::Zeroizing<Vec<u8>>>, &'static str> {
            Ok(self
                .saved
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find(|(saved_id, _)| *saved_id == invitation_id)
                .map(|(_, encoded)| zeroize::Zeroizing::new(encoded.clone())))
        }

        fn remove(&self, invitation_id: InvitationId) -> Result<(), &'static str> {
            self.saved
                .lock()
                .unwrap()
                .retain(|(saved_id, _)| *saved_id != invitation_id);
            Ok(())
        }
    }

    fn service() -> GroupService {
        GroupService {
            operations: Arc::new(Mutex::new(())),
            metadata: Mutex::new(EventStore::in_memory().unwrap()),
            secrets: Box::new(MemorySecretStore::default()),
            invitation_secrets: Box::new(MemoryInvitationStore::default()),
        }
    }

    fn spec<'a>(name: &'a str) -> CreateGroupSpec<'a> {
        CreateGroupSpec {
            group_name: name,
            icon: 1,
            history_policy: "none",
            approval_required: false,
            invitation_lifetime_seconds: 604_800,
            reusable_invitation: true,
        }
    }

    fn join_request(link: &str, now_unix: u64) -> JoinRequest {
        let invitation = Invitation::decode_input(link, now_unix).unwrap();
        JoinRequest::from_invitation(&invitation, vec![1]).unwrap()
    }

    fn request_invitation_id(request: &JoinRequest, now_unix: u64) -> InvitationId {
        Invitation::decode(request.invitation(), now_unix)
            .unwrap()
            .invitation_id()
    }

    #[test]
    fn created_group_restores_with_the_same_protected_root() {
        let service = service();
        let created = service.create(spec(" Project Atlas ")).unwrap();
        let restored = service.list().unwrap();

        assert_eq!(restored, vec![created]);
        assert_eq!(restored[0].group_name, "Project Atlas");
        assert_eq!(
            service.create(spec("Hidden second group")).unwrap_err(),
            "group_already_exists"
        );
    }

    #[test]
    fn failed_follow_up_can_remove_a_new_group_and_its_root() {
        let service = service();
        let created = service.create(spec("Launch room")).unwrap();
        let group_id: PeerId = created.group_id.parse().unwrap();

        service.rollback_created_group(group_id).unwrap();

        assert!(service.list().unwrap().is_empty());
        assert!(matches!(
            service.secrets.get(group_id),
            Err("group_identity_missing")
        ));
    }

    #[test]
    fn issued_invitation_restores_and_expires_from_both_stores() {
        const NOW: u64 = 1_800_000_000;
        let service = service();
        let created = service.create(spec("Project Atlas")).unwrap();
        let group_id = created.group_id.parse().unwrap();

        let issued = service
            .issue_invitation_at(group_id, DeviceIdentity::generate().peer_id(), "Maya's PC", NOW)
            .unwrap();
        let decoded = Invitation::decode_input(&issued.link, NOW).unwrap();
        assert_eq!(decoded.group_id(), group_id);
        assert_eq!(decoded.group_name(), "Project Atlas");
        assert_eq!(decoded.inviter_name(), "Maya's PC");
        let restored = service.issued_invitations_at(NOW).unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].invitation_id, issued.invitation_id);
        assert_eq!(restored[0].group_id, issued.group_id);
        assert_eq!(restored[0].expires_at_unix, issued.expires_at_unix);
        assert_eq!(restored[0].reusable, issued.reusable);
        assert!(Invitation::decode_input(&restored[0].link, NOW).is_ok());
        assert!(matches!(
            service.issue_invitation_at(group_id, DeviceIdentity::generate().peer_id(), "Maya's PC", NOW + 1),
            Err("invitation_already_exists")
        ));

        assert!(service
            .issued_invitations_at(NOW + 604_800)
            .unwrap()
            .is_empty());
        assert!(service
            .metadata
            .lock()
            .unwrap()
            .issued_invitations()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn reusable_invitation_authorizes_repeatedly_until_expiry() {
        const NOW: u64 = 1_800_000_000;
        let service = service();
        let created = service.create(spec("Project Atlas")).unwrap();
        let group_id = created.group_id.parse().unwrap();
        let issued = service
            .issue_invitation_at(group_id, DeviceIdentity::generate().peer_id(), "Maya's PC", NOW)
            .unwrap();
        let request = join_request(&issued.link, NOW);

        let first = service.authorize_join_request_at(&request, NOW).unwrap();
        let second = service.authorize_join_request_at(&request, NOW).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.group_id(), group_id);
        assert_eq!(first.invitation_id(), request_invitation_id(&request, NOW));
        assert!(first.is_reusable());
        assert_eq!(
            JoinRequestAuthorizer::authorize_join_request(&service, &request),
            JoinRequestAuthorization::Authorized
        );
        assert_eq!(service.issued_invitations_at(NOW).unwrap().len(), 1);
    }

    #[test]
    fn revoked_invitation_is_removed_and_no_longer_authorizes_joining() {
        const NOW: u64 = 1_800_000_000;
        let service = service();
        let created = service.create(spec("Project Atlas")).unwrap();
        let group_id = created.group_id.parse().unwrap();
        let issued = service
            .issue_invitation_at(group_id, DeviceIdentity::generate().peer_id(), "Maya's PC", NOW)
            .unwrap();
        let request = join_request(&issued.link, NOW);
        let invitation_id = request_invitation_id(&request, NOW);
        assert!(service.authorize_join_request_at(&request, NOW).is_ok());

        service.revoke_invitation(group_id).unwrap();

        assert_eq!(
            service.authorize_join_request_at(&request, NOW),
            Err(JoinInvitationAuthorizationError::Unauthorized)
        );
        assert!(service.issued_invitations_at(NOW).unwrap().is_empty());
        assert!(service
            .invitation_secrets
            .get_optional(invitation_id)
            .unwrap()
            .is_none());
        assert_eq!(
            service.revoke_invitation(group_id),
            Err("issued_invitation_not_found")
        );
    }

    #[test]
    fn expired_or_foreign_invitation_is_not_authorized() {
        const NOW: u64 = 1_800_000_000;
        let service = service();
        let created = service.create(spec("Project Atlas")).unwrap();
        let group_id = created.group_id.parse().unwrap();
        let issued = service
            .issue_invitation_at(group_id, DeviceIdentity::generate().peer_id(), "Maya's PC", NOW)
            .unwrap();
        let request = join_request(&issued.link, NOW);
        assert_eq!(
            service.authorize_join_request_at(&request, NOW + 604_800),
            Err(JoinInvitationAuthorizationError::Unauthorized)
        );

        let foreign_identity = GroupIdentity::generate();
        let foreign_invitation = Invitation::issue(
            &foreign_identity,
            DeviceIdentity::generate().peer_id(),
            InvitationSpec {
                group_name: "Foreign",
                inviter_name: "Another owner",
                expires_at_unix: NOW + 600,
                history_policy: HistoryPolicy::None,
                reusable: true,
            },
            NOW,
        )
        .unwrap();
        let foreign_request =
            JoinRequest::from_invitation(&foreign_invitation, vec![1]).unwrap();
        assert_eq!(
            service.authorize_join_request_at(&foreign_request, NOW),
            Err(JoinInvitationAuthorizationError::Unauthorized)
        );
    }

    #[test]
    fn missing_or_corrupt_protected_invitation_fails_closed() {
        const NOW: u64 = 1_800_000_000;
        let service = service();
        let created = service.create(spec("Project Atlas")).unwrap();
        let group_id = created.group_id.parse().unwrap();
        let issued = service
            .issue_invitation_at(group_id, DeviceIdentity::generate().peer_id(), "Maya's PC", NOW)
            .unwrap();
        let request = join_request(&issued.link, NOW);
        let invitation_id = request_invitation_id(&request, NOW);

        service.invitation_secrets.remove(invitation_id).unwrap();
        assert_eq!(
            service.authorize_join_request_at(&request, NOW),
            Err(JoinInvitationAuthorizationError::Unauthorized)
        );

        service
            .invitation_secrets
            .put(invitation_id, b"not an invitation")
            .unwrap();
        assert_eq!(
            service.authorize_join_request_at(&request, NOW),
            Err(JoinInvitationAuthorizationError::Unavailable)
        );
    }

    #[test]
    fn issued_invitation_is_removed_when_local_group_metadata_is_missing() {
        const NOW: u64 = 1_800_000_000;
        let service = service();
        let created = service.create(spec("Project Atlas")).unwrap();
        let group_id = created.group_id.parse().unwrap();
        service
            .issue_invitation_at(group_id, DeviceIdentity::generate().peer_id(), "Maya's PC", NOW)
            .unwrap();
        service
            .metadata
            .lock()
            .unwrap()
            .remove_local_group(group_id)
            .unwrap();

        assert!(service.issued_invitations_at(NOW).unwrap().is_empty());
        assert!(service
            .metadata
            .lock()
            .unwrap()
            .issued_invitations()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn malformed_active_invitation_fails_closed_before_replacement() {
        const NOW: u64 = 1_800_000_000;
        let service = service();
        let created = service.create(spec("Project Atlas")).unwrap();
        let group_id = created.group_id.parse().unwrap();
        service
            .issue_invitation_at(group_id, DeviceIdentity::generate().peer_id(), "Maya's PC", NOW)
            .unwrap();
        let indexed = service
            .metadata
            .lock()
            .unwrap()
            .issued_invitations()
            .unwrap()
            .remove(0);
        service
            .invitation_secrets
            .put(indexed.invitation_id, b"not an invitation")
            .unwrap();

        assert!(matches!(
            service.issue_invitation_at(group_id, DeviceIdentity::generate().peer_id(), "Maya's PC", NOW + 1),
            Err("issued_invitation_record_invalid")
        ));
        assert_eq!(
            service
                .metadata
                .lock()
                .unwrap()
                .issued_invitations()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn invalid_group_defaults_are_rejected_before_key_creation() {
        let service = service();
        assert_eq!(
            service.create(spec("\n")).unwrap_err(),
            "invalid_group_name"
        );
        assert_eq!(
            service.create(spec(&"😀".repeat(21))).unwrap_err(),
            "invalid_group_name"
        );

        let mut invalid = spec("Atlas");
        invalid.invitation_lifetime_seconds = 42;
        assert_eq!(
            service.create(invalid).unwrap_err(),
            "invalid_invitation_lifetime"
        );
        assert!(service.list().unwrap().is_empty());
    }

    #[test]
    fn unimplemented_access_and_history_options_are_rejected() {
        let service = service();
        let mut unsupported_history = spec("Design Crew");
        unsupported_history.history_policy = "allRetained";
        assert!(matches!(
            service.create(unsupported_history),
            Err("group_option_unsupported")
        ));

        let mut approval = spec("Design Crew");
        approval.approval_required = true;
        assert!(matches!(
            service.create(approval),
            Err("group_option_unsupported")
        ));

        let mut single_use = spec("Design Crew");
        single_use.reusable_invitation = false;
        assert!(matches!(
            service.create(single_use),
            Err("group_option_unsupported")
        ));
    }

    #[test]
    fn mismatched_root_identity_is_rejected_on_load() {
        let service = service();
        let created = service.create(spec("Atlas")).unwrap();
        let wrong = GroupIdentity::generate_persistable().unwrap().1;
        service
            .secrets
            .put(
                created.group_id.parse().unwrap(),
                wrong.expose_for_protected_storage(),
            )
            .unwrap();

        assert_eq!(service.list().unwrap_err(), "group_identity_record_invalid");
    }

    #[test]
    fn failed_protected_write_rolls_back_sqlite_metadata() {
        let service = GroupService {
            operations: Arc::new(Mutex::new(())),
            metadata: Mutex::new(EventStore::in_memory().unwrap()),
            secrets: Box::new(FailingSecretStore),
            invitation_secrets: Box::new(MemoryInvitationStore::default()),
        };

        assert_eq!(
            service.create(spec("Atlas")).unwrap_err(),
            "group_identity_store_unavailable"
        );
        assert!(service
            .metadata
            .lock()
            .unwrap()
            .local_groups()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn incomplete_group_creation_is_removed_during_recovery() {
        let mut metadata = EventStore::in_memory().unwrap();
        metadata
            .put_local_group(&LocalGroupMetadata {
                group_id: GroupIdentity::generate().group_id(),
                group_name: "Interrupted".to_owned(),
                icon: 0,
                history_policy: HistoryPolicy::None,
                approval_required: false,
                invitation_lifetime_seconds: 604_800,
                reusable_invitation: false,
            })
            .unwrap();
        let service = GroupService {
            operations: Arc::new(Mutex::new(())),
            metadata: Mutex::new(metadata),
            secrets: Box::new(MemorySecretStore::default()),
            invitation_secrets: Box::new(MemoryInvitationStore::default()),
        };

        assert!(service.list().unwrap().is_empty());
        assert!(service
            .metadata
            .lock()
            .unwrap()
            .local_groups()
            .unwrap()
            .is_empty());
    }
}
