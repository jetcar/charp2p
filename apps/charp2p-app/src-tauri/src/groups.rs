use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use charp2p_core::{
    DeviceIdentity, DiscoveryKey, GroupIdentity, GroupIdentitySecret, HistoryPolicy, Invitation,
    InvitationId, InvitationSpec, InviteRejectReason, InviteRequest, InviteResponse, JoinRequest,
    JoinResponse, PeerId,
};
use charp2p_store::{
    ApprovalRequestOutcome, ApprovalState, EventStore, IssuedInvitationMetadata,
    LocalGroupMetadata, OwnerDiscoveryKeyMetadata,
};
use keyring_core::Error as KeyringError;
use libp2p::Multiaddr;
use serde::Serialize;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::identity::protected_entry;
use crate::mls_storage::{MemberAdmissionError, MlsProviderService};
use crate::network::{
    InviteRequestService, JoinRequestAuthorization, JoinRequestAuthorizer, MemberAdmissionService,
};

const CREDENTIAL_PREFIX: &str = "group-identity-v1-";
const INVITATION_CREDENTIAL_PREFIX: &str = "issued-invitation-v1-";
const OWNER_DISCOVERY_CREDENTIAL_PREFIX: &str = "owner-discovery-v1-";
const MAX_GROUP_NAME_CHARS: usize = 80;
const MAX_GROUP_NAME_BYTES: usize = 80;
const MAX_GROUP_SECRET_BYTES: usize = 512;
const MAX_PROTECTED_INVITATION_BYTES: usize = 2 * 1024;
const MAX_OWNER_DISCOVERY_KEYS: usize = 64;
/// Active invitations one owned group may hold at once (ADR-043).
const MAX_ACTIVE_INVITATIONS_PER_GROUP: usize = 16;
/// Upper bound on rendezvous keys advertised together for all owned groups.
pub const MAX_ADVERTISED_DISCOVERY_KEYS: usize = 256;
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

/// Owner-local join request for an approval-required group (ADR-041).
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalRequest {
    pub device_id: String,
    pub invitation_id: String,
    pub expires_at_unix: u64,
    pub first_requested_at_unix: u64,
    pub last_requested_at_unix: u64,
    pub state: &'static str,
}

/// Owner decision on one recorded approval request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalDecision {
    Approve,
    Decline,
    /// Clears a decline so the device's next request is recorded again.
    Allow,
}

#[derive(Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuedInvitation {
    pub invitation_id: String,
    pub group_id: String,
    pub link: String,
    pub expires_at_unix: u64,
    pub reusable: bool,
    /// Member device that asked the owner for this invitation (ADR-036), or
    /// `None` when the owner created it.
    pub requested_by: Option<String>,
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

trait OwnerDiscoveryKeyStore: Send + Sync {
    fn put(&self, invitation_id: InvitationId, key: DiscoveryKey) -> Result<(), &'static str>;
    fn get_optional(
        &self,
        invitation_id: InvitationId,
    ) -> Result<Option<DiscoveryKey>, &'static str>;
    fn remove(&self, invitation_id: InvitationId) -> Result<(), &'static str>;
}

struct PlatformGroupSecretStore;
struct PlatformIssuedInvitationSecretStore;
struct PlatformOwnerDiscoveryKeyStore;

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

impl OwnerDiscoveryKeyStore for PlatformOwnerDiscoveryKeyStore {
    fn put(&self, invitation_id: InvitationId, key: DiscoveryKey) -> Result<(), &'static str> {
        protected_entry(&owner_discovery_credential_user(invitation_id))?
            .set_secret(key.as_bytes())
            .map_err(|_| "owner_discovery_store_unavailable")
    }

    fn get_optional(
        &self,
        invitation_id: InvitationId,
    ) -> Result<Option<DiscoveryKey>, &'static str> {
        match protected_entry(&owner_discovery_credential_user(invitation_id))?.get_secret() {
            Ok(encoded) => {
                let encoded: [u8; 32] = encoded
                    .try_into()
                    .map_err(|_| "owner_discovery_record_invalid")?;
                Ok(Some(DiscoveryKey::from_bytes(encoded)))
            }
            Err(KeyringError::NoEntry) => Ok(None),
            Err(_) => Err("owner_discovery_store_unavailable"),
        }
    }

    fn remove(&self, invitation_id: InvitationId) -> Result<(), &'static str> {
        match protected_entry(&owner_discovery_credential_user(invitation_id))?.delete_credential()
        {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(_) => Err("owner_discovery_store_unavailable"),
        }
    }
}

pub struct GroupService {
    operations: Arc<Mutex<()>>,
    metadata: Mutex<EventStore>,
    secrets: Box<dyn GroupSecretStore>,
    invitation_secrets: Box<dyn IssuedInvitationSecretStore>,
    owner_discovery_keys: Box<dyn OwnerDiscoveryKeyStore>,
}

impl GroupService {
    pub fn open(path: impl AsRef<Path>, operations: Arc<Mutex<()>>) -> Result<Self, &'static str> {
        Ok(Self {
            operations,
            metadata: Mutex::new(EventStore::open(path).map_err(|_| "group_store_unavailable")?),
            secrets: Box::new(PlatformGroupSecretStore),
            invitation_secrets: Box::new(PlatformIssuedInvitationSecretStore),
            owner_discovery_keys: Box::new(PlatformOwnerDiscoveryKeyStore),
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
        if history_policy != HistoryPolicy::None {
            return Err("group_option_unsupported");
        }
        if !ALLOWED_INVITATION_LIFETIMES.contains(&spec.invitation_lifetime_seconds) {
            return Err("invalid_invitation_lifetime");
        }
        let mut store = self
            .metadata
            .lock()
            .map_err(|_| "group_service_unavailable")?;
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
                    self.remove_owner_discovery_keys(&mut store, stored.group_id)?;
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

    /// Changes the local icon of an owned group; members learn it from the
    /// owner's next metadata change.
    pub fn set_icon(&self, group_id: PeerId, icon: u8) -> Result<LocalGroup, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "group_service_unavailable")?;
        if icon > 4 {
            return Err("invalid_group_icon");
        }
        let mut store = self
            .metadata
            .lock()
            .map_err(|_| "group_service_unavailable")?;
        let mut metadata = store
            .local_groups()
            .map_err(|_| "group_store_unavailable")?
            .into_iter()
            .find(|group| group.group_id == group_id)
            .ok_or("group_not_owned")?;
        metadata.icon = icon;
        store
            .put_local_group(&metadata)
            .map_err(|_| "group_store_unavailable")?;
        Ok(metadata.into())
    }

    /// `address_hints` are the inviter device's current addresses, carried
    /// in the invitation as root-signed hints (ADR-037). `reusable` overrides
    /// the group's default reuse policy for this invitation (ADR-042), and
    /// `lifetime_seconds` selects a shorter expiry than the group's
    /// invitation lifetime.
    pub fn issue_invitation(
        &self,
        group_id: PeerId,
        inviter_device_id: PeerId,
        inviter_name: &str,
        reusable: Option<bool>,
        lifetime_seconds: Option<u64>,
        address_hints: &[Multiaddr],
    ) -> Result<IssuedInvitation, &'static str> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system_clock_invalid")?
            .as_secs();
        self.issue_requested_invitation_at(
            group_id,
            inviter_device_id,
            inviter_name,
            None,
            reusable,
            lifetime_seconds,
            address_hints,
            now_unix,
        )
        .map(|(invitation, encoded)| issued_invitation(&invitation, encoded.as_str(), None))
    }

    /// Answers a permitted member's invite request (ADR-036): the group must
    /// be owned here and `permitted` must confirm the authenticated peer's
    /// current membership and permission before an invitation is issued with
    /// this device pinned as inviter. Rejections are only `unauthorized` or
    /// `busy`.
    pub(crate) fn answer_invite_request(
        &self,
        owner_device_id: PeerId,
        inviter_name: &str,
        authenticated_peer: PeerId,
        request: &InviteRequest,
        address_hints: &[Multiaddr],
        permitted: impl FnOnce(PeerId, PeerId) -> Result<bool, &'static str>,
    ) -> InviteResponse {
        let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
            return InviteResponse::rejected(InviteRejectReason::Busy);
        };
        self.answer_invite_request_at(
            owner_device_id,
            inviter_name,
            authenticated_peer,
            request,
            address_hints,
            permitted,
            now.as_secs(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn answer_invite_request_at(
        &self,
        owner_device_id: PeerId,
        inviter_name: &str,
        authenticated_peer: PeerId,
        request: &InviteRequest,
        address_hints: &[Multiaddr],
        permitted: impl FnOnce(PeerId, PeerId) -> Result<bool, &'static str>,
        now_unix: u64,
    ) -> InviteResponse {
        let group_id = request.group_id();
        let owned = self
            .metadata
            .lock()
            .map_err(|_| ())
            .and_then(|store| store.local_groups().map_err(|_| ()))
            .map(|groups| groups.iter().any(|group| group.group_id == group_id));
        match owned {
            Ok(true) => {}
            Ok(false) => return InviteResponse::rejected(InviteRejectReason::Unauthorized),
            Err(()) => return InviteResponse::rejected(InviteRejectReason::Busy),
        }
        if authenticated_peer == owner_device_id {
            return InviteResponse::rejected(InviteRejectReason::Unauthorized);
        }
        match permitted(group_id, authenticated_peer) {
            Ok(true) => {}
            Ok(false) => return InviteResponse::rejected(InviteRejectReason::Unauthorized),
            Err(_) => return InviteResponse::rejected(InviteRejectReason::Busy),
        }
        match self.issue_requested_invitation_at(
            group_id,
            owner_device_id,
            inviter_name,
            Some((authenticated_peer, u64::from(request.lifetime_seconds()))),
            None,
            None,
            address_hints,
            now_unix,
        ) {
            Ok((invitation, _)) => InviteResponse::issued(&invitation)
                .unwrap_or_else(|_| InviteResponse::rejected(InviteRejectReason::Busy)),
            Err("group_not_found") => InviteResponse::rejected(InviteRejectReason::Unauthorized),
            Err(_) => InviteResponse::rejected(InviteRejectReason::Busy),
        }
    }

    pub fn issued_invitations(&self) -> Result<Vec<IssuedInvitation>, &'static str> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system_clock_invalid")?
            .as_secs();
        self.issued_invitations_at(now_unix)
    }

    /// Loads every rendezvous key retained for existing members of an owned group.
    pub fn owner_discovery_keys(
        &self,
        group_id: PeerId,
    ) -> Result<Vec<DiscoveryKey>, &'static str> {
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
            .into_iter()
            .any(|group| group.group_id == group_id)
        {
            return Err("group_not_found");
        }
        let indexed = store
            .owner_discovery_keys(group_id)
            .map_err(|_| "group_store_unavailable")?;
        if indexed.len() > MAX_OWNER_DISCOVERY_KEYS {
            return Err("owner_discovery_record_invalid");
        }
        let mut keys = Vec::with_capacity(indexed.len());
        for metadata in indexed {
            match self
                .owner_discovery_keys
                .get_optional(metadata.invitation_id)?
            {
                Some(key) => keys.push(key),
                None => {
                    store
                        .remove_owner_discovery_key(metadata.invitation_id)
                        .map_err(|_| "group_store_unavailable")?;
                }
            }
        }
        Ok(keys)
    }

    /// Loads the retained rendezvous keys of every locally owned group so one
    /// background advertisement keeps all of them discoverable.
    pub fn all_owner_discovery_keys(&self) -> Result<Vec<DiscoveryKey>, &'static str> {
        let group_ids = {
            let _operation = self
                .operations
                .lock()
                .map_err(|_| "group_service_unavailable")?;
            self.metadata
                .lock()
                .map_err(|_| "group_service_unavailable")?
                .local_groups()
                .map_err(|_| "group_store_unavailable")?
                .into_iter()
                .map(|group| group.group_id)
                .collect::<Vec<_>>()
        };
        let mut keys = Vec::new();
        for group_id in group_ids {
            match self.owner_discovery_keys(group_id) {
                Ok(group_keys) => keys.extend(group_keys),
                Err("group_not_found") => continue,
                Err(error) => return Err(error),
            }
        }
        if keys.len() > MAX_ADVERTISED_DISCOVERY_KEYS {
            return Err("owner_discovery_record_invalid");
        }
        Ok(keys)
    }

    /// Revokes one active invitation of a locally owned group; the group's
    /// other invitations stay active (ADR-043).
    ///
    /// The protected bearer is removed before its index so any interrupted
    /// operation fails closed during authorization.
    pub fn revoke_invitation(
        &self,
        group_id: PeerId,
        invitation_id: InvitationId,
    ) -> Result<(), &'static str> {
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
            .filter(|invitation| {
                invitation.group_id == group_id && invitation.invitation_id == invitation_id
            })
            .collect::<Vec<_>>();
        if invitations.is_empty() {
            return Err("issued_invitation_not_found");
        }
        self.remove_invitations(&mut store, invitations)
    }

    /// Reports whether the owner recorded the consumption of a single-use
    /// invitation of this group (ADR-042).
    pub fn single_use_invitation_consumed(
        &self,
        group_id: PeerId,
        invitation_id: InvitationId,
    ) -> Result<bool, &'static str> {
        Ok(self
            .metadata
            .lock()
            .map_err(|_| "group_service_unavailable")?
            .single_use_invitation_consumer(group_id, invitation_id)
            .map_err(|_| "group_store_unavailable")?
            .is_some())
    }

    /// Retires a single-use invitation after the owner recorded its
    /// consumption: it is no longer advertised and its protected bearer
    /// record and index are removed as for revocation, while the consumption
    /// record stays (ADR-042). Does nothing for an unconsumed or already
    /// retired invitation, so it is safe to repeat after an interruption.
    pub fn retire_consumed_invitation(
        &self,
        group_id: PeerId,
        invitation_id: InvitationId,
    ) -> Result<bool, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "group_service_unavailable")?;
        let mut store = self
            .metadata
            .lock()
            .map_err(|_| "group_service_unavailable")?;
        if store
            .single_use_invitation_consumer(group_id, invitation_id)
            .map_err(|_| "group_store_unavailable")?
            .is_none()
        {
            return Ok(false);
        }
        let invitations = store
            .issued_invitations()
            .map_err(|_| "group_store_unavailable")?
            .into_iter()
            .filter(|invitation| {
                invitation.group_id == group_id && invitation.invitation_id == invitation_id
            })
            .collect::<Vec<_>>();
        if invitations.is_empty() {
            return Ok(false);
        }
        self.remove_invitations(&mut store, invitations)?;
        Ok(true)
    }

    /// Revokes the invitations a member device requested from a locally owned
    /// group, after its invite permission is withdrawn or it is removed
    /// (ADR-036). Returns how many invitations were revoked.
    pub fn revoke_requested_invitations(
        &self,
        group_id: PeerId,
        requester: PeerId,
    ) -> Result<usize, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "group_service_unavailable")?;
        let mut store = self
            .metadata
            .lock()
            .map_err(|_| "group_service_unavailable")?;
        let invitations = store
            .issued_invitations()
            .map_err(|_| "group_store_unavailable")?
            .into_iter()
            .filter(|invitation| {
                invitation.group_id == group_id && invitation.requested_by == Some(requester)
            })
            .collect::<Vec<_>>();
        let revoked = invitations.len();
        self.remove_invitations(&mut store, invitations)?;
        Ok(revoked)
    }

    fn remove_invitations(
        &self,
        store: &mut EventStore,
        invitations: Vec<IssuedInvitationMetadata>,
    ) -> Result<(), &'static str> {
        for invitation in invitations {
            if let Some(encoded) = self
                .invitation_secrets
                .get_optional(invitation.invitation_id)?
            {
                let (decoded, _) = decode_issued_invitation(&encoded)?;
                if decoded.invitation_id() != invitation.invitation_id
                    || decoded.group_id() != invitation.group_id
                    || decoded.expires_at_unix() != invitation.expires_at_unix
                {
                    return Err("issued_invitation_record_invalid");
                }
                self.retain_owner_discovery_key(store, &decoded)?;
            }
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

        let invitation =
            Invitation::decode(request.invitation(), now_unix).map_err(|_| Unauthorized)?;
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

        let Some(indexed) = store
            .issued_invitations()
            .map_err(|_| Unavailable)?
            .into_iter()
            .find(|indexed| indexed.invitation_id == invitation.invitation_id())
        else {
            // A consumed single-use invitation is retired like a revoked one,
            // but its group-signed bearer still reaches admission so the
            // consuming device's exact retry is answered from its cached
            // response; admission refuses every other device (ADR-042).
            let consumed = !invitation.is_reusable()
                && store
                    .single_use_invitation_consumer(
                        invitation.group_id(),
                        invitation.invitation_id(),
                    )
                    .map_err(|_| Unavailable)?
                    .is_some();
            return if consumed {
                Ok(AuthorizedJoinInvitation {
                    invitation_id: invitation.invitation_id(),
                    group_id: invitation.group_id(),
                    reusable: false,
                })
            } else {
                Err(Unauthorized)
            };
        };
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

    /// Checks owner approval for an authorized join request (ADR-041).
    /// Groups created without approval admit directly; otherwise the request
    /// is recorded and only devices the owner approved proceed.
    pub(crate) fn admission_approval(
        &self,
        request: &JoinRequest,
        device_id: PeerId,
    ) -> Result<(), MemberAdmissionError> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| MemberAdmissionError::Unavailable)?
            .as_secs();
        self.admission_approval_at(request, device_id, now_unix)
    }

    fn admission_approval_at(
        &self,
        request: &JoinRequest,
        device_id: PeerId,
        now_unix: u64,
    ) -> Result<(), MemberAdmissionError> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| MemberAdmissionError::Unavailable)?;
        let mut store = self
            .metadata
            .lock()
            .map_err(|_| MemberAdmissionError::Unavailable)?;
        let group = store
            .local_groups()
            .map_err(|_| MemberAdmissionError::Unavailable)?
            .into_iter()
            .find(|group| group.group_id == request.group_id())
            .ok_or(MemberAdmissionError::Unauthorized)?;
        if !group.approval_required {
            return Ok(());
        }
        let invitation = Invitation::decode(request.invitation(), now_unix)
            .map_err(|_| MemberAdmissionError::Unauthorized)?;
        if invitation.group_id() != group.group_id {
            return Err(MemberAdmissionError::Unauthorized);
        }
        match store
            .record_owner_approval_request(
                group.group_id,
                device_id,
                invitation.invitation_id(),
                invitation.expires_at_unix(),
                now_unix,
            )
            .map_err(|_| MemberAdmissionError::Unavailable)?
        {
            ApprovalRequestOutcome::Approved => Ok(()),
            ApprovalRequestOutcome::Pending => Err(MemberAdmissionError::AwaitingApproval),
            ApprovalRequestOutcome::Declined => Err(MemberAdmissionError::Unauthorized),
            ApprovalRequestOutcome::Full => Err(MemberAdmissionError::Unavailable),
        }
    }

    /// Lists unexpired join requests and declined devices for a locally
    /// owned approval-required group, oldest request first.
    pub fn approval_requests(
        &self,
        group_id: PeerId,
    ) -> Result<Vec<ApprovalRequest>, &'static str> {
        self.approval_requests_at(group_id, unix_now()?)
    }

    fn approval_requests_at(
        &self,
        group_id: PeerId,
        now_unix: u64,
    ) -> Result<Vec<ApprovalRequest>, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "group_service_unavailable")?;
        let store = self
            .metadata
            .lock()
            .map_err(|_| "group_service_unavailable")?;
        owned_approval_requests(&store, group_id, now_unix)
    }

    /// Applies the owner's decision to a recorded request and returns the
    /// updated list. Approval admits the device on its next retry.
    pub fn decide_approval_request(
        &self,
        group_id: PeerId,
        device_id: PeerId,
        decision: ApprovalDecision,
    ) -> Result<Vec<ApprovalRequest>, &'static str> {
        self.decide_approval_request_at(group_id, device_id, decision, unix_now()?)
    }

    fn decide_approval_request_at(
        &self,
        group_id: PeerId,
        device_id: PeerId,
        decision: ApprovalDecision,
        now_unix: u64,
    ) -> Result<Vec<ApprovalRequest>, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "group_service_unavailable")?;
        let mut store = self
            .metadata
            .lock()
            .map_err(|_| "group_service_unavailable")?;
        // Checks ownership and approval before changing any record.
        owned_approval_requests(&store, group_id, now_unix)?;
        let changed = match decision {
            ApprovalDecision::Approve => store.approve_owner_approval_request(group_id, device_id),
            ApprovalDecision::Decline => store.decline_owner_approval_request(group_id, device_id),
            ApprovalDecision::Allow => store.clear_declined_approval_request(group_id, device_id),
        }
        .map_err(|_| "group_store_unavailable")?;
        if !changed {
            return Err("approval_request_not_found");
        }
        owned_approval_requests(&store, group_id, now_unix)
    }

    #[cfg(test)]
    fn issue_invitation_at(
        &self,
        group_id: PeerId,
        inviter_device_id: PeerId,
        inviter_name: &str,
        now_unix: u64,
    ) -> Result<IssuedInvitation, &'static str> {
        self.issue_reuse_invitation_at(group_id, inviter_device_id, inviter_name, None, now_unix)
    }

    #[cfg(test)]
    fn issue_reuse_invitation_at(
        &self,
        group_id: PeerId,
        inviter_device_id: PeerId,
        inviter_name: &str,
        reusable: Option<bool>,
        now_unix: u64,
    ) -> Result<IssuedInvitation, &'static str> {
        self.issue_requested_invitation_at(
            group_id,
            inviter_device_id,
            inviter_name,
            None,
            reusable,
            None,
            &[],
            now_unix,
        )
        .map(|(invitation, encoded)| issued_invitation(&invitation, encoded.as_str(), None))
    }

    /// Issues an invitation, recording the member device that requested it
    /// so withdrawing that member's permission can revoke it (ADR-036). A
    /// member request may only shorten the group's invitation lifetime, and
    /// a repeated request from the same member returns its still-active
    /// invitation instead of issuing another. Other active invitations of the
    /// group stay valid, up to a per-group bound (ADR-043). Member requests always use the group's
    /// default reuse policy; only the owner may override it or select a
    /// shorter allowed lifetime. Address hints are dropped when they
    /// would make the invitation invalid or too large to protect, since they
    /// are only an optimization.
    #[allow(clippy::too_many_arguments)]
    fn issue_requested_invitation_at(
        &self,
        group_id: PeerId,
        inviter_device_id: PeerId,
        inviter_name: &str,
        requested: Option<(PeerId, u64)>,
        reusable: Option<bool>,
        lifetime_seconds: Option<u64>,
        address_hints: &[Multiaddr],
        now_unix: u64,
    ) -> Result<(Invitation, Zeroizing<String>), &'static str> {
        if let Some(lifetime) = lifetime_seconds {
            if requested.is_some() || !ALLOWED_INVITATION_LIFETIMES.contains(&lifetime) {
                return Err("invalid_invitation_lifetime");
            }
        }
        let requested_by = requested.map(|(requester, _)| requester);
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
        if lifetime_seconds.is_some_and(|lifetime| lifetime > group.invitation_lifetime_seconds) {
            return Err("invalid_invitation_lifetime");
        }
        let mut active = 0;
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
            self.retain_owner_discovery_key(&mut store, &invitation)?;
            if invitation.expires_at_unix() > now_unix {
                if requested_by.is_some() && existing.requested_by == requested_by {
                    let encoded = Zeroizing::new(
                        invitation
                            .encode()
                            .map_err(|_| "issued_invitation_record_invalid")?,
                    );
                    return Ok((invitation, encoded));
                }
                active += 1;
                continue;
            }
            self.invitation_secrets.remove(existing.invitation_id)?;
            store
                .remove_issued_invitation(existing.invitation_id)
                .map_err(|_| "group_store_unavailable")?;
        }
        if active >= MAX_ACTIVE_INVITATIONS_PER_GROUP {
            return Err("invitation_limit_reached");
        }
        if store
            .owner_discovery_keys(group_id)
            .map_err(|_| "group_store_unavailable")?
            .len()
            >= MAX_OWNER_DISCOVERY_KEYS
        {
            return Err("owner_discovery_limit_reached");
        }
        let mut advertised_keys = 0;
        for owned in store
            .local_groups()
            .map_err(|_| "group_store_unavailable")?
        {
            advertised_keys += store
                .owner_discovery_keys(owned.group_id)
                .map_err(|_| "group_store_unavailable")?
                .len();
        }
        if advertised_keys >= MAX_ADVERTISED_DISCOVERY_KEYS {
            return Err("advertised_discovery_limit_reached");
        }
        let secret = self.secrets.get(group_id)?;
        let identity = GroupIdentity::from_persisted_secret(&secret)
            .map_err(|_| "group_identity_record_invalid")?;
        if identity.group_id() != group_id {
            return Err("group_identity_record_invalid");
        }
        let lifetime_seconds = requested.map_or(
            lifetime_seconds.unwrap_or(group.invitation_lifetime_seconds),
            |(_, lifetime)| lifetime.min(group.invitation_lifetime_seconds),
        );
        let expires_at_unix = now_unix
            .checked_add(lifetime_seconds)
            .ok_or("system_clock_invalid")?;
        let spec = InvitationSpec {
            group_name: &group.group_name,
            inviter_name,
            expires_at_unix,
            history_policy: group.history_policy,
            reusable: reusable.unwrap_or(group.reusable_invitation),
        };
        let hinted = (!address_hints.is_empty())
            .then(|| {
                let invitation = Invitation::issue_with_address_hints(
                    &identity,
                    inviter_device_id,
                    spec,
                    address_hints,
                    now_unix,
                )
                .ok()?;
                let encoded = Zeroizing::new(invitation.encode().ok()?);
                (encoded.len() <= MAX_PROTECTED_INVITATION_BYTES).then_some((invitation, encoded))
            })
            .flatten();
        let (invitation, encoded) = match hinted {
            Some(hinted) => hinted,
            None => {
                let invitation = Invitation::issue(&identity, inviter_device_id, spec, now_unix)
                    .map_err(|_| "invitation_creation_failed")?;
                let encoded = Zeroizing::new(
                    invitation
                        .encode()
                        .map_err(|_| "invitation_creation_failed")?,
                );
                (invitation, encoded)
            }
        };
        if encoded.len() > MAX_PROTECTED_INVITATION_BYTES {
            return Err("invitation_creation_failed");
        }
        let indexed = IssuedInvitationMetadata {
            invitation_id: invitation.invitation_id(),
            group_id,
            expires_at_unix,
            requested_by,
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
        if let Err(error) = self.retain_owner_discovery_key(&mut store, &invitation) {
            self.invitation_secrets.remove(indexed.invitation_id)?;
            store
                .remove_issued_invitation(indexed.invitation_id)
                .map_err(|_| "group_store_unavailable")?;
            return Err(error);
        }
        Ok((invitation, encoded))
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
                self.owner_discovery_keys.remove(indexed.invitation_id)?;
                store
                    .remove_owner_discovery_key(indexed.invitation_id)
                    .map_err(|_| "group_store_unavailable")?;
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
            self.retain_owner_discovery_key(&mut store, &invitation)?;
            if indexed.expires_at_unix <= now_unix {
                self.invitation_secrets.remove(indexed.invitation_id)?;
                store
                    .remove_issued_invitation(indexed.invitation_id)
                    .map_err(|_| "group_store_unavailable")?;
                continue;
            }
            invitations.push(issued_invitation(
                &invitation,
                encoded,
                indexed.requested_by,
            ));
        }
        Ok(invitations)
    }

    fn retain_owner_discovery_key(
        &self,
        store: &mut EventStore,
        invitation: &Invitation,
    ) -> Result<(), &'static str> {
        let invitation_id = invitation.invitation_id();
        let key = DiscoveryKey::from_invitation(invitation);
        let created =
            if let Some(existing) = self.owner_discovery_keys.get_optional(invitation_id)? {
                if existing != key {
                    return Err("owner_discovery_record_invalid");
                }
                false
            } else {
                self.owner_discovery_keys.put(invitation_id, key)?;
                true
            };
        if let Err(error) = store.put_owner_discovery_key(&OwnerDiscoveryKeyMetadata {
            invitation_id,
            group_id: invitation.group_id(),
        }) {
            if created {
                self.owner_discovery_keys.remove(invitation_id)?;
            }
            return Err(if matches!(error, charp2p_store::StoreError::Sqlite(_)) {
                "group_store_unavailable"
            } else {
                "owner_discovery_record_invalid"
            });
        }
        Ok(())
    }

    fn remove_owner_discovery_keys(
        &self,
        store: &mut EventStore,
        group_id: PeerId,
    ) -> Result<(), &'static str> {
        for metadata in store
            .owner_discovery_keys(group_id)
            .map_err(|_| "group_store_unavailable")?
        {
            self.owner_discovery_keys.remove(metadata.invitation_id)?;
            store
                .remove_owner_discovery_key(metadata.invitation_id)
                .map_err(|_| "group_store_unavailable")?;
        }
        Ok(())
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

/// Owner-side invite request handling that rechecks membership and
/// permission in the owner's MLS event state (ADR-036).
pub(crate) struct MemberInvitationService {
    groups: Arc<GroupService>,
    permissions: Arc<MlsProviderService>,
}

impl MemberInvitationService {
    pub(crate) fn new(groups: Arc<GroupService>, permissions: Arc<MlsProviderService>) -> Self {
        Self {
            groups,
            permissions,
        }
    }
}

impl InviteRequestService for MemberInvitationService {
    fn answer_invite_request(
        &self,
        owner_device_id: PeerId,
        inviter_name: &str,
        authenticated_peer: PeerId,
        request: &InviteRequest,
        address_hints: &[Multiaddr],
    ) -> InviteResponse {
        self.groups.answer_invite_request(
            owner_device_id,
            inviter_name,
            authenticated_peer,
            request,
            address_hints,
            |group_id, peer| self.permissions.may_request_invitation(group_id, peer),
        )
    }
}

/// Owner-side member admission that also shares the owned group's current
/// name and icon with the new member, whose Welcome starts after any earlier
/// metadata change.
pub(crate) struct OwnerMemberAdmissionService {
    groups: Arc<GroupService>,
    mls: Arc<MlsProviderService>,
}

impl OwnerMemberAdmissionService {
    pub(crate) fn new(groups: Arc<GroupService>, mls: Arc<MlsProviderService>) -> Self {
        Self { groups, mls }
    }
}

impl MemberAdmissionService for OwnerMemberAdmissionService {
    fn admit_member(
        &self,
        request: &JoinRequest,
        owner_identity: &DeviceIdentity,
        authenticated_peer: PeerId,
    ) -> Result<JoinResponse, MemberAdmissionError> {
        let group_id = request.group_id();
        // The signed reuse claim is authoritative (ADR-042); the invitation
        // was already authorized against the issued bearer record.
        let now_unix = unix_now().map_err(|_| MemberAdmissionError::Unavailable)?;
        let invitation = Invitation::decode(request.invitation(), now_unix)
            .map_err(|_| MemberAdmissionError::Unauthorized)?;
        if invitation.group_id() != group_id {
            return Err(MemberAdmissionError::Unauthorized);
        }
        let single_use_invitation = (!invitation.is_reusable()).then(|| invitation.invitation_id());
        // A consumed invitation no longer asks for approval: admission only
        // replays the consuming device's exact retry and refuses the rest.
        let consumed = match single_use_invitation {
            Some(invitation_id) => self
                .groups
                .single_use_invitation_consumed(group_id, invitation_id)
                .map_err(|_| MemberAdmissionError::Unavailable)?,
            None => false,
        };
        if !consumed {
            self.groups
                .admission_approval(request, authenticated_peer)?;
        }
        let group = self
            .groups
            .list()
            .map_err(|_| MemberAdmissionError::Unavailable)?
            .into_iter()
            .find(|group| group.group_id == group_id.to_string())
            .ok_or(MemberAdmissionError::Unavailable)?;
        let admission = self.mls.admit_member_sharing_metadata(
            group_id,
            owner_identity,
            authenticated_peer,
            request.key_package(),
            single_use_invitation,
            &group.group_name,
            group.icon,
        );
        if let Some(invitation_id) = single_use_invitation {
            // The admission is already committed; a failed retirement is
            // repeated by the next join attempt through the same invitation.
            let _ = self
                .groups
                .retire_consumed_invitation(group_id, invitation_id);
        }
        admission
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

fn owner_discovery_credential_user(invitation_id: InvitationId) -> String {
    format!(
        "{OWNER_DISCOVERY_CREDENTIAL_PREFIX}{}",
        encode_identifier(invitation_id)
    )
}

fn unix_now() -> Result<u64, &'static str> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "system_clock_invalid")?
        .as_secs())
}

/// Loads approval requests only for a locally owned group created with
/// approval required.
fn owned_approval_requests(
    store: &EventStore,
    group_id: PeerId,
    now_unix: u64,
) -> Result<Vec<ApprovalRequest>, &'static str> {
    let group = store
        .local_groups()
        .map_err(|_| "group_store_unavailable")?
        .into_iter()
        .find(|group| group.group_id == group_id)
        .ok_or("group_not_found")?;
    if !group.approval_required {
        return Err("approval_not_required");
    }
    Ok(store
        .owner_approval_requests(group_id, now_unix)
        .map_err(|_| "group_store_unavailable")?
        .into_iter()
        .map(|request| ApprovalRequest {
            device_id: request.device_id.to_string(),
            invitation_id: encode_identifier(request.invitation_id),
            expires_at_unix: request.expires_at_unix,
            first_requested_at_unix: request.first_requested_at_unix,
            last_requested_at_unix: request.last_requested_at_unix,
            state: match request.state {
                ApprovalState::Pending => "pending",
                ApprovalState::Approved => "approved",
                ApprovalState::Declined => "declined",
            },
        })
        .collect())
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

/// Parses an invitation identifier as shown to the interface: exactly the
/// lowercase hexadecimal form produced for `IssuedInvitation`.
pub(crate) fn parse_invitation_id(text: &str) -> Option<InvitationId> {
    let mut bytes = [0u8; 16];
    if text.len() != bytes.len() * 2
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(InvitationId::from_bytes(bytes))
}

fn issued_invitation(
    invitation: &Invitation,
    encoded: &str,
    requested_by: Option<PeerId>,
) -> IssuedInvitation {
    IssuedInvitation {
        invitation_id: encode_identifier(invitation.invitation_id()),
        group_id: invitation.group_id().to_string(),
        link: format!("charp2p://join/{encoded}"),
        expires_at_unix: invitation.expires_at_unix(),
        reusable: invitation.is_reusable(),
        requested_by: requested_by.map(|device| device.to_string()),
    }
}

/// Verifies an owner's answer to this member device's invite request
/// (ADR-036): the invitation must decode unexpired, belong to the requested
/// group and pin the owner device that was asked.
pub(crate) fn requested_invitation(
    response: &InviteResponse,
    group_id: PeerId,
    owner_device_id: PeerId,
    now_unix: u64,
) -> Result<IssuedInvitation, &'static str> {
    if let Some(reason) = response.rejection() {
        return Err(match reason {
            InviteRejectReason::Unauthorized => "invite_unauthorized",
            InviteRejectReason::Busy => "invite_busy",
        });
    }
    let encoded = response.invitation().ok_or("invite_response_invalid")?;
    let invitation =
        Invitation::decode(encoded, now_unix).map_err(|_| "invite_response_invalid")?;
    if invitation.group_id() != group_id || invitation.inviter_device_id() != owner_device_id {
        return Err("invite_response_invalid");
    }
    Ok(issued_invitation(&invitation, encoded, None))
}

/// Invitations the owner issued at this member device's request, kept in
/// memory only for display until they expire or the app closes. Asking the
/// owner again returns the same active invitation.
#[derive(Default)]
pub struct ReceivedInvitationCache {
    invitations: Mutex<BTreeMap<String, IssuedInvitation>>,
}

impl ReceivedInvitationCache {
    /// Keeps the latest invitation for its group.
    pub fn save(&self, invitation: IssuedInvitation) -> Result<(), &'static str> {
        self.invitations
            .lock()
            .map_err(|_| "received_invitations_unavailable")?
            .insert(invitation.group_id.clone(), invitation);
        Ok(())
    }

    /// Lists unexpired invitations for which `permitted` still holds,
    /// forgetting the rest.
    pub fn list(
        &self,
        permitted: impl FnMut(&IssuedInvitation) -> bool,
    ) -> Result<Vec<IssuedInvitation>, &'static str> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system_clock_invalid")?
            .as_secs();
        self.list_at(now_unix, permitted)
    }

    fn list_at(
        &self,
        now_unix: u64,
        mut permitted: impl FnMut(&IssuedInvitation) -> bool,
    ) -> Result<Vec<IssuedInvitation>, &'static str> {
        let mut invitations = self
            .invitations
            .lock()
            .map_err(|_| "received_invitations_unavailable")?;
        invitations
            .retain(|_, invitation| invitation.expires_at_unix > now_unix && permitted(invitation));
        Ok(invitations.values().cloned().collect())
    }
}

pub(crate) fn normalize_group_name(requested: &str) -> Result<String, &'static str> {
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
        DeviceIdentity, DiscoveryKey, GroupIdentity, GroupIdentitySecret, HistoryPolicy,
        Invitation, InvitationId, InvitationSpec, InviteRejectReason, InviteRequest,
        InviteResponse, JoinRequest, PeerId,
    };
    use charp2p_store::{EventStore, LocalGroupMetadata};

    use super::{
        encode_identifier, issued_invitation, parse_invitation_id, requested_invitation,
        ApprovalDecision, ApprovalRequest, CreateGroupSpec, GroupSecretStore, GroupService,
        IssuedInvitationSecretStore, JoinInvitationAuthorizationError, OwnerDiscoveryKeyStore,
        ReceivedInvitationCache, MAX_ACTIVE_INVITATIONS_PER_GROUP,
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

    #[derive(Default)]
    struct MemoryOwnerDiscoveryStore {
        saved: Mutex<Vec<(InvitationId, DiscoveryKey)>>,
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

    impl OwnerDiscoveryKeyStore for MemoryOwnerDiscoveryStore {
        fn put(&self, invitation_id: InvitationId, key: DiscoveryKey) -> Result<(), &'static str> {
            self.saved.lock().unwrap().push((invitation_id, key));
            Ok(())
        }

        fn get_optional(
            &self,
            invitation_id: InvitationId,
        ) -> Result<Option<DiscoveryKey>, &'static str> {
            Ok(self
                .saved
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find(|(saved_id, _)| *saved_id == invitation_id)
                .map(|(_, key)| *key))
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
            owner_discovery_keys: Box::new(MemoryOwnerDiscoveryStore::default()),
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

    fn revoke_group_invitations(service: &GroupService, group_id: PeerId) {
        let invitation_ids = service
            .metadata
            .lock()
            .unwrap()
            .issued_invitations()
            .unwrap()
            .into_iter()
            .filter(|invitation| invitation.group_id == group_id)
            .map(|invitation| invitation.invitation_id)
            .collect::<Vec<_>>();
        for invitation_id in invitation_ids {
            service.revoke_invitation(group_id, invitation_id).unwrap();
        }
    }

    #[test]
    fn created_group_restores_with_the_same_protected_root() {
        let service = service();
        let created = service.create(spec(" Project Atlas ")).unwrap();
        let restored = service.list().unwrap();

        assert_eq!(restored, vec![created]);
        assert_eq!(restored[0].group_name, "Project Atlas");
    }

    #[test]
    fn invitation_carries_address_hints_and_drops_invalid_ones() {
        const NOW: u64 = 1_800_000_000;
        let service = service();
        let created = service.create(spec("Project Atlas")).unwrap();
        let group_id: PeerId = created.group_id.parse().unwrap();
        let inviter = DeviceIdentity::generate().peer_id();
        let hint: libp2p::Multiaddr = "/ip4/198.51.100.7/udp/4001/quic-v1".parse().unwrap();

        let (hinted, _) = service
            .issue_requested_invitation_at(
                group_id,
                inviter,
                "Maya's PC",
                None,
                None,
                None,
                std::slice::from_ref(&hint),
                NOW,
            )
            .unwrap();
        assert_eq!(hinted.address_hints(), std::slice::from_ref(&hint));
        revoke_group_invitations(&service, group_id);

        // A hint ending in a peer ID is invalid, so the invitation is issued
        // without hints rather than failing.
        let invalid = hint.with(libp2p::multiaddr::Protocol::P2p(inviter));
        let (unhinted, encoded) = service
            .issue_requested_invitation_at(
                group_id,
                inviter,
                "Maya's PC",
                None,
                None,
                None,
                &[invalid],
                NOW,
            )
            .unwrap();
        assert!(unhinted.address_hints().is_empty());
        assert!(Invitation::decode(&encoded, NOW)
            .unwrap()
            .address_hints()
            .is_empty());
    }

    #[test]
    fn owner_can_create_several_groups_with_separate_roots_and_invitations() {
        const NOW: u64 = 1_800_000_000;
        let service = service();
        let first = service.create(spec("Project Atlas")).unwrap();
        let second = service.create(spec("Launch room")).unwrap();
        assert_ne!(first.group_id, second.group_id);

        let restored = service.list().unwrap();
        assert_eq!(restored.len(), 2);
        assert!(restored.contains(&first) && restored.contains(&second));

        let first_id: PeerId = first.group_id.parse().unwrap();
        let second_id: PeerId = second.group_id.parse().unwrap();
        let inviter = DeviceIdentity::generate().peer_id();
        service
            .issue_invitation_at(first_id, inviter, "Maya's PC", NOW)
            .unwrap();
        let second_invitation = service
            .issue_invitation_at(second_id, inviter, "Maya's PC", NOW)
            .unwrap();
        assert_eq!(service.issued_invitations_at(NOW).unwrap().len(), 2);
        let mut all_keys = service.owner_discovery_keys(first_id).unwrap();
        all_keys.extend(service.owner_discovery_keys(second_id).unwrap());
        assert_eq!(all_keys.len(), 2);
        let advertised = service.all_owner_discovery_keys().unwrap();
        assert_eq!(advertised.len(), all_keys.len());
        assert!(all_keys.iter().all(|key| advertised.contains(key)));

        revoke_group_invitations(&service, first_id);
        let remaining = service.issued_invitations_at(NOW).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].invitation_id, second_invitation.invitation_id);
        assert_eq!(remaining[0].group_id, second.group_id);
    }

    #[test]
    fn owner_changes_only_the_icon_of_an_owned_group() {
        let service = service();
        let created = service.create(spec("Launch room")).unwrap();
        let group_id: PeerId = created.group_id.parse().unwrap();

        let changed = service.set_icon(group_id, 4).unwrap();

        assert_eq!(changed.icon, 4);
        assert_eq!(changed.group_name, created.group_name);
        assert_eq!(service.list().unwrap(), vec![changed]);
        assert_eq!(service.set_icon(group_id, 5), Err("invalid_group_icon"));
        assert_eq!(
            service.set_icon(DeviceIdentity::generate().peer_id(), 1),
            Err("group_not_owned")
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
            .issue_invitation_at(
                group_id,
                DeviceIdentity::generate().peer_id(),
                "Maya's PC",
                NOW,
            )
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
        assert_eq!(restored[0].requested_by, None);
        assert!(Invitation::decode_input(&restored[0].link, NOW).is_ok());

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
    fn group_keeps_several_active_invitations_and_revokes_each_separately() {
        const NOW: u64 = 1_800_000_000;
        let service = service();
        let created = service.create(spec("Project Atlas")).unwrap();
        let group_id: PeerId = created.group_id.parse().unwrap();
        let owner = DeviceIdentity::generate().peer_id();
        let requester = DeviceIdentity::generate().peer_id();

        let first = service
            .issue_invitation_at(group_id, owner, "Maya's PC", NOW)
            .unwrap();
        let (requested, _) = service
            .issue_requested_invitation_at(
                group_id,
                owner,
                "Maya's PC",
                Some((requester, 86_400)),
                None,
                None,
                &[],
                NOW,
            )
            .unwrap();
        let second = service
            .issue_invitation_at(group_id, owner, "Maya's PC", NOW + 1)
            .unwrap();
        assert_ne!(first.invitation_id, second.invitation_id);

        let listed = service.issued_invitations_at(NOW + 1).unwrap();
        assert_eq!(listed.len(), 3);
        let requested_id = encode_identifier(requested.invitation_id());
        for invitation in &listed {
            let expected =
                (invitation.invitation_id == requested_id).then(|| requester.to_string());
            assert_eq!(invitation.requested_by, expected);
        }
        let first_request = join_request(&first.link, NOW + 1);
        let second_request = join_request(&second.link, NOW + 1);
        assert!(service
            .authorize_join_request_at(&first_request, NOW + 1)
            .is_ok());
        assert!(service
            .authorize_join_request_at(&second_request, NOW + 1)
            .is_ok());

        let first_id = parse_invitation_id(&first.invitation_id).unwrap();
        service.revoke_invitation(group_id, first_id).unwrap();
        assert_eq!(
            service.authorize_join_request_at(&first_request, NOW + 1),
            Err(JoinInvitationAuthorizationError::Unauthorized)
        );
        assert!(service
            .authorize_join_request_at(&second_request, NOW + 1)
            .is_ok());
        assert_eq!(service.issued_invitations_at(NOW + 1).unwrap().len(), 2);
        assert_eq!(
            service.revoke_invitation(DeviceIdentity::generate().peer_id(), first_id),
            Err("group_not_found")
        );

        for offset in 2..MAX_ACTIVE_INVITATIONS_PER_GROUP as u64 {
            service
                .issue_invitation_at(group_id, owner, "Maya's PC", NOW + offset)
                .unwrap();
        }
        assert!(matches!(
            service.issue_invitation_at(group_id, owner, "Maya's PC", NOW + 100),
            Err("invitation_limit_reached")
        ));
        // The member's repeated request still returns its active invitation.
        let (repeated, _) = service
            .issue_requested_invitation_at(
                group_id,
                owner,
                "Maya's PC",
                Some((requester, 86_400)),
                None,
                None,
                &[],
                NOW + 100,
            )
            .unwrap();
        assert_eq!(repeated.invitation_id(), requested.invitation_id());
    }

    #[test]
    fn invitation_ids_parse_only_in_their_displayed_form() {
        let id = InvitationId::from_bytes([0xab; 16]);
        assert_eq!(parse_invitation_id(&encode_identifier(id)), Some(id));
        assert_eq!(parse_invitation_id(&"AB".repeat(16)), None);
        assert_eq!(parse_invitation_id(&"ab".repeat(15)), None);
        assert_eq!(parse_invitation_id(&"gg".repeat(16)), None);
    }

    #[test]
    fn reusable_invitation_authorizes_repeatedly_until_expiry() {
        const NOW: u64 = 1_800_000_000;
        let service = service();
        let created = service.create(spec("Project Atlas")).unwrap();
        let group_id = created.group_id.parse().unwrap();
        let issued = service
            .issue_invitation_at(
                group_id,
                DeviceIdentity::generate().peer_id(),
                "Maya's PC",
                NOW,
            )
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
    fn owner_selects_a_shorter_invitation_expiry_capped_at_the_group_lifetime() {
        const NOW: u64 = 1_800_000_000;
        let service = service();
        let created = service.create(spec("Project Atlas")).unwrap();
        let group_id = created.group_id.parse().unwrap();
        let owner = DeviceIdentity::generate().peer_id();
        let issue = |lifetime| {
            service
                .issue_requested_invitation_at(
                    group_id,
                    owner,
                    "Maya's PC",
                    None,
                    None,
                    lifetime,
                    &[],
                    NOW,
                )
                .map(|(invitation, _)| invitation.expires_at_unix())
        };

        for refused in [1_209_600, 3_600] {
            assert_eq!(issue(Some(refused)), Err("invalid_invitation_lifetime"));
        }
        assert_eq!(
            service
                .issue_requested_invitation_at(
                    group_id,
                    owner,
                    "Maya's PC",
                    Some((owner, 86_400)),
                    None,
                    Some(86_400),
                    &[],
                    NOW,
                )
                .err(),
            Some("invalid_invitation_lifetime")
        );
        assert!(service.issued_invitations_at(NOW).unwrap().is_empty());

        assert_eq!(issue(Some(86_400)), Ok(NOW + 86_400));
        assert_eq!(
            service.issued_invitations_at(NOW).unwrap()[0].expires_at_unix,
            NOW + 86_400
        );
        revoke_group_invitations(&service, group_id);
        assert_eq!(issue(None), Ok(NOW + 604_800));
    }

    #[test]
    fn owner_overrides_group_reuse_default_per_invitation() {
        const NOW: u64 = 1_800_000_000;
        let service = service();
        let created = service.create(spec("Project Atlas")).unwrap();
        let group_id = created.group_id.parse().unwrap();
        let owner = DeviceIdentity::generate().peer_id();

        let single_use = service
            .issue_reuse_invitation_at(group_id, owner, "Maya's PC", Some(false), NOW)
            .unwrap();
        assert!(!single_use.reusable);
        let request = join_request(&single_use.link, NOW);
        assert!(!service
            .authorize_join_request_at(&request, NOW)
            .unwrap()
            .is_reusable());
        assert!(!service.issued_invitations_at(NOW).unwrap()[0].reusable);

        revoke_group_invitations(&service, group_id);
        let mut single_use_group = spec("Design Crew");
        single_use_group.reusable_invitation = false;
        let single_use_group = service.create(single_use_group).unwrap();
        let single_use_group_id = single_use_group.group_id.parse().unwrap();
        assert!(
            !service
                .issue_invitation_at(single_use_group_id, owner, "Maya's PC", NOW)
                .unwrap()
                .reusable
        );
        revoke_group_invitations(&service, single_use_group_id);
        assert!(
            service
                .issue_reuse_invitation_at(single_use_group_id, owner, "Maya's PC", Some(true), NOW)
                .unwrap()
                .reusable
        );
    }

    #[test]
    fn consumed_single_use_invitation_is_retired_but_still_reaches_admission() {
        use charp2p_core::{EventKind, EventSpec, SignedEvent};
        const NOW: u64 = 1_800_000_000;
        let service = service();
        let mut single_use = spec("Project Atlas");
        single_use.reusable_invitation = false;
        let created = service.create(single_use).unwrap();
        let group_id = created.group_id.parse().unwrap();
        let owner = DeviceIdentity::generate();
        let issued = service
            .issue_invitation_at(group_id, owner.peer_id(), "Maya's PC", NOW)
            .unwrap();
        assert!(!issued.reusable);
        let request = join_request(&issued.link, NOW);
        let invitation_id = request_invitation_id(&request, NOW);
        assert!(!service
            .authorize_join_request_at(&request, NOW)
            .unwrap()
            .is_reusable());

        // An unconsumed invitation is neither retired nor reported consumed.
        assert!(!service
            .retire_consumed_invitation(group_id, invitation_id)
            .unwrap());
        assert!(!service
            .single_use_invitation_consumed(group_id, invitation_id)
            .unwrap());
        assert_eq!(service.issued_invitations_at(NOW).unwrap().len(), 1);

        let added = SignedEvent::create(
            &owner,
            EventSpec {
                group_id,
                author_sequence: 1,
                causal_parents: &[],
                created_at_unix_ms: NOW * 1000,
                kind: EventKind::MemberAdded,
                protected_payload: b"MLS commit",
            },
        )
        .unwrap();
        service
            .metadata
            .lock()
            .unwrap()
            .put_mls_join_admission(
                &added,
                b"snapshot",
                DeviceIdentity::generate().peer_id(),
                &[1; 32],
                b"response",
                Some(invitation_id),
            )
            .unwrap();
        assert!(service
            .single_use_invitation_consumed(group_id, invitation_id)
            .unwrap());

        assert!(service
            .retire_consumed_invitation(group_id, invitation_id)
            .unwrap());
        assert!(service.issued_invitations_at(NOW).unwrap().is_empty());
        assert!(service
            .invitation_secrets
            .get_optional(invitation_id)
            .unwrap()
            .is_none());
        // As for revocation, the owner stays reachable for the consumer's retry.
        assert_eq!(service.owner_discovery_keys(group_id).unwrap().len(), 1);
        assert!(!service
            .retire_consumed_invitation(group_id, invitation_id)
            .unwrap());
        // The retired bearer still reaches admission, which answers only the
        // consuming device's exact retry (ADR-042).
        let authorized = service.authorize_join_request_at(&request, NOW).unwrap();
        assert_eq!(authorized.invitation_id(), invitation_id);
        assert!(!authorized.is_reusable());
        assert_eq!(
            service.authorize_join_request_at(
                &request,
                Invitation::decode(request.invitation(), NOW)
                    .unwrap()
                    .expires_at_unix()
            ),
            Err(JoinInvitationAuthorizationError::Unauthorized)
        );
    }

    #[test]
    fn approval_required_group_admits_only_approved_devices() {
        use crate::mls_storage::MemberAdmissionError;
        const NOW: u64 = 1_800_000_000;
        let service = service();
        let mut approval = spec("Design Crew");
        approval.approval_required = true;
        let created = service.create(approval).unwrap();
        assert!(created.approval_required);
        let group_id: PeerId = created.group_id.parse().unwrap();
        let issued = service
            .issue_invitation_at(
                group_id,
                DeviceIdentity::generate().peer_id(),
                "Maya's PC",
                NOW,
            )
            .unwrap();
        let request = join_request(&issued.link, NOW);
        let device = DeviceIdentity::generate().peer_id();
        let declined = DeviceIdentity::generate().peer_id();

        for _ in 0..2 {
            assert_eq!(
                service.admission_approval_at(&request, device, NOW),
                Err(MemberAdmissionError::AwaitingApproval)
            );
        }
        assert_eq!(
            service.admission_approval_at(&request, declined, NOW),
            Err(MemberAdmissionError::AwaitingApproval)
        );
        {
            let mut store = service.metadata.lock().unwrap();
            let requests = store.owner_approval_requests(group_id, NOW).unwrap();
            assert_eq!(requests.len(), 2);
            assert_eq!(
                requests[0].invitation_id,
                request_invitation_id(&request, NOW)
            );
            assert!(store
                .approve_owner_approval_request(group_id, device)
                .unwrap());
            assert!(store
                .decline_owner_approval_request(group_id, declined)
                .unwrap());
        }
        assert_eq!(service.admission_approval_at(&request, device, NOW), Ok(()));
        assert_eq!(
            service.admission_approval_at(&request, declined, NOW),
            Err(MemberAdmissionError::Unauthorized)
        );

        let open = service.create(spec("Open Crew")).unwrap();
        let open_issued = service
            .issue_invitation_at(
                open.group_id.parse().unwrap(),
                DeviceIdentity::generate().peer_id(),
                "Maya's PC",
                NOW,
            )
            .unwrap();
        let open_request = join_request(&open_issued.link, NOW);
        assert_eq!(
            service.admission_approval_at(&open_request, device, NOW),
            Ok(())
        );
        assert!(service
            .metadata
            .lock()
            .unwrap()
            .owner_approval_requests(open.group_id.parse().unwrap(), NOW)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn owner_lists_and_decides_approval_requests() {
        use crate::mls_storage::MemberAdmissionError;
        const NOW: u64 = 1_800_000_000;
        let service = service();
        let mut approval = spec("Design Crew");
        approval.approval_required = true;
        let group_id: PeerId = service.create(approval).unwrap().group_id.parse().unwrap();
        let issued = service
            .issue_invitation_at(
                group_id,
                DeviceIdentity::generate().peer_id(),
                "Maya's PC",
                NOW,
            )
            .unwrap();
        let request = join_request(&issued.link, NOW);
        let device = DeviceIdentity::generate().peer_id();
        let other = DeviceIdentity::generate().peer_id();
        assert!(service
            .approval_requests_at(group_id, NOW)
            .unwrap()
            .is_empty());
        for joining in [device, other] {
            assert_eq!(
                service.admission_approval_at(&request, joining, NOW),
                Err(MemberAdmissionError::AwaitingApproval)
            );
        }

        let listed = service.approval_requests_at(group_id, NOW).unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].invitation_id, issued.invitation_id);
        assert_eq!(listed[0].expires_at_unix, issued.expires_at_unix);
        assert!(listed.iter().all(|request| request.state == "pending"));

        let approved = service
            .decide_approval_request_at(group_id, device, ApprovalDecision::Approve, NOW)
            .unwrap();
        let state = |requests: &[ApprovalRequest], id: PeerId| {
            requests
                .iter()
                .find(|request| request.device_id == id.to_string())
                .map(|request| request.state)
        };
        assert_eq!(state(&approved, device), Some("approved"));
        assert_eq!(
            service.decide_approval_request_at(group_id, device, ApprovalDecision::Approve, NOW),
            Err("approval_request_not_found")
        );
        assert_eq!(
            service.decide_approval_request_at(group_id, device, ApprovalDecision::Allow, NOW),
            Err("approval_request_not_found")
        );

        let declined = service
            .decide_approval_request_at(group_id, other, ApprovalDecision::Decline, NOW)
            .unwrap();
        assert_eq!(state(&declined, other), Some("declined"));
        assert_eq!(
            service.admission_approval_at(&request, other, NOW),
            Err(MemberAdmissionError::Unauthorized)
        );
        let allowed = service
            .decide_approval_request_at(group_id, other, ApprovalDecision::Allow, NOW)
            .unwrap();
        assert_eq!(state(&allowed, other), None);
        assert_eq!(
            service.admission_approval_at(&request, other, NOW),
            Err(MemberAdmissionError::AwaitingApproval)
        );

        let open: PeerId = service
            .create(spec("Open Crew"))
            .unwrap()
            .group_id
            .parse()
            .unwrap();
        assert_eq!(
            service.approval_requests_at(open, NOW),
            Err("approval_not_required")
        );
        assert_eq!(
            service.decide_approval_request_at(open, device, ApprovalDecision::Approve, NOW),
            Err("approval_not_required")
        );
        assert_eq!(
            service.approval_requests_at(DeviceIdentity::generate().peer_id(), NOW),
            Err("group_not_found")
        );
    }

    #[test]
    fn permitted_member_invite_request_issues_owner_pinned_invitation() {
        const NOW: u64 = 1_800_000_000;
        let service = service();
        let created = service.create(spec("Project Atlas")).unwrap();
        let group_id: PeerId = created.group_id.parse().unwrap();
        let owner = DeviceIdentity::generate().peer_id();
        let member = DeviceIdentity::generate().peer_id();
        let other = DeviceIdentity::generate().peer_id();
        let answer = |peer, request: &InviteRequest, permitted: Result<bool, &'static str>| {
            service.answer_invite_request_at(
                owner,
                "Maya's PC",
                peer,
                request,
                &[],
                |checked_group, checked_peer| {
                    assert_eq!((checked_group, checked_peer), (group_id, peer));
                    permitted
                },
                NOW,
            )
        };
        let request = InviteRequest::new(group_id, 86_400).unwrap();

        let foreign = InviteRequest::new(DeviceIdentity::generate().peer_id(), 86_400).unwrap();
        assert_eq!(
            answer(member, &foreign, Ok(true)).rejection(),
            Some(InviteRejectReason::Unauthorized)
        );
        assert_eq!(
            answer(owner, &request, Ok(true)).rejection(),
            Some(InviteRejectReason::Unauthorized)
        );
        assert_eq!(
            answer(member, &request, Ok(false)).rejection(),
            Some(InviteRejectReason::Unauthorized)
        );
        assert_eq!(
            answer(member, &request, Err("message_store_unavailable")).rejection(),
            Some(InviteRejectReason::Busy)
        );
        assert!(service.issued_invitations_at(NOW).unwrap().is_empty());

        let issued = answer(member, &request, Ok(true));
        let invitation = Invitation::decode(issued.invitation().unwrap(), NOW).unwrap();
        assert_eq!(invitation.group_id(), group_id);
        assert_eq!(invitation.inviter_device_id(), owner);
        assert_eq!(invitation.inviter_name(), "Maya's PC");
        assert_eq!(invitation.expires_at_unix(), NOW + 86_400);
        assert!(invitation.is_reusable());

        // A lost response can be retried; another member gets its own
        // invitation while the first stays active.
        let repeated = answer(member, &request, Ok(true));
        assert_eq!(
            Invitation::decode(repeated.invitation().unwrap(), NOW)
                .unwrap()
                .invitation_id(),
            invitation.invitation_id()
        );
        let other_issued = answer(other, &request, Ok(true));
        assert_ne!(
            Invitation::decode(other_issued.invitation().unwrap(), NOW)
                .unwrap()
                .invitation_id(),
            invitation.invitation_id()
        );
        assert_eq!(service.issued_invitations_at(NOW).unwrap().len(), 2);

        let join = JoinRequest::from_invitation(&invitation, vec![1]).unwrap();
        assert!(service.authorize_join_request_at(&join, NOW).is_ok());
        assert_eq!(
            service
                .revoke_requested_invitations(group_id, member)
                .unwrap(),
            1
        );
        assert!(service.authorize_join_request_at(&join, NOW).is_err());

        // The owner's group lifetime caps a longer requested lifetime.
        let longer = InviteRequest::new(group_id, 2_592_000).unwrap();
        let capped = answer(member, &longer, Ok(true));
        assert_eq!(
            Invitation::decode(capped.invitation().unwrap(), NOW)
                .unwrap()
                .expires_at_unix(),
            NOW + 604_800
        );
    }

    #[test]
    fn member_accepts_only_the_requested_owner_invitation_and_caches_it() {
        const NOW: u64 = 1_800_000_000;
        let service = service();
        let created = service.create(spec("Project Atlas")).unwrap();
        let group_id: PeerId = created.group_id.parse().unwrap();
        let owner = DeviceIdentity::generate().peer_id();
        let member = DeviceIdentity::generate().peer_id();
        let request = InviteRequest::new(group_id, 86_400).unwrap();
        let response = service.answer_invite_request_at(
            owner,
            "Maya's PC",
            member,
            &request,
            &[],
            |_, _| Ok(true),
            NOW,
        );

        let accepted = requested_invitation(&response, group_id, owner, NOW).unwrap();
        assert_eq!(accepted.group_id, group_id.to_string());
        assert_eq!(accepted.expires_at_unix, NOW + 86_400);
        assert!(accepted.link.starts_with("charp2p://join/"));
        let other = DeviceIdentity::generate().peer_id();
        assert!(matches!(
            requested_invitation(&response, other, owner, NOW),
            Err("invite_response_invalid")
        ));
        assert!(matches!(
            requested_invitation(&response, group_id, other, NOW),
            Err("invite_response_invalid")
        ));
        assert!(matches!(
            requested_invitation(&response, group_id, owner, NOW + 86_400),
            Err("invite_response_invalid")
        ));
        assert!(matches!(
            requested_invitation(
                &InviteResponse::rejected(InviteRejectReason::Unauthorized),
                group_id,
                owner,
                NOW
            ),
            Err("invite_unauthorized")
        ));
        assert!(matches!(
            requested_invitation(
                &InviteResponse::rejected(InviteRejectReason::Busy),
                group_id,
                owner,
                NOW
            ),
            Err("invite_busy")
        ));

        let cache = ReceivedInvitationCache::default();
        cache.save(accepted.clone()).unwrap();
        assert!(cache.list_at(NOW, |_| true).unwrap() == vec![accepted.clone()]);
        // Withdrawn permission or expiry forgets the invitation.
        assert!(cache.list_at(NOW, |_| false).unwrap().is_empty());
        cache.save(accepted).unwrap();
        assert!(cache.list_at(NOW + 86_400, |_| true).unwrap().is_empty());
    }

    #[test]
    fn requested_invitations_are_revoked_only_for_their_requester() {
        const NOW: u64 = 1_800_000_000;
        let service = service();
        let created = service.create(spec("Project Atlas")).unwrap();
        let group_id = created.group_id.parse().unwrap();
        let owner = DeviceIdentity::generate().peer_id();
        let requester = DeviceIdentity::generate().peer_id();
        let issued = service
            .issue_requested_invitation_at(
                group_id,
                owner,
                "Maya's PC",
                Some((requester, 86_400)),
                None,
                None,
                &[],
                NOW,
            )
            .map(|(invitation, encoded)| {
                issued_invitation(&invitation, encoded.as_str(), Some(requester))
            })
            .unwrap();
        let request = join_request(&issued.link, NOW);
        assert!(service.authorize_join_request_at(&request, NOW).is_ok());

        assert_eq!(
            service
                .revoke_requested_invitations(group_id, DeviceIdentity::generate().peer_id())
                .unwrap(),
            0
        );
        assert!(service.authorize_join_request_at(&request, NOW).is_ok());
        assert_eq!(
            service
                .revoke_requested_invitations(group_id, requester)
                .unwrap(),
            1
        );

        assert_eq!(
            service.authorize_join_request_at(&request, NOW),
            Err(JoinInvitationAuthorizationError::Unauthorized)
        );
        assert!(service.issued_invitations_at(NOW).unwrap().is_empty());
        service
            .issue_invitation_at(group_id, owner, "Maya's PC", NOW)
            .unwrap();
        assert_eq!(
            service
                .revoke_requested_invitations(group_id, requester)
                .unwrap(),
            0
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
            .issue_invitation_at(
                group_id,
                DeviceIdentity::generate().peer_id(),
                "Maya's PC",
                NOW,
            )
            .unwrap();
        let request = join_request(&issued.link, NOW);
        let invitation_id = request_invitation_id(&request, NOW);
        let expected_discovery_key =
            DiscoveryKey::from_invitation(&Invitation::decode_input(&issued.link, NOW).unwrap());
        assert!(service.authorize_join_request_at(&request, NOW).is_ok());
        assert_eq!(
            service.owner_discovery_keys(group_id).unwrap(),
            vec![expected_discovery_key]
        );

        service.revoke_invitation(group_id, invitation_id).unwrap();

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
            service.owner_discovery_keys(group_id).unwrap(),
            vec![expected_discovery_key]
        );
        assert_eq!(
            service.revoke_invitation(group_id, invitation_id),
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
            .issue_invitation_at(
                group_id,
                DeviceIdentity::generate().peer_id(),
                "Maya's PC",
                NOW,
            )
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
        let foreign_request = JoinRequest::from_invitation(&foreign_invitation, vec![1]).unwrap();
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
            .issue_invitation_at(
                group_id,
                DeviceIdentity::generate().peer_id(),
                "Maya's PC",
                NOW,
            )
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
        let issued = service
            .issue_invitation_at(
                group_id,
                DeviceIdentity::generate().peer_id(),
                "Maya's PC",
                NOW,
            )
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
        assert!(service
            .metadata
            .lock()
            .unwrap()
            .owner_discovery_keys(group_id)
            .unwrap()
            .is_empty());
        assert!(service
            .owner_discovery_keys
            .get_optional(request_invitation_id(&join_request(&issued.link, NOW), NOW))
            .unwrap()
            .is_none());
    }

    #[test]
    fn malformed_active_invitation_fails_closed_before_replacement() {
        const NOW: u64 = 1_800_000_000;
        let service = service();
        let created = service.create(spec("Project Atlas")).unwrap();
        let group_id = created.group_id.parse().unwrap();
        service
            .issue_invitation_at(
                group_id,
                DeviceIdentity::generate().peer_id(),
                "Maya's PC",
                NOW,
            )
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
            service.issue_invitation_at(
                group_id,
                DeviceIdentity::generate().peer_id(),
                "Maya's PC",
                NOW + 1
            ),
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
    fn unimplemented_history_option_is_rejected_and_single_use_is_accepted() {
        let service = service();
        let mut unsupported_history = spec("Design Crew");
        unsupported_history.history_policy = "allRetained";
        assert!(matches!(
            service.create(unsupported_history),
            Err("group_option_unsupported")
        ));

        let mut single_use = spec("Design Crew");
        single_use.reusable_invitation = false;
        assert!(!service.create(single_use).unwrap().reusable_invitation);
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
            owner_discovery_keys: Box::new(MemoryOwnerDiscoveryStore::default()),
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
            owner_discovery_keys: Box::new(MemoryOwnerDiscoveryStore::default()),
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
