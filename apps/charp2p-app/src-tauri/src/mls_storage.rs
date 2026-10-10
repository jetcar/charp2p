use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use charp2p_core::{
    DeviceIdentity, DiscoveryKey, EventId, EventKind, EventSpec, GroupMetadata, Invitation,
    InvitationId, InvitePermission, JoinRequest, JoinResponse, MessageBody, MessageDeletion,
    MessageEdit, PeerId, SignedEvent, SyncPeerHead, SyncRejectReason, SyncRequest, SyncResponse,
    MAX_JOIN_RESPONSE_WIRE_BYTES, MAX_SYNC_AUTHORS, MAX_SYNC_BATCH_ITEMS, MAX_SYNC_RESPONSE_BYTES,
};
use charp2p_mls::{
    decode_profile_message, device_credential, device_id_from_credential, group_create_config,
    merge_prepared_key_refresh, merge_prepared_member_admission, merge_prepared_member_removal,
    prepare_profile_key_package, prepare_profile_key_refresh, prepare_profile_member_admission,
    prepare_profile_member_removal, stage_profile_welcome, validate_group_profile,
    validate_key_refresh_commit, validate_profile_key_package, validate_staged_commit_profile,
    PrepareMemberAdmissionError, PrepareMemberRemovalError, ProfileKeyPackageError,
    ProfileProvider, CIPHERSUITE, MAX_MLS_WIRE_BYTES,
};
use charp2p_store::{
    EventStore, StoreError, MAX_ENCRYPTED_JOIN_RESPONSE_BYTES, MAX_ENCRYPTED_MESSAGE_BODY_BYTES,
    MAX_ENCRYPTED_MLS_PROVIDER_SNAPSHOT_BYTES,
};
use charp2p_sync::{
    accept_pushed_events, build_authorized_response, record_reported_heads, PullSession,
    SessionProgress, SynchronizationError,
};
use keyring_core::Error as KeyringError;
use openmls::prelude::{
    tls_codec::Deserialize, ContentType, CredentialWithKey, GroupId, KeyPackageIn, MlsGroup,
    OpenMlsProvider, ProcessedMessageContent, ProtocolMessage, ProtocolVersion,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::storage::StorageProvider;
use serde::Serialize as SerdeSerialize;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::identity::protected_entry;

const WRAPPING_KEY_CREDENTIAL_USER: &str = "mls-provider-wrapping-key-v1";
const WRAPPING_KEY_BYTES: usize = 32;
const ENVELOPE_VERSION: u16 = 1;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
const ENVELOPE_HEADER_BYTES: usize = 2 + NONCE_BYTES;
const SNAPSHOT_AAD: &[u8] = b"charp2p-mls-provider-snapshot-v1\0";
const MESSAGE_AAD: &[u8] = b"charp2p-local-message-v1\0";
const JOIN_RESPONSE_AAD: &[u8] = b"charp2p-join-response-v1\0";
const JOIN_REQUEST_HASH_DOMAIN: &[u8] = b"charp2p-join-request-v1\0";
const MAX_MESSAGE_TEXT_BYTES: usize = 16 * 1024;
const MEMBER_RENDEZVOUS_LABEL: &str = "charp2p member rendezvous v1";
const MEMBER_RENDEZVOUS_SECRET_BYTES: usize = 32;
pub(crate) const MAX_EVIDENCE_EVENTS: usize = 64;
/// Maximum number of groups one group list preview request may name.
pub(crate) const MAX_PREVIEW_GROUPS: usize = 256;
const EVIDENCE_FORMAT: &str = "charp2p-evidence-v1";
const EVIDENCE_NOTICE: &str = "Each signed event proves which device signed it and when it claims to have been created. Event payloads are end-to-end encrypted; displayedText is the text shown on the exporting device and is not covered by the signatures.";

trait WrappingKeyStore: Send + Sync {
    fn get_optional(&self) -> Result<Option<Zeroizing<[u8; WRAPPING_KEY_BYTES]>>, &'static str>;
    fn put(&self, key: &[u8; WRAPPING_KEY_BYTES]) -> Result<(), &'static str>;
}

struct PlatformWrappingKeyStore;

impl WrappingKeyStore for PlatformWrappingKeyStore {
    fn get_optional(&self) -> Result<Option<Zeroizing<[u8; WRAPPING_KEY_BYTES]>>, &'static str> {
        let entry = protected_entry(WRAPPING_KEY_CREDENTIAL_USER)
            .map_err(|_| "mls_wrapping_key_store_unavailable")?;
        let encoded = match entry.get_secret() {
            Ok(encoded) => Zeroizing::new(encoded),
            Err(KeyringError::NoEntry) => return Ok(None),
            Err(_) => return Err("mls_wrapping_key_store_unavailable"),
        };
        if encoded.len() != WRAPPING_KEY_BYTES {
            return Err("mls_wrapping_key_record_invalid");
        }
        let mut key = Zeroizing::new([0; WRAPPING_KEY_BYTES]);
        key.copy_from_slice(encoded.as_slice());
        Ok(Some(key))
    }

    fn put(&self, key: &[u8; WRAPPING_KEY_BYTES]) -> Result<(), &'static str> {
        protected_entry(WRAPPING_KEY_CREDENTIAL_USER)
            .map_err(|_| "mls_wrapping_key_store_unavailable")?
            .set_secret(key)
            .map_err(|_| "mls_wrapping_key_store_unavailable")
    }
}

/// Owns the in-memory OpenMLS provider and its encrypted durable snapshot.
pub(crate) struct MlsProviderService {
    operations: Arc<Mutex<()>>,
    store: Mutex<EventStore>,
    provider: Mutex<ProfileProvider>,
    wrapping_keys: Box<dyn WrappingKeyStore>,
}

#[derive(Clone, Debug, Eq, PartialEq, SerdeSerialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CreatedMessage {
    pub event_id: String,
    pub group_id: String,
    pub author_id: String,
    pub author_sequence: u64,
    pub created_at_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, SerdeSerialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StoredMessage {
    pub event_id: String,
    pub group_id: String,
    pub author_id: String,
    pub author_sequence: u64,
    pub created_at_unix_ms: u64,
    pub text: String,
    pub edited: bool,
    pub reply_to_event_id: Option<String>,
    pub delivery_state: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq, SerdeSerialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StoredMessagePage {
    pub messages: Vec<StoredMessage>,
    pub has_earlier: bool,
}

/// User-selected signed events exported for review outside the app (ADR-029).
#[derive(Clone, Debug, Eq, PartialEq, SerdeSerialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EvidenceExport {
    pub format: &'static str,
    pub notice: &'static str,
    pub generated_at_unix_ms: u64,
    pub exported_by_device_id: String,
    pub group_id: String,
    pub events: Vec<EvidenceEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq, SerdeSerialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EvidenceEvent {
    pub event_id: String,
    pub kind: &'static str,
    pub author_id: String,
    pub author_sequence: u64,
    pub created_at_unix_ms: u64,
    /// Canonical signed envelope; its payload stays MLS ciphertext.
    pub signed_event_hex: String,
    /// Text this device shows, asserted by the exporter, not by a signature.
    pub displayed_text: String,
    pub edit: Option<EvidenceEdit>,
}

#[derive(Clone, Debug, Eq, PartialEq, SerdeSerialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EvidenceEdit {
    pub event_id: String,
    pub kind: &'static str,
    pub signed_event_hex: String,
}

#[derive(Clone, Debug, Eq, PartialEq, SerdeSerialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct UnreadMessageCount {
    pub group_id: String,
    pub count: u64,
}

/// Newest displayable message of one group, shown in the group list.
#[derive(Clone, Debug, Eq, PartialEq, SerdeSerialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GroupMessagePreview {
    pub group_id: String,
    pub author_id: String,
    pub created_at_unix_ms: u64,
    pub text: String,
}

#[derive(Clone, Debug, Eq, PartialEq, SerdeSerialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GroupMemberDevice {
    pub device_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, SerdeSerialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct MemberActivity {
    pub device_id: String,
    pub last_signed_at_unix_ms: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, SerdeSerialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DeviceSequenceConflict {
    pub device_id: String,
    pub conflicting_sequences: u64,
    pub first_sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MemberAdmissionError {
    Unauthorized,
    UnsupportedProfile,
    Unavailable,
    /// The owner has not approved the device yet (ADR-041).
    AwaitingApproval,
}

impl MlsProviderService {
    pub(crate) fn open(
        path: impl AsRef<Path>,
        operations: Arc<Mutex<()>>,
    ) -> Result<Self, &'static str> {
        Self::open_with_key_store(path, operations, Box::new(PlatformWrappingKeyStore))
    }

    fn open_with_key_store(
        path: impl AsRef<Path>,
        operations: Arc<Mutex<()>>,
        wrapping_keys: Box<dyn WrappingKeyStore>,
    ) -> Result<Self, &'static str> {
        let _operation = operations
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let store = EventStore::open(path).map_err(|_| "mls_provider_store_unavailable")?;
        let provider = match store
            .encrypted_mls_provider_snapshot()
            .map_err(|_| "mls_provider_store_unavailable")?
        {
            Some(encrypted) => {
                let key = wrapping_keys
                    .get_optional()?
                    .ok_or("mls_wrapping_key_missing")?;
                let snapshot = decrypt_snapshot(&encrypted, &key)?;
                ProfileProvider::from_snapshot(&snapshot)
                    .map_err(|_| "mls_provider_snapshot_invalid")?
            }
            None => ProfileProvider::default(),
        };
        drop(_operation);
        Ok(Self {
            operations,
            store: Mutex::new(store),
            provider: Mutex::new(provider),
            wrapping_keys,
        })
    }

    /// Creates or verifies the owner's MLS group using the stable CharP2P
    /// group identifier as the MLS group identifier.
    pub(crate) fn initialize_owner_group(
        &self,
        group_id: PeerId,
        owner_identity: &DeviceIdentity,
    ) -> Result<(), &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let mut provider = self
            .provider
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let previous = provider
            .snapshot()
            .map_err(|_| "mls_provider_snapshot_invalid")?;
        let result = (|| {
            initialize_owner_group(&mut provider, group_id, owner_identity.peer_id())?;
            if store
                .synchronization_summary(group_id)
                .map_err(|_| "mls_provider_store_unavailable")?
                .into_iter()
                .any(|head| head.author_id == owner_identity.peer_id())
            {
                return Ok(());
            }
            let event = SignedEvent::create(
                owner_identity,
                EventSpec {
                    group_id,
                    author_sequence: 1,
                    causal_parents: &[],
                    created_at_unix_ms: unix_time_millis()?,
                    kind: EventKind::GroupCreated,
                    protected_payload: &[],
                },
            )
            .map_err(|_| "group_creation_event_failed")?;
            let snapshot = provider
                .snapshot()
                .map_err(|_| "mls_provider_snapshot_invalid")?;
            let key = self.load_or_create_wrapping_key()?;
            let encrypted = encrypt_snapshot(&snapshot, &key)?;
            store
                .put_event_and_encrypted_mls_provider_snapshot(&event, &encrypted)
                .map_err(|_| "mls_provider_store_unavailable")?;
            Ok(())
        })();
        if result.is_err() {
            *provider = ProfileProvider::from_snapshot(&previous)
                .map_err(|_| "mls_provider_snapshot_invalid")?;
        }
        result
    }

    pub(crate) fn has_group(&self, group_id: PeerId) -> Result<bool, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let provider = self
            .provider
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        MlsGroup::load(
            provider.storage(),
            &GroupId::from_slice(&group_id.to_bytes()),
        )
        .map(|group| group.is_some())
        .map_err(|_| "mls_group_storage_unavailable")
    }

    pub(crate) fn group_members(
        &self,
        group_id: PeerId,
    ) -> Result<Vec<GroupMemberDevice>, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let provider = self
            .provider
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let group = MlsGroup::load(
            provider.storage(),
            &GroupId::from_slice(&group_id.to_bytes()),
        )
        .map_err(|_| "mls_group_storage_unavailable")?
        .ok_or("mls_joined_group_missing")?;
        validate_group_profile(&group).map_err(|_| "mls_group_profile_invalid")?;
        if group.group_id().as_slice() != group_id.to_bytes() {
            return Err("mls_group_identity_invalid");
        }
        group_member_devices(&group)
    }

    /// Derives the member rendezvous key of the group's current MLS epoch
    /// (ADR-040). It changes with every commit, so only devices that are
    /// members in this epoch share it.
    // Advertised and searched by member-served synchronization (ADR-040).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn member_rendezvous_key(
        &self,
        group_id: PeerId,
    ) -> Result<DiscoveryKey, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let provider = self
            .provider
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let group = MlsGroup::load(
            provider.storage(),
            &GroupId::from_slice(&group_id.to_bytes()),
        )
        .map_err(|_| "mls_group_storage_unavailable")?
        .ok_or("mls_joined_group_missing")?;
        validate_group_profile(&group).map_err(|_| "mls_group_profile_invalid")?;
        if !group.is_active() {
            return Err("mls_group_inactive");
        }
        let secret = Zeroizing::new(
            group
                .export_secret(
                    provider.crypto(),
                    MEMBER_RENDEZVOUS_LABEL,
                    &group_id.to_bytes(),
                    MEMBER_RENDEZVOUS_SECRET_BYTES,
                )
                .map_err(|_| "mls_export_failed")?,
        );
        let secret: &[u8; MEMBER_RENDEZVOUS_SECRET_BYTES] = secret
            .as_slice()
            .try_into()
            .map_err(|_| "mls_export_failed")?;
        Ok(DiscoveryKey::derive(group_id, secret))
    }

    /// Removes one current device and durably blocks it from reusing an
    /// outstanding reusable invitation.
    pub(crate) fn remove_member(
        &self,
        group_id: PeerId,
        owner_identity: &DeviceIdentity,
        removed_peer: PeerId,
    ) -> Result<Vec<GroupMemberDevice>, &'static str> {
        let created_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .ok_or("system_clock_invalid")?;
        self.remove_member_at(group_id, owner_identity, removed_peer, created_at_unix_ms)
    }

    fn remove_member_at(
        &self,
        group_id: PeerId,
        owner_identity: &DeviceIdentity,
        removed_peer: PeerId,
        created_at_unix_ms: u64,
    ) -> Result<Vec<GroupMemberDevice>, &'static str> {
        if removed_peer == owner_identity.peer_id() {
            return Err("member_owner_cannot_remove");
        }
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let mut provider = self
            .provider
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let previous = provider
            .snapshot()
            .map_err(|_| "mls_provider_snapshot_invalid")?;
        let result = (|| {
            let mut group = MlsGroup::load(
                provider.storage(),
                &GroupId::from_slice(&group_id.to_bytes()),
            )
            .map_err(|_| "mls_group_storage_unavailable")?
            .ok_or("mls_joined_group_missing")?;
            validate_owner_group(&group, group_id, owner_identity.peer_id())
                .map_err(|_| "member_removal_not_allowed")?;
            let own_signature_key = group
                .own_leaf_node()
                .ok_or("mls_group_storage_unavailable")?
                .signature_key();
            let signer = SignatureKeyPair::read(
                provider.storage(),
                own_signature_key.as_slice(),
                CIPHERSUITE.signature_algorithm(),
            )
            .ok_or("mls_group_storage_unavailable")?;
            let (author_sequence, causal_parents) =
                next_event_position(&store, group_id, owner_identity.peer_id())
                    .map_err(|_| "member_removal_failed")?;
            let removal =
                prepare_profile_member_removal(&mut group, &*provider, &signer, removed_peer)
                    .map_err(map_removal_preparation_error)?;
            let event = SignedEvent::create(
                owner_identity,
                EventSpec {
                    group_id,
                    author_sequence,
                    causal_parents: &causal_parents,
                    created_at_unix_ms,
                    kind: EventKind::MemberRemoved,
                    protected_payload: removal.commit(),
                },
            )
            .map_err(|_| "member_removal_failed")?;
            merge_prepared_member_removal(&mut group, &*provider)
                .map_err(|_| "member_removal_failed")?;
            let snapshot = provider
                .snapshot()
                .map_err(|_| "mls_provider_snapshot_invalid")?;
            let key = self.load_or_create_wrapping_key()?;
            let encrypted = encrypt_snapshot(&snapshot, &key)?;
            store
                .put_mls_member_removal(&event, &encrypted, removed_peer)
                .map_err(|_| "member_removal_store_unavailable")?;
            group_member_devices(&group)
        })();
        if result.is_err() {
            *provider = ProfileProvider::from_snapshot(&previous)
                .map_err(|_| "mls_provider_snapshot_invalid")?;
        }
        result
    }

    /// Advances an owned group to a fresh epoch with an owner-signed
    /// KeyEpochAdvanced Commit that leaves membership unchanged (ADR-045).
    pub(crate) fn refresh_group_keys(
        &self,
        group_id: PeerId,
        owner_identity: &DeviceIdentity,
    ) -> Result<(), &'static str> {
        let created_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .ok_or("system_clock_invalid")?;
        self.refresh_group_keys_at(group_id, owner_identity, created_at_unix_ms)
    }

    fn refresh_group_keys_at(
        &self,
        group_id: PeerId,
        owner_identity: &DeviceIdentity,
        created_at_unix_ms: u64,
    ) -> Result<(), &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let mut provider = self
            .provider
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let previous = provider
            .snapshot()
            .map_err(|_| "mls_provider_snapshot_invalid")?;
        let result = (|| {
            let mut group = MlsGroup::load(
                provider.storage(),
                &GroupId::from_slice(&group_id.to_bytes()),
            )
            .map_err(|_| "mls_group_storage_unavailable")?
            .ok_or("mls_joined_group_missing")?;
            validate_owner_group(&group, group_id, owner_identity.peer_id())
                .map_err(|_| "key_refresh_not_allowed")?;
            // Joined members never commit; only the owning device refreshes.
            if store
                .joined_groups()
                .map_err(|_| "key_refresh_store_unavailable")?
                .iter()
                .any(|joined| joined.group_id == group_id)
            {
                return Err("key_refresh_not_allowed");
            }
            let own_signature_key = group
                .own_leaf_node()
                .ok_or("mls_group_storage_unavailable")?
                .signature_key();
            let signer = SignatureKeyPair::read(
                provider.storage(),
                own_signature_key.as_slice(),
                CIPHERSUITE.signature_algorithm(),
            )
            .ok_or("mls_group_storage_unavailable")?;
            let (author_sequence, causal_parents) =
                next_event_position(&store, group_id, owner_identity.peer_id())
                    .map_err(|_| "key_refresh_failed")?;
            let refresh = prepare_profile_key_refresh(&mut group, &*provider, &signer)
                .map_err(|_| "key_refresh_failed")?;
            let event = SignedEvent::create(
                owner_identity,
                EventSpec {
                    group_id,
                    author_sequence,
                    causal_parents: &causal_parents,
                    created_at_unix_ms,
                    kind: EventKind::KeyEpochAdvanced,
                    protected_payload: refresh.commit(),
                },
            )
            .map_err(|_| "key_refresh_failed")?;
            merge_prepared_key_refresh(&mut group, &*provider).map_err(|_| "key_refresh_failed")?;
            let snapshot = provider
                .snapshot()
                .map_err(|_| "mls_provider_snapshot_invalid")?;
            let key = self.load_or_create_wrapping_key()?;
            let encrypted = encrypt_snapshot(&snapshot, &key)?;
            store
                .put_mls_key_refresh(&event, &encrypted)
                .map_err(|_| "key_refresh_store_unavailable")?;
            Ok(())
        })();
        if result.is_err() {
            *provider = ProfileProvider::from_snapshot(&previous)
                .map_err(|_| "mls_provider_snapshot_invalid")?;
        }
        result
    }

    /// Lists the devices removed from an owned group that remain blocked from
    /// re-admission.
    pub(crate) fn removed_members(&self, group_id: PeerId) -> Result<Vec<String>, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let store = self
            .store
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        removed_member_ids(&store, group_id)
    }

    /// Lets the owner clear a removed device's re-admission block. The device
    /// is not added back: it must join again through an active invitation
    /// with a new KeyPackage, which creates a new MLS leaf and epoch.
    pub(crate) fn allow_member_readmission(
        &self,
        group_id: PeerId,
        owner_identity: &DeviceIdentity,
        removed_peer: PeerId,
    ) -> Result<Vec<String>, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let provider = self
            .provider
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let group = MlsGroup::load(
            provider.storage(),
            &GroupId::from_slice(&group_id.to_bytes()),
        )
        .map_err(|_| "mls_group_storage_unavailable")?
        .ok_or("mls_joined_group_missing")?;
        validate_owner_group(&group, group_id, owner_identity.peer_id())
            .map_err(|_| "member_readmission_not_allowed")?;
        if !store
            .allow_removed_mls_member_readmission(group_id, removed_peer)
            .map_err(|_| "member_readmission_failed")?
        {
            return Err("member_not_removed");
        }
        removed_member_ids(&store, group_id)
    }

    pub(crate) fn create_message(
        &self,
        group_id: PeerId,
        author: &DeviceIdentity,
        message: &str,
        reply_to: Option<&[u8; 32]>,
    ) -> Result<CreatedMessage, &'static str> {
        let created_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .ok_or("system_clock_invalid")?;
        let body = MessageBody::new(message, reply_to.copied()).map_err(|_| "message_invalid")?;
        let event = self.create_body_at(group_id, author, &body, created_at_unix_ms)?;
        Ok(CreatedMessage {
            event_id: hex_bytes(event.id().as_bytes()),
            group_id: event.group_id().to_string(),
            author_id: event.author_id().to_string(),
            author_sequence: event.author_sequence(),
            created_at_unix_ms: event.created_at_unix_ms(),
        })
    }

    pub(crate) fn messages(
        &self,
        group_id: PeerId,
        local_device_id: PeerId,
    ) -> Result<StoredMessagePage, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let other_members = {
            let provider = self
                .provider
                .lock()
                .map_err(|_| "mls_provider_service_unavailable")?;
            match MlsGroup::load(
                provider.storage(),
                &GroupId::from_slice(&group_id.to_bytes()),
            )
            .map_err(|_| "mls_group_storage_unavailable")?
            {
                Some(group) => group
                    .members()
                    .map(|member| {
                        device_id_from_credential(&member.credential)
                            .map_err(|_| "mls_group_members_invalid")
                    })
                    .filter(|member| *member != Ok(local_device_id))
                    .collect::<Result<Vec<_>, _>>()?,
                None => Vec::new(),
            }
        };
        let mut store = self
            .store
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let encrypted_page = store
            .encrypted_messages(group_id)
            .map_err(|_| "message_list_unavailable")?;
        store
            .mark_messages_read(group_id)
            .map_err(|_| "message_list_unavailable")?;
        let acknowledged_heads = store
            .acknowledged_author_heads(group_id, local_device_id)
            .map_err(|_| "message_list_unavailable")?;
        let acknowledged_head = acknowledged_heads.values().copied().max().unwrap_or(0);
        let observed_by_all_head = observed_by_all_head(&other_members, &acknowledged_heads);
        if encrypted_page.messages.is_empty() {
            return Ok(StoredMessagePage {
                messages: Vec::new(),
                has_earlier: false,
            });
        }
        let key = self
            .wrapping_keys
            .get_optional()?
            .ok_or("mls_wrapping_key_missing")?;
        let messages = encrypted_page
            .messages
            .into_iter()
            .map(|message| {
                let text = displayed_message_text(&message, &key)?;
                Ok::<_, &'static str>(StoredMessage {
                    event_id: hex_bytes(&message.event_id),
                    group_id: message.group_id.to_string(),
                    author_id: message.author_id.to_string(),
                    author_sequence: message.author_sequence,
                    created_at_unix_ms: message.created_at_unix_ms,
                    text,
                    edited: message.edit.is_some(),
                    reply_to_event_id: message.reply_to.as_ref().map(|id| hex_bytes(id)),
                    delivery_state: if message.author_id != local_device_id {
                        "received"
                    } else if message.author_sequence <= observed_by_all_head {
                        "observedByAll"
                    } else if message.author_sequence <= acknowledged_head {
                        "sharedWithPeer"
                    } else {
                        "local"
                    },
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(StoredMessagePage {
            messages,
            has_earlier: encrypted_page.has_earlier,
        })
    }

    /// Builds an evidence export of user-selected readable messages: their
    /// signed event envelopes (and the latest applied edit's envelope) with
    /// the text shown on this device (ADR-029). Selection is limited to the
    /// messages the timeline currently shows.
    pub(crate) fn evidence(
        &self,
        group_id: PeerId,
        local_device_id: PeerId,
        event_ids: &[[u8; 32]],
        generated_at_unix_ms: u64,
    ) -> Result<EvidenceExport, &'static str> {
        if event_ids.is_empty() || event_ids.len() > MAX_EVIDENCE_EVENTS {
            return Err("evidence_selection_invalid");
        }
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let store = self
            .store
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let page = store
            .encrypted_messages(group_id)
            .map_err(|_| "message_list_unavailable")?;
        let selected = page
            .messages
            .into_iter()
            .filter(|message| event_ids.contains(&message.event_id))
            .collect::<Vec<_>>();
        let mut requested = event_ids.to_vec();
        requested.sort_unstable();
        requested.dedup();
        if selected.len() != requested.len() {
            return Err("message_not_found");
        }
        let key = self
            .wrapping_keys
            .get_optional()?
            .ok_or("mls_wrapping_key_missing")?;
        let signed_envelope = |event_id: &[u8; 32]| -> Result<String, &'static str> {
            let event = store
                .get_event(EventId::from_bytes(*event_id))
                .map_err(|_| "message_store_unavailable")?
                .ok_or("message_not_found")?;
            if event.group_id() != group_id {
                return Err("message_not_found");
            }
            Ok(hex_bytes(
                &event.encode().map_err(|_| "message_record_invalid")?,
            ))
        };
        let events = selected
            .iter()
            .map(|message| {
                Ok(EvidenceEvent {
                    event_id: hex_bytes(&message.event_id),
                    kind: "MessageCreated",
                    author_id: message.author_id.to_string(),
                    author_sequence: message.author_sequence,
                    created_at_unix_ms: message.created_at_unix_ms,
                    signed_event_hex: signed_envelope(&message.event_id)?,
                    displayed_text: displayed_message_text(message, &key)?,
                    edit: message
                        .edit
                        .as_ref()
                        .map(|edit| {
                            Ok::<_, &'static str>(EvidenceEdit {
                                event_id: hex_bytes(&edit.event_id),
                                kind: "MessageEdited",
                                signed_event_hex: signed_envelope(&edit.event_id)?,
                            })
                        })
                        .transpose()?,
                })
            })
            .collect::<Result<Vec<_>, &'static str>>()?;
        Ok(EvidenceExport {
            format: EVIDENCE_FORMAT,
            notice: EVIDENCE_NOTICE,
            generated_at_unix_ms,
            exported_by_device_id: local_device_id.to_string(),
            group_id: group_id.to_string(),
            events,
        })
    }

    /// Returns this device's unread message counts for groups that have any.
    pub(crate) fn unread_message_counts(&self) -> Result<Vec<UnreadMessageCount>, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let counts = self
            .store
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?
            .unread_message_counts()
            .map_err(|_| "message_list_unavailable")?;
        Ok(counts
            .into_iter()
            .map(|(group_id, count)| UnreadMessageCount {
                group_id: group_id.to_string(),
                count,
            })
            .collect())
    }

    /// Returns the newest displayable message of each named group that has
    /// one, without marking anything read.
    pub(crate) fn message_previews(
        &self,
        group_ids: &[PeerId],
    ) -> Result<Vec<GroupMessagePreview>, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let latest = {
            let store = self
                .store
                .lock()
                .map_err(|_| "mls_provider_service_unavailable")?;
            group_ids
                .iter()
                .filter_map(|group_id| {
                    store
                        .latest_encrypted_message(*group_id)
                        .map_err(|_| "message_list_unavailable")
                        .transpose()
                })
                .collect::<Result<Vec<_>, _>>()?
        };
        if latest.is_empty() {
            return Ok(Vec::new());
        }
        let key = self
            .wrapping_keys
            .get_optional()?
            .ok_or("mls_wrapping_key_missing")?;
        latest
            .iter()
            .map(|message| {
                Ok(GroupMessagePreview {
                    group_id: message.group_id.to_string(),
                    author_id: message.author_id.to_string(),
                    created_at_unix_ms: message.created_at_unix_ms,
                    text: displayed_message_text(message, &key)?,
                })
            })
            .collect()
    }

    pub(crate) fn acknowledge_messages_shared(
        &self,
        group_id: PeerId,
        peer_id: PeerId,
        author_id: PeerId,
        sequence: u64,
    ) -> Result<(), &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        self.store
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?
            .acknowledge_author_head(group_id, peer_id, author_id, sequence)
            .map_err(|_| "message_delivery_state_unavailable")
    }

    /// Builds the report of this device's gap-free author heads sent after
    /// a completed exchange (ADR-030).
    pub(crate) fn report_heads_request(
        &self,
        group_id: PeerId,
    ) -> Result<SyncRequest, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let mut heads = self
            .store
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?
            .synchronization_summary(group_id)
            .map_err(|_| "synchronization_unavailable")?;
        heads.truncate(MAX_SYNC_AUTHORS);
        Ok(SyncRequest::ReportHeads { group_id, heads })
    }

    /// Records the heads of this device's own events that the peer reported
    /// for every other member it knows.
    pub(crate) fn record_observed_heads(
        &self,
        group_id: PeerId,
        author_id: PeerId,
        peers: &[SyncPeerHead],
    ) -> Result<(), &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        for peer in peers.iter().filter(|peer| peer.peer_id != author_id) {
            store
                .acknowledge_author_head(
                    group_id,
                    peer.peer_id,
                    author_id,
                    peer.contiguous_sequence,
                )
                .map_err(|_| "message_delivery_state_unavailable")?;
        }
        Ok(())
    }

    pub(crate) fn hide_message_locally(
        &self,
        group_id: PeerId,
        event_id: &[u8; 32],
    ) -> Result<(), &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        if !store
            .hide_message_locally(group_id, event_id)
            .map_err(|_| "message_delete_failed")?
        {
            return Err("message_not_found");
        }
        Ok(())
    }

    /// Removes readable copies of messages created before the cutoff in
    /// every group on this device (ADR-035) and returns how many were removed.
    pub(crate) fn hide_messages_created_before(
        &self,
        cutoff_unix_ms: u64,
    ) -> Result<u64, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        store
            .hide_messages_created_before(cutoff_unix_ms)
            .map_err(|_| "message_retention_failed")
    }

    /// Blocks or unblocks one device's messages on this device only and
    /// returns the group's locally blocked devices.
    pub(crate) fn set_device_blocked_locally(
        &self,
        group_id: PeerId,
        device_id: PeerId,
        blocked: bool,
    ) -> Result<Vec<String>, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        if blocked {
            store.block_device_locally(group_id, device_id)
        } else {
            store.unblock_device_locally(group_id, device_id)
        }
        .map_err(|_| "device_block_failed")?;
        blocked_device_ids(&store, group_id)
    }

    /// Reports each author's latest signed event time held for a group. The
    /// time is the author's own signed claim, not presence or a verified clock.
    pub(crate) fn member_activity(
        &self,
        group_id: PeerId,
    ) -> Result<Vec<MemberActivity>, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let store = self
            .store
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        Ok(store
            .latest_author_activity(group_id)
            .map_err(|_| "member_activity_unavailable")?
            .into_iter()
            .map(|(device_id, last_signed_at_unix_ms)| MemberActivity {
                device_id: device_id.to_string(),
                last_signed_at_unix_ms,
            })
            .collect())
    }

    /// Reports devices that signed different events with the same author
    /// sequence in a group. Both signed events were observed, so each entry is
    /// evidence of equivocation by that device.
    pub(crate) fn sequence_conflicts(
        &self,
        group_id: PeerId,
    ) -> Result<Vec<DeviceSequenceConflict>, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let store = self
            .store
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        Ok(store
            .sequence_conflicts(group_id)
            .map_err(|_| "sequence_conflicts_unavailable")?
            .into_iter()
            .map(|conflict| DeviceSequenceConflict {
                device_id: conflict.author_id.to_string(),
                conflicting_sequences: conflict.conflicting_sequences,
                first_sequence: conflict.first_sequence,
            })
            .collect())
    }

    pub(crate) fn blocked_devices(&self, group_id: PeerId) -> Result<Vec<String>, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let store = self
            .store
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        blocked_device_ids(&store, group_id)
    }

    #[cfg(test)]
    fn create_message_at(
        &self,
        group_id: PeerId,
        author: &DeviceIdentity,
        message: &str,
        created_at_unix_ms: u64,
    ) -> Result<SignedEvent, &'static str> {
        let body = MessageBody::new(message, None).map_err(|_| "message_invalid")?;
        self.create_body_at(group_id, author, &body, created_at_unix_ms)
    }

    /// Protects a message body, including any reply reference, as an MLS
    /// application message. A reply must target a message readable here.
    fn create_body_at(
        &self,
        group_id: PeerId,
        author: &DeviceIdentity,
        body: &MessageBody,
        created_at_unix_ms: u64,
    ) -> Result<SignedEvent, &'static str> {
        if let Some(reply_to) = body.reply_to() {
            let store = self
                .store
                .lock()
                .map_err(|_| "mls_provider_service_unavailable")?;
            store
                .materialized_message_author(group_id, reply_to)
                .map_err(|_| "message_store_unavailable")?
                .ok_or("message_not_found")?;
        }
        let encoded = body.encode().map_err(|_| "message_invalid")?;
        self.create_application_event_at(
            group_id,
            author,
            EventKind::MessageCreated,
            &encoded,
            created_at_unix_ms,
            |store, event, encrypted_snapshot, key| {
                let encrypted_body =
                    encrypt_local_message(body.text().as_bytes(), key, event.id().as_bytes())?;
                match body.reply_to() {
                    Some(reply_to) => store.put_reply_message_and_encrypted_mls_provider_snapshot(
                        event,
                        encrypted_snapshot,
                        &encrypted_body,
                        reply_to,
                        false,
                    ),
                    None => store.put_message_and_encrypted_mls_provider_snapshot(
                        event,
                        encrypted_snapshot,
                        &encrypted_body,
                    ),
                }
                .map_err(|_| "message_store_unavailable")?;
                Ok(())
            },
        )
    }

    /// Protects replacement text for one of this device's readable messages
    /// as an MLS application message and stores the signed `MessageEdited`
    /// event with the advanced provider state in one transaction.
    pub(crate) fn edit_message(
        &self,
        group_id: PeerId,
        author: &DeviceIdentity,
        target_event_id: &[u8; 32],
        text: &str,
    ) -> Result<(), &'static str> {
        let created_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .ok_or("system_clock_invalid")?;
        let edit = MessageEdit::new(*target_event_id, text).map_err(|_| "message_invalid")?;
        let encoded = edit.encode().map_err(|_| "message_invalid")?;
        {
            let store = self
                .store
                .lock()
                .map_err(|_| "mls_provider_service_unavailable")?;
            let target_author = store
                .materialized_message_author(group_id, target_event_id)
                .map_err(|_| "message_store_unavailable")?
                .ok_or("message_not_found")?;
            if target_author != author.peer_id() {
                return Err("message_not_own");
            }
        }
        self.create_application_event_at(
            group_id,
            author,
            EventKind::MessageEdited,
            &encoded,
            created_at_unix_ms,
            |store, event, encrypted_snapshot, key| {
                let encrypted_body =
                    encrypt_local_message(text.as_bytes(), key, event.id().as_bytes())?;
                store
                    .put_message_edit_and_encrypted_mls_provider_snapshot(
                        event,
                        encrypted_snapshot,
                        target_event_id,
                        &encrypted_body,
                    )
                    .map_err(|_| "message_store_unavailable")?;
                Ok(())
            },
        )?;
        Ok(())
    }

    /// Protects a group-wide deletion request for one of this device's
    /// readable messages as an MLS application message and stores the signed
    /// `MessageDeleted` tombstone with the advanced provider state in one
    /// transaction, which also removes the local readable copy.
    pub(crate) fn delete_message(
        &self,
        group_id: PeerId,
        author: &DeviceIdentity,
        target_event_id: &[u8; 32],
    ) -> Result<(), &'static str> {
        let created_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .ok_or("system_clock_invalid")?;
        let encoded = MessageDeletion::new(*target_event_id)
            .encode()
            .map_err(|_| "message_invalid")?;
        {
            let store = self
                .store
                .lock()
                .map_err(|_| "mls_provider_service_unavailable")?;
            let target_author = store
                .materialized_message_author(group_id, target_event_id)
                .map_err(|_| "message_store_unavailable")?
                .ok_or("message_not_found")?;
            if target_author != author.peer_id() {
                return Err("message_not_own");
            }
        }
        self.create_application_event_at(
            group_id,
            author,
            EventKind::MessageDeleted,
            &encoded,
            created_at_unix_ms,
            |store, event, encrypted_snapshot, _key| {
                store
                    .put_message_deletion_and_encrypted_mls_provider_snapshot(
                        event,
                        encrypted_snapshot,
                        target_event_id,
                    )
                    .map_err(|_| "message_store_unavailable")?;
                Ok(())
            },
        )?;
        Ok(())
    }

    /// Protects owner-authored display metadata as an MLS application message
    /// and stores the signed `GroupMetadataChanged` event with the advanced
    /// provider state in one transaction.
    pub(crate) fn change_group_metadata(
        &self,
        group_id: PeerId,
        author: &DeviceIdentity,
        metadata: &GroupMetadata,
    ) -> Result<(), &'static str> {
        let created_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .ok_or("system_clock_invalid")?;
        self.change_group_metadata_at(group_id, author, metadata, created_at_unix_ms)
    }

    fn change_group_metadata_at(
        &self,
        group_id: PeerId,
        author: &DeviceIdentity,
        metadata: &GroupMetadata,
        created_at_unix_ms: u64,
    ) -> Result<(), &'static str> {
        let encoded = metadata.encode().map_err(|_| "invalid_group_name")?;
        {
            let store = self
                .store
                .lock()
                .map_err(|_| "mls_provider_service_unavailable")?;
            let joined = store
                .joined_groups()
                .map_err(|_| "message_store_unavailable")?;
            if joined.iter().any(|group| group.group_id == group_id) {
                return Err("group_not_owned");
            }
        }
        self.create_application_event_at(
            group_id,
            author,
            EventKind::GroupMetadataChanged,
            &encoded,
            created_at_unix_ms,
            |store, event, encrypted_snapshot, _key| {
                store
                    .put_group_metadata_and_encrypted_mls_provider_snapshot(
                        event,
                        encrypted_snapshot,
                        metadata,
                    )
                    .map_err(|_| "message_store_unavailable")?;
                Ok(())
            },
        )?;
        Ok(())
    }

    /// Grants or withdraws one current member device's permission to request
    /// owner-issued invitations, storing the signed `InvitePermissionChanged`
    /// event with the advanced provider state in one transaction (ADR-036).
    pub(crate) fn change_invite_permission(
        &self,
        group_id: PeerId,
        author: &DeviceIdentity,
        target_device_id: PeerId,
        granted: bool,
    ) -> Result<Vec<PeerId>, &'static str> {
        let created_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .ok_or("system_clock_invalid")?;
        self.change_invite_permission_at(
            group_id,
            author,
            target_device_id,
            granted,
            created_at_unix_ms,
        )
    }

    fn change_invite_permission_at(
        &self,
        group_id: PeerId,
        author: &DeviceIdentity,
        target_device_id: PeerId,
        granted: bool,
        created_at_unix_ms: u64,
    ) -> Result<Vec<PeerId>, &'static str> {
        if target_device_id == author.peer_id() {
            return Err("invite_permission_owner");
        }
        {
            let store = self
                .store
                .lock()
                .map_err(|_| "mls_provider_service_unavailable")?;
            let joined = store
                .joined_groups()
                .map_err(|_| "message_store_unavailable")?;
            if joined.iter().any(|group| group.group_id == group_id) {
                return Err("group_not_owned");
            }
            let current = store
                .has_invite_permission(group_id, target_device_id)
                .map_err(|_| "message_store_unavailable")?;
            if current == granted {
                return store
                    .invite_permitted_devices(group_id)
                    .map_err(|_| "message_store_unavailable");
            }
        }
        let target = target_device_id.to_string();
        if !self
            .group_members(group_id)?
            .iter()
            .any(|member| member.device_id == target)
        {
            return Err("member_not_found");
        }
        let permission = InvitePermission::new(target_device_id, granted);
        let encoded = permission
            .encode()
            .map_err(|_| "invite_permission_invalid")?;
        self.create_application_event_at(
            group_id,
            author,
            EventKind::InvitePermissionChanged,
            &encoded,
            created_at_unix_ms,
            |store, event, encrypted_snapshot, _key| {
                store
                    .put_invite_permission_and_encrypted_mls_provider_snapshot(
                        event,
                        encrypted_snapshot,
                        &permission,
                    )
                    .map_err(|_| "message_store_unavailable")?;
                Ok(())
            },
        )?;
        self.invite_permitted_devices(group_id)
    }

    /// Returns member devices currently permitted to request invitations.
    pub(crate) fn invite_permitted_devices(
        &self,
        group_id: PeerId,
    ) -> Result<Vec<PeerId>, &'static str> {
        let store = self
            .store
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        store
            .invite_permitted_devices(group_id)
            .map_err(|_| "message_store_unavailable")
    }

    /// Whether an authenticated peer is a current, non-removed member device
    /// that holds invite permission in this owner's own event state
    /// (ADR-036).
    pub(crate) fn may_request_invitation(
        &self,
        group_id: PeerId,
        authenticated_peer: PeerId,
    ) -> Result<bool, &'static str> {
        let store = self
            .store
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        if store
            .is_removed_mls_member(group_id, authenticated_peer)
            .map_err(|_| "message_store_unavailable")?
        {
            return Ok(false);
        }
        store
            .has_invite_permission(group_id, authenticated_peer)
            .map_err(|_| "message_store_unavailable")
    }

    /// Returns authenticated group names from applied metadata changes.
    pub(crate) fn current_group_names(&self) -> Result<Vec<(PeerId, String)>, &'static str> {
        let store = self
            .store
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        store
            .current_group_names()
            .map_err(|_| "message_store_unavailable")
    }

    /// Returns authenticated group icons from applied metadata changes.
    pub(crate) fn current_group_icons(&self) -> Result<Vec<(PeerId, u8)>, &'static str> {
        let store = self
            .store
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        store
            .current_group_icons()
            .map_err(|_| "message_store_unavailable")
    }

    fn create_application_event_at(
        &self,
        group_id: PeerId,
        author: &DeviceIdentity,
        kind: EventKind,
        plaintext: &[u8],
        created_at_unix_ms: u64,
        persist: impl FnOnce(
            &mut EventStore,
            &SignedEvent,
            &[u8],
            &[u8; WRAPPING_KEY_BYTES],
        ) -> Result<(), &'static str>,
    ) -> Result<SignedEvent, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let mut provider = self
            .provider
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let previous = provider
            .snapshot()
            .map_err(|_| "mls_provider_snapshot_invalid")?;
        let result = (|| {
            let mut store = self
                .store
                .lock()
                .map_err(|_| "mls_provider_service_unavailable")?;
            let mut group = MlsGroup::load(
                provider.storage(),
                &GroupId::from_slice(&group_id.to_bytes()),
            )
            .map_err(|_| "mls_group_storage_unavailable")?
            .ok_or("mls_joined_group_missing")?;
            validate_group_profile(&group).map_err(|_| "mls_group_storage_unavailable")?;
            let own_leaf = group.own_leaf_node().ok_or("mls_group_owner_missing")?;
            let own_device = device_id_from_credential(own_leaf.credential())
                .map_err(|_| "mls_group_owner_invalid")?;
            if own_device != author.peer_id() {
                return Err("mls_group_author_mismatch");
            }
            let signer = SignatureKeyPair::read(
                provider.storage(),
                own_leaf.signature_key().as_slice(),
                CIPHERSUITE.signature_algorithm(),
            )
            .ok_or("mls_group_storage_unavailable")?;
            let protected = group
                .create_message(&*provider, &signer, plaintext)
                .map_err(|_| "mls_message_creation_failed")?
                .to_bytes()
                .map_err(|_| "mls_message_creation_failed")?;
            if protected.is_empty() || protected.len() > MAX_MLS_WIRE_BYTES {
                return Err("mls_message_creation_failed");
            }
            let (author_sequence, causal_parents) =
                next_event_position(&store, group_id, author.peer_id())
                    .map_err(|_| "message_store_unavailable")?;
            let event = SignedEvent::create(
                author,
                EventSpec {
                    group_id,
                    author_sequence,
                    causal_parents: &causal_parents,
                    created_at_unix_ms,
                    kind,
                    protected_payload: &protected,
                },
            )
            .map_err(|_| "message_creation_failed")?;
            let snapshot = provider
                .snapshot()
                .map_err(|_| "mls_provider_snapshot_invalid")?;
            let key = self.load_or_create_wrapping_key()?;
            let encrypted = encrypt_snapshot(&snapshot, &key)?;
            persist(&mut store, &event, &encrypted, &key)?;
            Ok(event)
        })();
        if result.is_err() {
            *provider = ProfileProvider::from_snapshot(&previous)
                .map_err(|_| "mls_provider_snapshot_invalid")?;
        }
        result
    }

    pub(crate) fn answer_sync_request(
        &self,
        authenticated_peer: PeerId,
        request: &SyncRequest,
    ) -> SyncResponse {
        let Ok(_operation) = self.operations.lock() else {
            return SyncResponse::Rejected {
                reason: SyncRejectReason::Busy,
            };
        };
        let Ok(mut provider) = self.provider.lock() else {
            return SyncResponse::Rejected {
                reason: SyncRejectReason::Busy,
            };
        };
        let group_id = sync_request_group_id(request);
        let mls_group_id = GroupId::from_slice(&group_id.to_bytes());
        let Ok(Some(group)) = MlsGroup::load(provider.storage(), &mls_group_id) else {
            return SyncResponse::Rejected {
                reason: SyncRejectReason::Unauthorized,
            };
        };
        let authorized = group.members().any(|member| {
            device_id_from_credential(&member.credential)
                .is_ok_and(|device_id| device_id == authenticated_peer)
        });
        if !authorized {
            return SyncResponse::Rejected {
                reason: SyncRejectReason::Unauthorized,
            };
        }
        let membership = if matches!(request, SyncRequest::ReportHeads { .. }) {
            let Some(own_leaf) = group.own_leaf_node() else {
                return SyncResponse::Rejected {
                    reason: SyncRejectReason::Busy,
                };
            };
            let (Ok(local_device_id), Ok(members)) = (
                device_id_from_credential(own_leaf.credential()),
                group
                    .members()
                    .map(|member| device_id_from_credential(&member.credential))
                    .collect::<Result<Vec<_>, _>>(),
            ) else {
                return SyncResponse::Rejected {
                    reason: SyncRejectReason::Busy,
                };
            };
            Some((local_device_id, members))
        } else {
            None
        };
        drop(group);
        let Ok(mut store) = self.store.lock() else {
            return SyncResponse::Rejected {
                reason: SyncRejectReason::Busy,
            };
        };
        // A member device serves only the pull exchanges; uploads and head
        // reports stay with the owner (ADR-040).
        if matches!(
            request,
            SyncRequest::PushEvents { .. } | SyncRequest::ReportHeads { .. }
        ) {
            match store.joined_groups() {
                Ok(joined) if joined.iter().any(|joined| joined.group_id == group_id) => {
                    return SyncResponse::Rejected {
                        reason: SyncRejectReason::Unauthorized,
                    };
                }
                Ok(_) => {}
                Err(_) => {
                    return SyncResponse::Rejected {
                        reason: SyncRejectReason::Busy,
                    };
                }
            }
        }
        if let Some((local_device_id, members)) = membership {
            return record_reported_heads(
                &mut store,
                local_device_id,
                authenticated_peer,
                &members,
                request,
            )
            .unwrap_or_else(|error| SyncResponse::Rejected {
                reason: match error {
                    SynchronizationError::Protocol(_) => SyncRejectReason::InvalidRequest,
                    _ => SyncRejectReason::Busy,
                },
            });
        }
        if let SyncRequest::PushEvents { group_id, .. } = request {
            return match accept_pushed_events(&mut store, authenticated_peer, request) {
                Ok(outcome) => {
                    if self
                        .materialize_pending_messages(&mut provider, &mut store, *group_id)
                        .is_err()
                    {
                        return SyncResponse::Rejected {
                            reason: SyncRejectReason::Busy,
                        };
                    }
                    SyncResponse::EventsAccepted {
                        group_id: *group_id,
                        inserted: u16::try_from(outcome.inserted).unwrap_or(u16::MAX),
                    }
                }
                Err(error) => SyncResponse::Rejected {
                    reason: match error {
                        SynchronizationError::Protocol(_)
                        | SynchronizationError::PushedAuthorMismatch
                        | SynchronizationError::UnsupportedPushedEvent => {
                            SyncRejectReason::InvalidRequest
                        }
                        _ => SyncRejectReason::Busy,
                    },
                },
            };
        }
        build_authorized_response(&store, request).unwrap_or_else(|error| SyncResponse::Rejected {
            reason: match error {
                SynchronizationError::Protocol(_) => SyncRejectReason::InvalidRequest,
                _ => SyncRejectReason::Busy,
            },
        })
    }

    pub(crate) fn next_push_request(
        &self,
        group_id: PeerId,
        author_id: PeerId,
        after_sequence: u64,
    ) -> Result<Option<(SyncRequest, u64)>, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "synchronization_unavailable")?;
        let store = self
            .store
            .lock()
            .map_err(|_| "synchronization_unavailable")?;
        let event_ids = store
            .event_ids_after(group_id, author_id, after_sequence, MAX_SYNC_BATCH_ITEMS)
            .map_err(|_| "synchronization_unavailable")?;
        if event_ids.is_empty() {
            return Ok(None);
        }

        let mut encoded_events = Vec::new();
        let mut total_bytes = 0usize;
        let mut last_sequence = after_sequence;
        for event_id in event_ids {
            let Some(event) = store
                .get_event(event_id)
                .map_err(|_| "synchronization_unavailable")?
            else {
                continue;
            };
            if !matches!(
                event.kind(),
                EventKind::MessageCreated | EventKind::MessageEdited | EventKind::MessageDeleted
            ) {
                last_sequence = event.author_sequence();
                continue;
            }
            let encoded = event.encode().map_err(|_| "synchronization_unavailable")?;
            let Some(next_total) = total_bytes.checked_add(encoded.len()) else {
                break;
            };
            if next_total > MAX_SYNC_RESPONSE_BYTES {
                break;
            }
            total_bytes = next_total;
            last_sequence = event.author_sequence();
            encoded_events.push(encoded);
        }
        if encoded_events.is_empty() {
            return Ok(None);
        }
        Ok(Some((
            SyncRequest::PushEvents {
                group_id,
                encoded_events,
            },
            last_sequence,
        )))
    }

    pub(crate) fn advance_pull_session(
        &self,
        session: &mut PullSession,
        response: &SyncResponse,
    ) -> Result<SessionProgress, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "synchronization_unavailable")?;
        let mut provider = self
            .provider
            .lock()
            .map_err(|_| "synchronization_unavailable")?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| "synchronization_unavailable")?;
        let progress = session
            .handle_response(&mut store, response)
            .map_err(|_| "synchronization_failed")?;
        self.apply_pending_group_commits(&mut provider, &mut store, session.group_id())?;
        self.materialize_pending_messages(&mut provider, &mut store, session.group_id())?;
        Ok(progress)
    }

    fn apply_pending_group_commits(
        &self,
        provider: &mut ProfileProvider,
        store: &mut EventStore,
        group_id: PeerId,
    ) -> Result<(), &'static str> {
        loop {
            let events = store
                .unapplied_mls_commit_events(group_id, charp2p_store::MAX_SYNC_BATCH_EVENTS)
                .map_err(|_| "mls_group_storage_unavailable")?;
            if events.is_empty() {
                return Ok(());
            }
            let mut applied = 0usize;
            for event in events {
                let previous = provider
                    .snapshot()
                    .map_err(|_| "mls_provider_snapshot_invalid")?;
                match self.apply_group_commit(provider, store, group_id, &event) {
                    Ok(true) => applied += 1,
                    Ok(false) => {}
                    Err(ApplyGroupCommitError::Unreadable) => {
                        *provider = ProfileProvider::from_snapshot(&previous)
                            .map_err(|_| "mls_provider_snapshot_invalid")?;
                    }
                    Err(ApplyGroupCommitError::Unavailable(error)) => {
                        *provider = ProfileProvider::from_snapshot(&previous)
                            .map_err(|_| "mls_provider_snapshot_invalid")?;
                        return Err(error);
                    }
                }
            }
            if applied == 0 {
                return Ok(());
            }
        }
    }

    fn apply_group_commit(
        &self,
        provider: &mut ProfileProvider,
        store: &mut EventStore,
        group_id: PeerId,
        event: &SignedEvent,
    ) -> Result<bool, ApplyGroupCommitError> {
        // Only the pinned owner device commits membership changes; a commit
        // from any other member stays unapplied even if MLS would accept it.
        if !is_joined_group_owner(store, group_id, event.author_id())
            .map_err(ApplyGroupCommitError::Unavailable)?
        {
            return Err(ApplyGroupCommitError::Unreadable);
        }
        let mut group = MlsGroup::load(
            provider.storage(),
            &GroupId::from_slice(&group_id.to_bytes()),
        )
        .map_err(|_| ApplyGroupCommitError::Unavailable("mls_group_storage_unavailable"))?
        .ok_or(ApplyGroupCommitError::Unavailable(
            "mls_joined_group_missing",
        ))?;
        validate_group_profile(&group).map_err(|_| ApplyGroupCommitError::Unreadable)?;
        let message = decode_profile_message(event.protected_payload())
            .map_err(|_| ApplyGroupCommitError::Unreadable)?;
        let protocol: ProtocolMessage = message
            .try_into_protocol_message()
            .map_err(|_| ApplyGroupCommitError::Unreadable)?;
        if protocol.content_type() != ContentType::Commit || protocol.group_id() != group.group_id()
        {
            return Err(ApplyGroupCommitError::Unreadable);
        }
        if protocol.epoch() > group.epoch() {
            return Ok(false);
        }
        if protocol.epoch() == group.epoch() {
            let processed = group
                .process_message(&*provider, protocol)
                .map_err(|_| ApplyGroupCommitError::Unreadable)?;
            let sender = device_id_from_credential(processed.credential())
                .map_err(|_| ApplyGroupCommitError::Unreadable)?;
            if sender != event.author_id() {
                return Err(ApplyGroupCommitError::Unreadable);
            }
            let ProcessedMessageContent::StagedCommitMessage(staged) = processed.into_content()
            else {
                return Err(ApplyGroupCommitError::Unreadable);
            };
            validate_staged_commit_profile(&staged)
                .map_err(|_| ApplyGroupCommitError::Unreadable)?;
            // A key refresh may only replace the owner's path secrets
            // (ADR-045).
            if event.kind() == EventKind::KeyEpochAdvanced {
                validate_key_refresh_commit(&staged)
                    .map_err(|_| ApplyGroupCommitError::Unreadable)?;
            }
            group
                .merge_staged_commit(&*provider, *staged)
                .map_err(|_| ApplyGroupCommitError::Unreadable)?;
            validate_group_profile(&group).map_err(|_| ApplyGroupCommitError::Unreadable)?;
        }
        let snapshot = provider
            .snapshot()
            .map_err(|_| ApplyGroupCommitError::Unavailable("mls_provider_snapshot_invalid"))?;
        let key = self
            .load_or_create_wrapping_key()
            .map_err(ApplyGroupCommitError::Unavailable)?;
        let encrypted =
            encrypt_snapshot(&snapshot, &key).map_err(ApplyGroupCommitError::Unavailable)?;
        store
            .put_applied_mls_event_and_encrypted_provider_snapshot(event, &encrypted)
            .map_err(|_| ApplyGroupCommitError::Unavailable("mls_group_storage_unavailable"))?;
        Ok(true)
    }

    fn materialize_pending_messages(
        &self,
        provider: &mut ProfileProvider,
        store: &mut EventStore,
        group_id: PeerId,
    ) -> Result<(), &'static str> {
        loop {
            let events = store
                .unmaterialized_message_events(group_id, charp2p_store::MAX_SYNC_BATCH_EVENTS)
                .map_err(|_| "message_store_unavailable")?;
            if events.is_empty() {
                return Ok(());
            }
            let mut materialized = 0usize;
            for event in events {
                let previous = provider
                    .snapshot()
                    .map_err(|_| "mls_provider_snapshot_invalid")?;
                match self.materialize_message(provider, store, group_id, &event) {
                    Ok(()) => materialized += 1,
                    Err(MaterializeMessageError::Unreadable) => {
                        *provider = ProfileProvider::from_snapshot(&previous)
                            .map_err(|_| "mls_provider_snapshot_invalid")?;
                    }
                    Err(MaterializeMessageError::Unavailable(error)) => {
                        *provider = ProfileProvider::from_snapshot(&previous)
                            .map_err(|_| "mls_provider_snapshot_invalid")?;
                        return Err(error);
                    }
                }
            }
            if materialized == 0 {
                return Ok(());
            }
        }
    }

    fn materialize_message(
        &self,
        provider: &mut ProfileProvider,
        store: &mut EventStore,
        group_id: PeerId,
        event: &SignedEvent,
    ) -> Result<(), MaterializeMessageError> {
        if matches!(
            event.kind(),
            EventKind::GroupMetadataChanged | EventKind::InvitePermissionChanged
        ) && !is_joined_group_owner(store, group_id, event.author_id())
            .map_err(MaterializeMessageError::Unavailable)?
        {
            return Err(MaterializeMessageError::Unreadable);
        }
        let mut group = MlsGroup::load(
            provider.storage(),
            &GroupId::from_slice(&group_id.to_bytes()),
        )
        .map_err(|_| MaterializeMessageError::Unavailable("mls_group_storage_unavailable"))?
        .ok_or(MaterializeMessageError::Unavailable(
            "mls_joined_group_missing",
        ))?;
        validate_group_profile(&group).map_err(|_| MaterializeMessageError::Unreadable)?;
        let message = decode_profile_message(event.protected_payload())
            .map_err(|_| MaterializeMessageError::Unreadable)?;
        let protocol: ProtocolMessage = message
            .try_into_protocol_message()
            .map_err(|_| MaterializeMessageError::Unreadable)?;
        let processed = group
            .process_message(&*provider, protocol)
            .map_err(|_| MaterializeMessageError::Unreadable)?;
        let sender = device_id_from_credential(processed.credential())
            .map_err(|_| MaterializeMessageError::Unreadable)?;
        if sender != event.author_id() {
            return Err(MaterializeMessageError::Unreadable);
        }
        let ProcessedMessageContent::ApplicationMessage(application) = processed.into_content()
        else {
            return Err(MaterializeMessageError::Unreadable);
        };
        let plaintext = Zeroizing::new(application.into_bytes());
        let edit = if event.kind() == EventKind::MessageEdited {
            Some(MessageEdit::decode(&plaintext).map_err(|_| MaterializeMessageError::Unreadable)?)
        } else {
            None
        };
        let deletion = if event.kind() == EventKind::MessageDeleted {
            Some(
                MessageDeletion::decode(&plaintext)
                    .map_err(|_| MaterializeMessageError::Unreadable)?,
            )
        } else {
            None
        };
        let metadata = if event.kind() == EventKind::GroupMetadataChanged {
            Some(
                GroupMetadata::decode(&plaintext)
                    .map_err(|_| MaterializeMessageError::Unreadable)?,
            )
        } else {
            None
        };
        let permission = if event.kind() == EventKind::InvitePermissionChanged {
            Some(
                InvitePermission::decode(&plaintext)
                    .map_err(|_| MaterializeMessageError::Unreadable)?,
            )
        } else {
            None
        };
        let body = if edit.is_none()
            && deletion.is_none()
            && metadata.is_none()
            && permission.is_none()
        {
            Some(MessageBody::decode(&plaintext).map_err(|_| MaterializeMessageError::Unreadable)?)
        } else {
            None
        };
        let snapshot = provider
            .snapshot()
            .map_err(|_| MaterializeMessageError::Unavailable("mls_provider_snapshot_invalid"))?;
        let key = self
            .load_or_create_wrapping_key()
            .map_err(MaterializeMessageError::Unavailable)?;
        let encrypted_snapshot =
            encrypt_snapshot(&snapshot, &key).map_err(MaterializeMessageError::Unavailable)?;
        if let Some(metadata) = metadata {
            store
                .put_group_metadata_and_encrypted_mls_provider_snapshot(
                    event,
                    &encrypted_snapshot,
                    &metadata,
                )
                .map_err(|_| MaterializeMessageError::Unavailable("message_store_unavailable"))?;
            return Ok(());
        }
        if let Some(permission) = permission {
            store
                .put_invite_permission_and_encrypted_mls_provider_snapshot(
                    event,
                    &encrypted_snapshot,
                    &permission,
                )
                .map_err(|_| MaterializeMessageError::Unavailable("message_store_unavailable"))?;
            return Ok(());
        }
        if let Some(deletion) = deletion {
            store
                .put_message_deletion_and_encrypted_mls_provider_snapshot(
                    event,
                    &encrypted_snapshot,
                    deletion.target_event_id(),
                )
                .map_err(|_| MaterializeMessageError::Unavailable("message_store_unavailable"))?;
            return Ok(());
        }
        if let Some(edit) = edit {
            let encrypted_body =
                encrypt_local_message(edit.text().as_bytes(), &key, event.id().as_bytes())
                    .map_err(MaterializeMessageError::Unavailable)?;
            store
                .put_message_edit_and_encrypted_mls_provider_snapshot(
                    event,
                    &encrypted_snapshot,
                    edit.target_event_id(),
                    &encrypted_body,
                )
                .map_err(|_| MaterializeMessageError::Unavailable("message_store_unavailable"))?;
            return Ok(());
        }
        let body = body.ok_or(MaterializeMessageError::Unreadable)?;
        let encrypted_body =
            encrypt_local_message(body.text().as_bytes(), &key, event.id().as_bytes())
                .map_err(MaterializeMessageError::Unavailable)?;
        match body.reply_to() {
            Some(reply_to) => store.put_reply_message_and_encrypted_mls_provider_snapshot(
                event,
                &encrypted_snapshot,
                &encrypted_body,
                reply_to,
                true,
            ),
            None => store.put_received_message_and_encrypted_mls_provider_snapshot(
                event,
                &encrypted_snapshot,
                &encrypted_body,
            ),
        }
        .map_err(|_| MaterializeMessageError::Unavailable("message_store_unavailable"))?;
        Ok(())
    }

    /// Adds one transport-authenticated device, publishes the resulting MLS
    /// Commit as a signed event, and persists the advanced MLS state in the
    /// same SQLite transaction before returning its Welcome. Only when this
    /// call made a new admission, it then re-authors the current group metadata in the
    /// joiner's first epoch. A joiner cannot decrypt metadata changes from
    /// before its Welcome, so this is how it learns the current name and icon.
    /// A single-use invitation is consumed by the admission (ADR-042).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn admit_member_sharing_metadata(
        &self,
        group_id: PeerId,
        owner_identity: &DeviceIdentity,
        authenticated_peer: PeerId,
        encoded_key_package: &[u8],
        single_use_invitation: Option<InvitationId>,
        local_group_name: &str,
        icon: u8,
    ) -> Result<JoinResponse, MemberAdmissionError> {
        let created_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .ok_or(MemberAdmissionError::Unavailable)?;
        self.admit_member_sharing_metadata_at(
            group_id,
            owner_identity,
            authenticated_peer,
            encoded_key_package,
            single_use_invitation,
            local_group_name,
            icon,
            created_at_unix_ms,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn admit_member_sharing_metadata_at(
        &self,
        group_id: PeerId,
        owner_identity: &DeviceIdentity,
        authenticated_peer: PeerId,
        encoded_key_package: &[u8],
        single_use_invitation: Option<InvitationId>,
        local_group_name: &str,
        icon: u8,
        created_at_unix_ms: u64,
    ) -> Result<JoinResponse, MemberAdmissionError> {
        let (response, admitted) = self.admit_member_once_at(
            group_id,
            owner_identity,
            authenticated_peer,
            encoded_key_package,
            single_use_invitation,
            created_at_unix_ms,
        )?;
        if admitted {
            // The admission is already durable, so a failure here only leaves
            // the joiner with its invitation-time name until the next rename.
            let _ = self.share_current_metadata_at(
                group_id,
                owner_identity,
                local_group_name,
                icon,
                created_at_unix_ms,
            );
        }
        Ok(response)
    }

    /// Shares a changed icon with members, keeping the owner's current name.
    pub(crate) fn share_current_metadata(
        &self,
        group_id: PeerId,
        owner_identity: &DeviceIdentity,
        local_group_name: &str,
        icon: u8,
    ) -> Result<(), &'static str> {
        let created_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .ok_or("system_clock_invalid")?;
        self.share_current_metadata_at(
            group_id,
            owner_identity,
            local_group_name,
            icon,
            created_at_unix_ms,
        )
    }

    /// Authors the owner's current name (latest applied rename, else the
    /// local name) and icon as a `GroupMetadataChanged` event.
    fn share_current_metadata_at(
        &self,
        group_id: PeerId,
        owner_identity: &DeviceIdentity,
        local_group_name: &str,
        icon: u8,
        created_at_unix_ms: u64,
    ) -> Result<(), &'static str> {
        let group_name = self
            .current_group_names()?
            .into_iter()
            .find(|(candidate, _)| *candidate == group_id)
            .map(|(_, name)| name)
            .unwrap_or_else(|| local_group_name.to_owned());
        let metadata = GroupMetadata::new(&group_name)
            .and_then(|metadata| metadata.with_icon(icon))
            .map_err(|_| "invalid_group_name")?;
        self.change_group_metadata_at(group_id, owner_identity, &metadata, created_at_unix_ms)
    }

    #[cfg(test)]
    fn admit_member_at(
        &self,
        group_id: PeerId,
        owner_identity: &DeviceIdentity,
        authenticated_peer: PeerId,
        encoded_key_package: &[u8],
        created_at_unix_ms: u64,
    ) -> Result<JoinResponse, MemberAdmissionError> {
        self.admit_member_once_at(
            group_id,
            owner_identity,
            authenticated_peer,
            encoded_key_package,
            None,
            created_at_unix_ms,
        )
        .map(|(response, _)| response)
    }

    /// Returns the Welcome response and whether this call admitted the
    /// device, as opposed to replaying a stored admission for a retry.
    /// Only the consuming device's exact retry passes a consumed single-use
    /// invitation; every other device, including a concurrent loser of the
    /// consuming transaction, is answered `unauthorized` (ADR-042).
    fn admit_member_once_at(
        &self,
        group_id: PeerId,
        owner_identity: &DeviceIdentity,
        authenticated_peer: PeerId,
        encoded_key_package: &[u8],
        single_use_invitation: Option<InvitationId>,
        created_at_unix_ms: u64,
    ) -> Result<(JoinResponse, bool), MemberAdmissionError> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| MemberAdmissionError::Unavailable)?;
        let mut provider = self
            .provider
            .lock()
            .map_err(|_| MemberAdmissionError::Unavailable)?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| MemberAdmissionError::Unavailable)?;
        if store
            .is_removed_mls_member(group_id, authenticated_peer)
            .map_err(|_| MemberAdmissionError::Unavailable)?
        {
            return Err(MemberAdmissionError::Unauthorized);
        }
        let request_hash = join_request_hash(encoded_key_package);
        if let Some(admission) = store
            .mls_join_admission(group_id, authenticated_peer)
            .map_err(|_| MemberAdmissionError::Unavailable)?
        {
            if !bool::from(admission.request_hash.ct_eq(&request_hash)) {
                return Err(MemberAdmissionError::Unauthorized);
            }
            let key = self
                .wrapping_keys
                .get_optional()
                .map_err(|_| MemberAdmissionError::Unavailable)?
                .ok_or(MemberAdmissionError::Unavailable)?;
            let encoded = decrypt_join_response(
                &admission.encrypted_response,
                &key,
                group_id,
                authenticated_peer,
                &request_hash,
            )
            .map_err(|_| MemberAdmissionError::Unavailable)?;
            let response =
                JoinResponse::decode(&encoded).map_err(|_| MemberAdmissionError::Unavailable)?;
            if response.welcome().is_none() {
                return Err(MemberAdmissionError::Unavailable);
            }
            return Ok((response, false));
        }
        if let Some(invitation_id) = single_use_invitation {
            if store
                .single_use_invitation_consumer(group_id, invitation_id)
                .map_err(|_| MemberAdmissionError::Unavailable)?
                .is_some()
            {
                return Err(MemberAdmissionError::Unauthorized);
            }
        }
        let previous = provider
            .snapshot()
            .map_err(|_| MemberAdmissionError::Unavailable)?;
        let result = (|| {
            let mls_group_id = GroupId::from_slice(&group_id.to_bytes());
            let mut group = MlsGroup::load(provider.storage(), &mls_group_id)
                .map_err(|_| MemberAdmissionError::Unavailable)?
                .ok_or(MemberAdmissionError::Unavailable)?;
            validate_owner_group(&group, group_id, owner_identity.peer_id())
                .map_err(|_| MemberAdmissionError::Unavailable)?;
            for member in group.members() {
                let member_id = device_id_from_credential(&member.credential)
                    .map_err(|_| MemberAdmissionError::Unavailable)?;
                if member_id == authenticated_peer {
                    return Err(MemberAdmissionError::Unauthorized);
                }
            }
            let own_signature_key = group
                .own_leaf_node()
                .ok_or(MemberAdmissionError::Unavailable)?
                .signature_key();
            let signer = SignatureKeyPair::read(
                provider.storage(),
                own_signature_key.as_slice(),
                CIPHERSUITE.signature_algorithm(),
            )
            .ok_or(MemberAdmissionError::Unavailable)?;
            let (author_sequence, causal_parents) =
                next_event_position(&store, group_id, owner_identity.peer_id())?;
            let admission = prepare_profile_member_admission(
                &mut group,
                &*provider,
                &signer,
                encoded_key_package,
                authenticated_peer,
            )
            .map_err(map_preparation_error)?;
            let response = JoinResponse::accepted(admission.welcome().to_vec())
                .map_err(|_| MemberAdmissionError::Unavailable)?;
            let encoded_response = response
                .encode()
                .map_err(|_| MemberAdmissionError::Unavailable)?;
            let event = SignedEvent::create(
                owner_identity,
                EventSpec {
                    group_id,
                    author_sequence,
                    causal_parents: &causal_parents,
                    created_at_unix_ms,
                    kind: EventKind::MemberAdded,
                    protected_payload: admission.commit(),
                },
            )
            .map_err(|_| MemberAdmissionError::Unavailable)?;
            merge_prepared_member_admission(&mut group, &*provider)
                .map_err(|_| MemberAdmissionError::Unavailable)?;
            let snapshot = provider
                .snapshot()
                .map_err(|_| MemberAdmissionError::Unavailable)?;
            let key = self
                .load_or_create_wrapping_key()
                .map_err(|_| MemberAdmissionError::Unavailable)?;
            let encrypted =
                encrypt_snapshot(&snapshot, &key).map_err(|_| MemberAdmissionError::Unavailable)?;
            let encrypted_response = encrypt_join_response(
                &encoded_response,
                &key,
                group_id,
                authenticated_peer,
                &request_hash,
            )
            .map_err(|_| MemberAdmissionError::Unavailable)?;
            store
                .put_mls_join_admission(
                    &event,
                    &encrypted,
                    authenticated_peer,
                    &request_hash,
                    &encrypted_response,
                    single_use_invitation,
                )
                .map_err(|error| match error {
                    StoreError::InvitationConsumed => MemberAdmissionError::Unauthorized,
                    _ => MemberAdmissionError::Unavailable,
                })?;
            Ok((response, true))
        })();

        if result.is_err() {
            *provider = ProfileProvider::from_snapshot(&previous)
                .map_err(|_| MemberAdmissionError::Unavailable)?;
        }
        result
    }

    /// Creates or reuses the durable one-time KeyPackage for a pending join.
    pub(crate) fn prepare_join_request(
        &self,
        device_id: PeerId,
        invitation: &Invitation,
    ) -> Result<JoinRequest, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let mut provider = self
            .provider
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let group_id = invitation.group_id();
        let mls_group_id = GroupId::from_slice(&group_id.to_bytes());
        if MlsGroup::load(provider.storage(), &mls_group_id)
            .map_err(|_| "mls_group_storage_unavailable")?
            .is_some()
        {
            return Err("mls_group_already_joined");
        }
        if let Some(encoded) = store
            .pending_mls_join_key_package(group_id)
            .map_err(|_| "mls_provider_store_unavailable")?
        {
            validate_profile_key_package(&*provider, &encoded, device_id)
                .map_err(|_| "mls_pending_join_invalid")?;
            return JoinRequest::from_invitation(invitation, encoded)
                .map_err(|_| "mls_pending_join_invalid");
        }

        let previous = provider
            .snapshot()
            .map_err(|_| "mls_provider_snapshot_invalid")?;
        let result = (|| {
            let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
                .map_err(|_| "mls_key_package_creation_failed")?;
            signer
                .store(provider.storage())
                .map_err(|_| "mls_group_storage_unavailable")?;
            let credential = CredentialWithKey {
                credential: device_credential(device_id).into(),
                signature_key: signer.public().into(),
            };
            let key_package =
                prepare_profile_key_package(&*provider, &signer, credential, device_id)
                    .map_err(|_| "mls_key_package_creation_failed")?;
            let encoded = key_package.encoded().to_vec();
            let request = key_package
                .into_join_request(invitation)
                .map_err(|_| "mls_key_package_creation_failed")?;
            let snapshot = provider
                .snapshot()
                .map_err(|_| "mls_provider_snapshot_invalid")?;
            let key = self.load_or_create_wrapping_key()?;
            let encrypted = encrypt_snapshot(&snapshot, &key)?;
            store
                .put_pending_mls_join_and_encrypted_mls_provider_snapshot(
                    group_id, &encoded, &encrypted,
                )
                .map_err(|_| "mls_provider_store_unavailable")?;
            Ok(request)
        })();
        if result.is_err() {
            *provider = ProfileProvider::from_snapshot(&previous)
                .map_err(|_| "mls_provider_snapshot_invalid")?;
        }
        result
    }

    /// Validates and persists the Welcome for a pending join, then removes the
    /// retained public KeyPackage in the same transaction as the new provider
    /// state.
    pub(crate) fn complete_join(
        &self,
        group_id: PeerId,
        encoded_welcome: &[u8],
    ) -> Result<(), &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let mut provider = self
            .provider
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        if store
            .pending_mls_join_key_package(group_id)
            .map_err(|_| "mls_provider_store_unavailable")?
            .is_none()
        {
            return Err("mls_pending_join_missing");
        }
        let previous = provider
            .snapshot()
            .map_err(|_| "mls_provider_snapshot_invalid")?;
        let result = (|| {
            let staged = stage_profile_welcome(&*provider, encoded_welcome)
                .map_err(|_| "mls_welcome_invalid")?;
            let group = staged
                .into_group(&*provider)
                .map_err(|_| "mls_welcome_invalid")?;
            validate_group_profile(&group).map_err(|_| "mls_welcome_invalid")?;
            if group.group_id().as_slice() != group_id.to_bytes() {
                return Err("mls_welcome_group_mismatch");
            }
            let snapshot = provider
                .snapshot()
                .map_err(|_| "mls_provider_snapshot_invalid")?;
            let key = self.load_or_create_wrapping_key()?;
            let encrypted = encrypt_snapshot(&snapshot, &key)?;
            if !store
                .remove_pending_mls_join_and_put_encrypted_mls_provider_snapshot(
                    group_id, &encrypted,
                )
                .map_err(|_| "mls_provider_store_unavailable")?
            {
                return Err("mls_pending_join_missing");
            }
            Ok(())
        })();
        if result.is_err() {
            *provider = ProfileProvider::from_snapshot(&previous)
                .map_err(|_| "mls_provider_snapshot_invalid")?;
        }
        result
    }

    /// Removes a pending join's one-time KeyPackage and its durable private
    /// material before an invitation is discarded.
    pub(crate) fn cancel_pending_join(&self, group_id: PeerId) -> Result<(), &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let mut provider = self
            .provider
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let Some(encoded) = store
            .pending_mls_join_key_package(group_id)
            .map_err(|_| "mls_provider_store_unavailable")?
        else {
            return Ok(());
        };
        let previous = provider
            .snapshot()
            .map_err(|_| "mls_provider_snapshot_invalid")?;
        let result = (|| {
            let mut remaining = encoded.as_slice();
            let key_package = KeyPackageIn::tls_deserialize(&mut remaining)
                .map_err(|_| "mls_pending_join_invalid")?;
            if !remaining.is_empty() {
                return Err("mls_pending_join_invalid");
            }
            let key_package = key_package
                .validate(provider.crypto(), ProtocolVersion::Mls10)
                .map_err(|_| "mls_pending_join_invalid")?;
            let reference = key_package
                .hash_ref(provider.crypto())
                .map_err(|_| "mls_pending_join_invalid")?;
            provider
                .storage()
                .delete_key_package(&reference)
                .map_err(|_| "mls_group_storage_unavailable")?;
            let snapshot = provider
                .snapshot()
                .map_err(|_| "mls_provider_snapshot_invalid")?;
            let key = self.load_or_create_wrapping_key()?;
            let encrypted = encrypt_snapshot(&snapshot, &key)?;
            if !store
                .remove_pending_mls_join_and_put_encrypted_mls_provider_snapshot(
                    group_id, &encrypted,
                )
                .map_err(|_| "mls_provider_store_unavailable")?
            {
                return Err("mls_pending_join_missing");
            }
            Ok(())
        })();
        if result.is_err() {
            *provider = ProfileProvider::from_snapshot(&previous)
                .map_err(|_| "mls_provider_snapshot_invalid")?;
        }
        result
    }

    /// Forgets a joined group on this device: the MLS group state leaves the
    /// provider snapshot in the same transaction that removes the group's
    /// local records. The owner still lists this device until it removes it.
    pub(crate) fn leave_joined_group(&self, group_id: PeerId) -> Result<(), &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let mut provider = self
            .provider
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let mut store = self
            .store
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let previous = provider
            .snapshot()
            .map_err(|_| "mls_provider_snapshot_invalid")?;
        let result = (|| {
            if let Some(mut group) = MlsGroup::load(
                provider.storage(),
                &GroupId::from_slice(&group_id.to_bytes()),
            )
            .map_err(|_| "mls_group_storage_unavailable")?
            {
                group
                    .delete(provider.storage())
                    .map_err(|_| "mls_group_storage_unavailable")?;
            }
            let snapshot = provider
                .snapshot()
                .map_err(|_| "mls_provider_snapshot_invalid")?;
            let key = self.load_or_create_wrapping_key()?;
            let encrypted = encrypt_snapshot(&snapshot, &key)?;
            if !store
                .leave_joined_group_and_put_encrypted_mls_provider_snapshot(group_id, &encrypted)
                .map_err(|_| "mls_provider_store_unavailable")?
            {
                return Err("joined_group_not_found");
            }
            Ok(())
        })();
        if result.is_err() {
            *provider = ProfileProvider::from_snapshot(&previous)
                .map_err(|_| "mls_provider_snapshot_invalid")?;
        }
        result
    }

    #[cfg(test)]
    fn read<T>(&self, operation: impl FnOnce(&ProfileProvider) -> T) -> Result<T, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let provider = self
            .provider
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        Ok(operation(&provider))
    }

    /// Runs one provider mutation and persists its encrypted snapshot. A failed
    /// operation or durable write restores the preceding in-memory state.
    #[cfg(test)]
    fn mutate<T, E>(
        &self,
        operation: impl FnOnce(&mut ProfileProvider) -> Result<T, E>,
    ) -> Result<T, MlsProviderMutationError<E>> {
        let _operation = self.operations.lock().map_err(|_| {
            MlsProviderMutationError::Unavailable("mls_provider_service_unavailable")
        })?;
        let mut provider = self.provider.lock().map_err(|_| {
            MlsProviderMutationError::Unavailable("mls_provider_service_unavailable")
        })?;
        let previous = provider
            .snapshot()
            .map_err(|_| MlsProviderMutationError::Unavailable("mls_provider_snapshot_invalid"))?;

        let result = match operation(&mut provider) {
            Ok(result) => result,
            Err(error) => {
                restore_provider(&mut provider, &previous)?;
                return Err(MlsProviderMutationError::Operation(error));
            }
        };
        let snapshot = match provider.snapshot() {
            Ok(snapshot) => snapshot,
            Err(_) => {
                restore_provider(&mut provider, &previous)?;
                return Err(MlsProviderMutationError::Unavailable(
                    "mls_provider_snapshot_invalid",
                ));
            }
        };
        let key = match self.load_or_create_wrapping_key() {
            Ok(key) => key,
            Err(error) => {
                restore_provider(&mut provider, &previous)?;
                return Err(MlsProviderMutationError::Unavailable(error));
            }
        };
        let encrypted = match encrypt_snapshot(&snapshot, &key) {
            Ok(encrypted) => encrypted,
            Err(error) => {
                restore_provider(&mut provider, &previous)?;
                return Err(MlsProviderMutationError::Unavailable(error));
            }
        };
        let write_result = self
            .store
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")
            .and_then(|mut store| {
                store
                    .put_encrypted_mls_provider_snapshot(&encrypted)
                    .map_err(|_| "mls_provider_store_unavailable")
            });
        if let Err(error) = write_result {
            restore_provider(&mut provider, &previous)?;
            return Err(MlsProviderMutationError::Unavailable(error));
        }
        Ok(result)
    }

    fn load_or_create_wrapping_key(
        &self,
    ) -> Result<Zeroizing<[u8; WRAPPING_KEY_BYTES]>, &'static str> {
        if let Some(key) = self.wrapping_keys.get_optional()? {
            return Ok(key);
        }
        let mut key = Zeroizing::new([0; WRAPPING_KEY_BYTES]);
        getrandom::fill(key.as_mut()).map_err(|_| "secure_random_unavailable")?;
        self.wrapping_keys.put(&key)?;
        Ok(key)
    }
}

/// Decrypts the text this device shows for a message: its latest applied edit,
/// otherwise the original body.
fn displayed_message_text(
    message: &charp2p_store::EncryptedMessage,
    key: &[u8; WRAPPING_KEY_BYTES],
) -> Result<String, &'static str> {
    let plaintext = match &message.edit {
        Some(edit) => decrypt_local_message(&edit.encrypted_body, key, &edit.event_id)?,
        None => decrypt_local_message(&message.encrypted_body, key, &message.event_id)?,
    };
    let text = std::str::from_utf8(&plaintext)
        .map_err(|_| "message_record_invalid")?
        .to_owned();
    if text.trim().is_empty() || text.len() > MAX_MESSAGE_TEXT_BYTES {
        return Err("message_record_invalid");
    }
    Ok(text)
}

fn hex_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
}

fn unix_time_millis() -> Result<u64, &'static str> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .ok_or("system_clock_invalid")
}

fn next_event_position(
    store: &EventStore,
    group_id: PeerId,
    author_id: PeerId,
) -> Result<(u64, Vec<EventId>), MemberAdmissionError> {
    let current_sequence = store
        .synchronization_summary(group_id)
        .map_err(|_| MemberAdmissionError::Unavailable)?
        .into_iter()
        .find(|head| head.author_id == author_id)
        .map_or(0, |head| head.contiguous_sequence);
    let author_sequence = current_sequence
        .checked_add(1)
        .ok_or(MemberAdmissionError::Unavailable)?;
    let causal_parents = if current_sequence == 0 {
        Vec::new()
    } else {
        let parent = store
            .event_ids_after(group_id, author_id, current_sequence - 1, 1)
            .map_err(|_| MemberAdmissionError::Unavailable)?
            .into_iter()
            .next()
            .ok_or(MemberAdmissionError::Unavailable)?;
        vec![parent]
    };
    Ok((author_sequence, causal_parents))
}

fn map_preparation_error(error: PrepareMemberAdmissionError) -> MemberAdmissionError {
    match error {
        PrepareMemberAdmissionError::InvalidKeyPackage(
            ProfileKeyPackageError::UnsupportedCiphersuite
            | ProfileKeyPackageError::UnsupportedCapabilities,
        ) => MemberAdmissionError::UnsupportedProfile,
        PrepareMemberAdmissionError::InvalidKeyPackage(_) => MemberAdmissionError::Unauthorized,
        _ => MemberAdmissionError::Unavailable,
    }
}

fn map_removal_preparation_error(error: PrepareMemberRemovalError) -> &'static str {
    match error {
        PrepareMemberRemovalError::MemberNotFound => "member_not_found",
        PrepareMemberRemovalError::OwnLeaf => "member_owner_cannot_remove",
        _ => "member_removal_failed",
    }
}

fn blocked_device_ids(store: &EventStore, group_id: PeerId) -> Result<Vec<String>, &'static str> {
    Ok(store
        .blocked_devices(group_id)
        .map_err(|_| "device_block_unavailable")?
        .into_iter()
        .map(|device_id| device_id.to_string())
        .collect())
}

fn group_member_devices(group: &MlsGroup) -> Result<Vec<GroupMemberDevice>, &'static str> {
    let mut member_ids = group
        .members()
        .map(|member| {
            device_id_from_credential(&member.credential).map_err(|_| "mls_group_members_invalid")
        })
        .collect::<Result<Vec<_>, _>>()?;
    member_ids.sort_by_key(|member_id| member_id.to_bytes());
    if member_ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("mls_group_members_invalid");
    }
    Ok(member_ids
        .into_iter()
        .map(|device_id| GroupMemberDevice {
            device_id: device_id.to_string(),
        })
        .collect())
}

fn initialize_owner_group(
    provider: &mut ProfileProvider,
    group_id: PeerId,
    device_id: PeerId,
) -> Result<(), &'static str> {
    let mls_group_id = GroupId::from_slice(&group_id.to_bytes());
    if let Some(group) = MlsGroup::load(provider.storage(), &mls_group_id)
        .map_err(|_| "mls_group_storage_unavailable")?
    {
        validate_owner_group(&group, group_id, device_id)?;
        return Ok(());
    }

    let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
        .map_err(|_| "mls_group_creation_failed")?;
    signer
        .store(provider.storage())
        .map_err(|_| "mls_group_storage_unavailable")?;
    let credential = CredentialWithKey {
        credential: device_credential(device_id).into(),
        signature_key: signer.public().into(),
    };
    let group = MlsGroup::new_with_group_id(
        provider,
        &signer,
        &group_create_config(),
        mls_group_id,
        credential,
    )
    .map_err(|_| "mls_group_creation_failed")?;
    validate_owner_group(&group, group_id, device_id)
}

fn removed_member_ids(store: &EventStore, group_id: PeerId) -> Result<Vec<String>, &'static str> {
    Ok(store
        .removed_mls_members(group_id)
        .map_err(|_| "removed_members_unavailable")?
        .into_iter()
        .map(|device_id| device_id.to_string())
        .collect())
}

fn validate_owner_group(
    group: &MlsGroup,
    group_id: PeerId,
    device_id: PeerId,
) -> Result<(), &'static str> {
    validate_group_profile(group).map_err(|_| "mls_group_profile_invalid")?;
    if group.group_id().as_slice() != group_id.to_bytes() {
        return Err("mls_group_identity_invalid");
    }
    let own_leaf = group.own_leaf_node().ok_or("mls_group_owner_missing")?;
    let stored_device =
        device_id_from_credential(own_leaf.credential()).map_err(|_| "mls_group_owner_invalid")?;
    if stored_device != device_id {
        return Err("mls_group_owner_mismatch");
    }
    Ok(())
}

/// Result of a provider operation that may fail before durable replacement.
#[cfg(test)]
#[allow(dead_code)]
#[derive(Debug)]
enum MlsProviderMutationError<E> {
    Operation(E),
    Unavailable(&'static str),
}

enum MaterializeMessageError {
    Unreadable,
    Unavailable(&'static str),
}

enum ApplyGroupCommitError {
    Unreadable,
    Unavailable(&'static str),
}

#[cfg(test)]
fn restore_provider<E>(
    provider: &mut ProfileProvider,
    snapshot: &[u8],
) -> Result<(), MlsProviderMutationError<E>> {
    *provider = ProfileProvider::from_snapshot(snapshot)
        .map_err(|_| MlsProviderMutationError::Unavailable("mls_provider_snapshot_invalid"))?;
    Ok(())
}

fn sync_request_group_id(request: &SyncRequest) -> PeerId {
    match request {
        SyncRequest::Summary { group_id }
        | SyncRequest::EventIds { group_id, .. }
        | SyncRequest::Events { group_id, .. }
        | SyncRequest::PushEvents { group_id, .. }
        | SyncRequest::ReportHeads { group_id, .. } => *group_id,
    }
}

/// Highest own sequence every other current member reported storing. With no
/// other member nothing can be observed by all of them.
fn observed_by_all_head(other_members: &[PeerId], acknowledged: &HashMap<PeerId, u64>) -> u64 {
    other_members
        .iter()
        .map(|member| acknowledged.get(member).copied().unwrap_or(0))
        .min()
        .unwrap_or(0)
}

/// Only the owner device that issued this device's invitation may change a
/// joined group's metadata. The owner applies its own changes when it creates
/// them, so a received change for a locally owned group is never authorized.
fn is_joined_group_owner(
    store: &EventStore,
    group_id: PeerId,
    author_id: PeerId,
) -> Result<bool, &'static str> {
    let joined = store
        .joined_groups()
        .map_err(|_| "message_store_unavailable")?;
    Ok(joined
        .iter()
        .any(|group| group.group_id == group_id && group.inviter_device_id == author_id))
}

fn encrypt_snapshot(
    snapshot: &[u8],
    key: &[u8; WRAPPING_KEY_BYTES],
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let mut nonce = [0; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| "secure_random_unavailable")?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: snapshot,
                aad: SNAPSHOT_AAD,
            },
        )
        .map_err(|_| "mls_provider_encryption_failed")?;
    let envelope_length = ENVELOPE_HEADER_BYTES
        .checked_add(ciphertext.len())
        .filter(|length| *length <= MAX_ENCRYPTED_MLS_PROVIDER_SNAPSHOT_BYTES)
        .ok_or("mls_provider_snapshot_invalid")?;
    let mut envelope = Zeroizing::new(Vec::with_capacity(envelope_length));
    envelope.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

fn decrypt_snapshot(
    envelope: &[u8],
    key: &[u8; WRAPPING_KEY_BYTES],
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if envelope.len() < ENVELOPE_HEADER_BYTES + TAG_BYTES
        || envelope.len() > MAX_ENCRYPTED_MLS_PROVIDER_SNAPSHOT_BYTES
    {
        return Err("mls_provider_snapshot_invalid");
    }
    let version = u16::from_be_bytes([envelope[0], envelope[1]]);
    if version != ENVELOPE_VERSION {
        return Err("mls_provider_snapshot_invalid");
    }
    let nonce = XNonce::from_slice(&envelope[2..ENVELOPE_HEADER_BYTES]);
    let cipher = XChaCha20Poly1305::new(key.into());
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &envelope[ENVELOPE_HEADER_BYTES..],
                aad: SNAPSHOT_AAD,
            },
        )
        .map_err(|_| "mls_provider_snapshot_invalid")?;
    Ok(Zeroizing::new(plaintext))
}

fn join_request_hash(encoded_key_package: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(JOIN_REQUEST_HASH_DOMAIN);
    hasher.update(encoded_key_package);
    *hasher.finalize().as_bytes()
}

fn join_response_aad(group_id: PeerId, member_id: PeerId, request_hash: &[u8; 32]) -> Vec<u8> {
    let group_id = group_id.to_bytes();
    let member_id = member_id.to_bytes();
    let mut aad = Vec::with_capacity(
        JOIN_RESPONSE_AAD.len() + group_id.len() + member_id.len() + request_hash.len(),
    );
    aad.extend_from_slice(JOIN_RESPONSE_AAD);
    aad.extend_from_slice(&group_id);
    aad.extend_from_slice(&member_id);
    aad.extend_from_slice(request_hash);
    aad
}

fn encrypt_join_response(
    encoded: &[u8],
    key: &[u8; WRAPPING_KEY_BYTES],
    group_id: PeerId,
    member_id: PeerId,
    request_hash: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if encoded.is_empty() || encoded.len() > MAX_JOIN_RESPONSE_WIRE_BYTES {
        return Err("mls_join_response_invalid");
    }
    let mut nonce = [0; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| "secure_random_unavailable")?;
    let aad = join_response_aad(group_id, member_id, request_hash);
    let cipher = XChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: encoded,
                aad: &aad,
            },
        )
        .map_err(|_| "mls_join_response_encryption_failed")?;
    let envelope_length = ENVELOPE_HEADER_BYTES
        .checked_add(ciphertext.len())
        .filter(|length| *length <= MAX_ENCRYPTED_JOIN_RESPONSE_BYTES)
        .ok_or("mls_join_response_invalid")?;
    let mut envelope = Zeroizing::new(Vec::with_capacity(envelope_length));
    envelope.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

fn decrypt_join_response(
    envelope: &[u8],
    key: &[u8; WRAPPING_KEY_BYTES],
    group_id: PeerId,
    member_id: PeerId,
    request_hash: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if envelope.len() < ENVELOPE_HEADER_BYTES + TAG_BYTES
        || envelope.len() > MAX_ENCRYPTED_JOIN_RESPONSE_BYTES
    {
        return Err("mls_join_response_invalid");
    }
    let version = u16::from_be_bytes([envelope[0], envelope[1]]);
    if version != ENVELOPE_VERSION {
        return Err("mls_join_response_invalid");
    }
    let aad = join_response_aad(group_id, member_id, request_hash);
    let nonce = XNonce::from_slice(&envelope[2..ENVELOPE_HEADER_BYTES]);
    let cipher = XChaCha20Poly1305::new(key.into());
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &envelope[ENVELOPE_HEADER_BYTES..],
                aad: &aad,
            },
        )
        .map_err(|_| "mls_join_response_invalid")?;
    if plaintext.is_empty() || plaintext.len() > MAX_JOIN_RESPONSE_WIRE_BYTES {
        return Err("mls_join_response_invalid");
    }
    Ok(Zeroizing::new(plaintext))
}

fn encrypt_local_message(
    plaintext: &[u8],
    key: &[u8; WRAPPING_KEY_BYTES],
    event_id: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if plaintext.is_empty() || plaintext.len() > MAX_MESSAGE_TEXT_BYTES {
        return Err("message_invalid");
    }
    let mut nonce = [0; NONCE_BYTES];
    getrandom::fill(&mut nonce).map_err(|_| "secure_random_unavailable")?;
    let mut aad = Vec::with_capacity(MESSAGE_AAD.len() + event_id.len());
    aad.extend_from_slice(MESSAGE_AAD);
    aad.extend_from_slice(event_id);
    let cipher = XChaCha20Poly1305::new(key.into());
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| "message_encryption_failed")?;
    let envelope_length = ENVELOPE_HEADER_BYTES
        .checked_add(ciphertext.len())
        .filter(|length| *length <= MAX_ENCRYPTED_MESSAGE_BODY_BYTES)
        .ok_or("message_encryption_failed")?;
    let mut envelope = Zeroizing::new(Vec::with_capacity(envelope_length));
    envelope.extend_from_slice(&ENVELOPE_VERSION.to_be_bytes());
    envelope.extend_from_slice(&nonce);
    envelope.extend_from_slice(&ciphertext);
    Ok(envelope)
}

fn decrypt_local_message(
    envelope: &[u8],
    key: &[u8; WRAPPING_KEY_BYTES],
    event_id: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    if envelope.len() < ENVELOPE_HEADER_BYTES + TAG_BYTES
        || envelope.len() > MAX_ENCRYPTED_MESSAGE_BODY_BYTES
    {
        return Err("message_record_invalid");
    }
    let version = u16::from_be_bytes([envelope[0], envelope[1]]);
    if version != ENVELOPE_VERSION {
        return Err("message_record_invalid");
    }
    let mut aad = Vec::with_capacity(MESSAGE_AAD.len() + event_id.len());
    aad.extend_from_slice(MESSAGE_AAD);
    aad.extend_from_slice(event_id);
    let nonce = XNonce::from_slice(&envelope[2..ENVELOPE_HEADER_BYTES]);
    let cipher = XChaCha20Poly1305::new(key.into());
    let plaintext = cipher
        .decrypt(
            nonce,
            Payload {
                msg: &envelope[ENVELOPE_HEADER_BYTES..],
                aad: &aad,
            },
        )
        .map_err(|_| "message_record_invalid")?;
    if plaintext.is_empty() || plaintext.len() > MAX_MESSAGE_TEXT_BYTES {
        return Err("message_record_invalid");
    }
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use std::{
        path::Path,
        sync::{Arc, Mutex},
    };

    use charp2p_core::{
        DeviceIdentity, DiscoveryKey, EventKind, EventSpec, GroupIdentity, HistoryPolicy,
        Invitation, InvitationSpec, PeerId, SignedEvent, SyncAuthorHead, SyncPeerHead,
        SyncRejectReason, SyncRequest, SyncResponse,
    };
    use charp2p_mls::{
        decode_profile_message, device_credential, device_id_from_credential, group_create_config,
        merge_prepared_member_admission, prepare_profile_key_package,
        prepare_profile_member_admission, stage_profile_welcome, ProfileProvider, CIPHERSUITE,
    };
    use charp2p_sync::PullSession;
    use openmls::prelude::{
        CredentialWithKey, GroupId, MlsGroup, OpenMlsProvider, ProcessedMessageContent,
        ProtocolMessage,
    };
    use openmls_basic_credential::SignatureKeyPair;
    use tempfile::tempdir;
    use zeroize::Zeroizing;

    use super::{
        decrypt_join_response, decrypt_local_message, decrypt_snapshot, encrypt_join_response,
        encrypt_local_message, encrypt_snapshot, hex_bytes, join_request_hash,
        DeviceSequenceConflict, GroupMemberDevice, GroupMessagePreview, MemberActivity,
        MemberAdmissionError, MlsProviderMutationError, MlsProviderService, UnreadMessageCount,
        WrappingKeyStore, MAX_EVIDENCE_EVENTS, WRAPPING_KEY_BYTES,
    };
    use charp2p_store::{EventStore, PendingInvitationMetadata};

    #[derive(Clone, Default)]
    struct MemoryWrappingKeyStore {
        key: Arc<Mutex<Option<[u8; WRAPPING_KEY_BYTES]>>>,
    }

    impl WrappingKeyStore for MemoryWrappingKeyStore {
        fn get_optional(
            &self,
        ) -> Result<Option<Zeroizing<[u8; WRAPPING_KEY_BYTES]>>, &'static str> {
            Ok(self
                .key
                .lock()
                .map_err(|_| "test_key_store_unavailable")?
                .map(Zeroizing::new))
        }

        fn put(&self, key: &[u8; WRAPPING_KEY_BYTES]) -> Result<(), &'static str> {
            *self.key.lock().map_err(|_| "test_key_store_unavailable")? = Some(*key);
            Ok(())
        }
    }

    fn add_key_package(provider: &mut charp2p_mls::ProfileProvider) {
        let device_id = DeviceIdentity::generate().peer_id();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).unwrap();
        signer.store(provider.storage()).unwrap();
        let credential = CredentialWithKey {
            credential: device_credential(device_id).into(),
            signature_key: signer.public().into(),
        };
        prepare_profile_key_package(provider, &signer, credential, device_id).unwrap();
    }

    fn member_key_package(
        member_id: charp2p_core::PeerId,
    ) -> (ProfileProvider, charp2p_mls::PreparedKeyPackage) {
        let provider = ProfileProvider::default();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).unwrap();
        signer.store(provider.storage()).unwrap();
        let credential = CredentialWithKey {
            credential: device_credential(member_id).into(),
            signature_key: signer.public().into(),
        };
        let key_package =
            prepare_profile_key_package(&provider, &signer, credential, member_id).unwrap();
        (provider, key_package)
    }

    fn invitation(group: &GroupIdentity) -> Invitation {
        Invitation::issue(
            group,
            DeviceIdentity::generate().peer_id(),
            InvitationSpec {
                group_name: "Design Crew",
                inviter_name: "Maya",
                expires_at_unix: 1_800_003_600,
                history_policy: HistoryPolicy::None,
                reusable: false,
            },
            1_800_000_000,
        )
        .unwrap()
    }

    #[test]
    fn encryption_uses_a_fresh_nonce_and_authenticates_round_trips() {
        let key = [7; WRAPPING_KEY_BYTES];
        let first = encrypt_snapshot(b"provider state", &key).unwrap();
        let second = encrypt_snapshot(b"provider state", &key).unwrap();

        assert_ne!(first.as_slice(), second.as_slice());
        assert_eq!(
            decrypt_snapshot(&first, &key).unwrap().as_slice(),
            b"provider state"
        );
    }

    #[test]
    fn local_message_encryption_is_bound_to_its_event() {
        let key = [9; WRAPPING_KEY_BYTES];
        let event_id = [3; 32];
        let encrypted = encrypt_local_message(b"local display text", &key, &event_id).unwrap();

        assert_eq!(
            decrypt_local_message(&encrypted, &key, &event_id)
                .unwrap()
                .as_slice(),
            b"local display text"
        );
        assert!(decrypt_local_message(&encrypted, &key, &[4; 32]).is_err());
    }

    #[test]
    fn cached_join_response_is_bound_to_the_exact_request_and_membership() {
        let key = [5; WRAPPING_KEY_BYTES];
        let group_id = GroupIdentity::generate().group_id();
        let member_id = DeviceIdentity::generate().peer_id();
        let other_member = DeviceIdentity::generate().peer_id();
        let request_hash = join_request_hash(b"bounded key package");
        let encrypted = encrypt_join_response(
            b"encoded accepted response",
            &key,
            group_id,
            member_id,
            &request_hash,
        )
        .unwrap();

        assert_eq!(
            decrypt_join_response(&encrypted, &key, group_id, member_id, &request_hash)
                .unwrap()
                .as_slice(),
            b"encoded accepted response"
        );
        assert!(
            decrypt_join_response(&encrypted, &key, group_id, other_member, &request_hash,)
                .is_err()
        );
        assert!(decrypt_join_response(&encrypted, &key, group_id, member_id, &[8; 32]).is_err());
    }

    #[test]
    fn owner_group_is_idempotent_and_survives_restart() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("charp2p.sqlite3");
        let key_store = MemoryWrappingKeyStore::default();
        let group_id = GroupIdentity::generate().group_id();
        let owner = DeviceIdentity::generate();
        let device_id = owner.peer_id();
        let service = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(key_store.clone()),
        )
        .unwrap();

        service.initialize_owner_group(group_id, &owner).unwrap();
        service.initialize_owner_group(group_id, &owner).unwrap();
        assert_eq!(
            service.group_members(group_id).unwrap(),
            vec![GroupMemberDevice {
                device_id: device_id.to_string(),
            }]
        );
        let store = EventStore::open(&path).unwrap();
        let event_ids = store.event_ids_after(group_id, device_id, 0, 2).unwrap();
        assert_eq!(event_ids.len(), 1);
        let created = store.get_event(event_ids[0]).unwrap().unwrap();
        assert_eq!(created.kind(), EventKind::GroupCreated);
        assert_eq!(created.author_sequence(), 1);
        assert_eq!(
            service.member_activity(group_id).unwrap(),
            vec![MemberActivity {
                device_id: device_id.to_string(),
                last_signed_at_unix_ms: created.created_at_unix_ms(),
            }]
        );
        assert!(service.sequence_conflicts(group_id).unwrap().is_empty());
        let mut store = store;
        let equivocation = SignedEvent::create(
            &owner,
            EventSpec {
                group_id,
                author_sequence: 1,
                causal_parents: &[],
                created_at_unix_ms: created.created_at_unix_ms(),
                kind: EventKind::MessageCreated,
                protected_payload: b"conflicting content",
            },
        )
        .unwrap();
        assert!(store.put_event(&equivocation).is_err());
        assert_eq!(
            service.sequence_conflicts(group_id).unwrap(),
            vec![DeviceSequenceConflict {
                device_id: device_id.to_string(),
                conflicting_sequences: 1,
                first_sequence: 1,
            }]
        );
        drop(store);
        drop(service);

        let restored = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(key_store),
        )
        .unwrap();
        restored.initialize_owner_group(group_id, &owner).unwrap();
    }

    #[test]
    fn pending_join_request_reuses_its_durable_key_package_after_restart() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("charp2p.sqlite3");
        let key_store = MemoryWrappingKeyStore::default();
        let invitation = invitation(&GroupIdentity::generate());
        let device_id = DeviceIdentity::generate().peer_id();
        let service = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(key_store.clone()),
        )
        .unwrap();

        let first = service
            .prepare_join_request(device_id, &invitation)
            .unwrap();
        let repeated = service
            .prepare_join_request(device_id, &invitation)
            .unwrap();
        assert_eq!(first.key_package(), repeated.key_package());
        assert_eq!(first.invitation(), repeated.invitation());
        assert_eq!(
            EventStore::open(&path)
                .unwrap()
                .pending_mls_join_key_package(invitation.group_id())
                .unwrap()
                .unwrap(),
            first.key_package()
        );
        drop(service);

        let restored = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(key_store),
        )
        .unwrap();
        let after_restart = restored
            .prepare_join_request(device_id, &invitation)
            .unwrap();
        assert_eq!(first.key_package(), after_restart.key_package());
    }

    #[test]
    fn cancelled_pending_join_removes_key_material_and_can_start_fresh() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("charp2p.sqlite3");
        let key_store = MemoryWrappingKeyStore::default();
        let invitation = invitation(&GroupIdentity::generate());
        let group_id = invitation.group_id();
        let device_id = DeviceIdentity::generate().peer_id();
        let service = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(key_store.clone()),
        )
        .unwrap();

        let first = service
            .prepare_join_request(device_id, &invitation)
            .unwrap();
        service.cancel_pending_join(group_id).unwrap();
        service.cancel_pending_join(group_id).unwrap();
        assert!(EventStore::open(&path)
            .unwrap()
            .pending_mls_join_key_package(group_id)
            .unwrap()
            .is_none());
        drop(service);

        let restored = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(key_store),
        )
        .unwrap();
        let replacement = restored
            .prepare_join_request(device_id, &invitation)
            .unwrap();
        assert_ne!(first.key_package(), replacement.key_package());
    }

    #[test]
    fn welcome_completion_restores_failures_then_persists_the_joined_group() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("charp2p.sqlite3");
        let key_store = MemoryWrappingKeyStore::default();
        let group_identity = GroupIdentity::generate();
        let group_id = group_identity.group_id();
        let invitation = invitation(&group_identity);
        let joiner_id = DeviceIdentity::generate().peer_id();
        let service = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(key_store.clone()),
        )
        .unwrap();
        let request = service
            .prepare_join_request(joiner_id, &invitation)
            .unwrap();

        let owner_provider = ProfileProvider::default();
        let owner_id = DeviceIdentity::generate().peer_id();
        let owner_signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).unwrap();
        owner_signer.store(owner_provider.storage()).unwrap();
        let owner_credential = CredentialWithKey {
            credential: device_credential(owner_id).into(),
            signature_key: owner_signer.public().into(),
        };
        let mut owner_group = MlsGroup::new_with_group_id(
            &owner_provider,
            &owner_signer,
            &group_create_config(),
            GroupId::from_slice(&group_id.to_bytes()),
            owner_credential,
        )
        .unwrap();
        let admission = prepare_profile_member_admission(
            &mut owner_group,
            &owner_provider,
            &owner_signer,
            request.key_package(),
            joiner_id,
        )
        .unwrap();
        merge_prepared_member_admission(&mut owner_group, &owner_provider).unwrap();

        assert_eq!(
            service.complete_join(group_id, &[1]),
            Err("mls_welcome_invalid")
        );
        assert!(EventStore::open(&path)
            .unwrap()
            .pending_mls_join_key_package(group_id)
            .unwrap()
            .is_some());
        service
            .complete_join(group_id, admission.welcome())
            .unwrap();
        assert!(EventStore::open(&path)
            .unwrap()
            .pending_mls_join_key_package(group_id)
            .unwrap()
            .is_none());
        drop(service);

        let restored = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(key_store),
        )
        .unwrap();
        let members = restored
            .read(|provider| {
                MlsGroup::load(
                    provider.storage(),
                    &GroupId::from_slice(&group_id.to_bytes()),
                )
                .unwrap()
                .unwrap()
                .members()
                .map(|member| device_id_from_credential(&member.credential).unwrap())
                .collect::<Vec<_>>()
            })
            .unwrap();
        assert!(members.contains(&owner_id));
        assert!(members.contains(&joiner_id));
    }

    #[test]
    fn leaving_a_joined_group_removes_it_from_the_persisted_provider() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("charp2p.sqlite3");
        let key_store = MemoryWrappingKeyStore::default();
        let group_identity = GroupIdentity::generate();
        let group_id = group_identity.group_id();
        let invitation = invitation(&group_identity);
        let owner = DeviceIdentity::generate();
        let joiner_id = DeviceIdentity::generate().peer_id();
        let owner_service = MlsProviderService::open_with_key_store(
            directory.path().join("owner.sqlite3"),
            Arc::new(Mutex::new(())),
            Box::new(MemoryWrappingKeyStore::default()),
        )
        .unwrap();
        owner_service
            .initialize_owner_group(group_id, &owner)
            .unwrap();
        let service = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(key_store.clone()),
        )
        .unwrap();
        let request = service
            .prepare_join_request(joiner_id, &invitation)
            .unwrap();
        let response = owner_service
            .admit_member_at(group_id, &owner, joiner_id, request.key_package(), 42)
            .unwrap();
        service
            .complete_join(group_id, response.welcome().unwrap())
            .unwrap();
        let mut store = EventStore::open(&path).unwrap();
        store
            .put_pending_invitation(&PendingInvitationMetadata {
                group_id,
                group_name: "Design Crew".to_owned(),
                inviter_name: "Maya".to_owned(),
                expires_at_unix: 1_800_003_600,
                history_policy: HistoryPolicy::FromInvitation,
                reusable: false,
            })
            .unwrap();
        store
            .promote_pending_invitation_to_joined_group(group_id, owner.peer_id())
            .unwrap();

        assert_eq!(
            owner_service.leave_joined_group(group_id),
            Err("joined_group_not_found")
        );
        assert!(owner_service.has_group(group_id).unwrap());
        service.leave_joined_group(group_id).unwrap();
        assert!(!service.has_group(group_id).unwrap());
        assert!(store.joined_groups().unwrap().is_empty());
        assert_eq!(
            service.leave_joined_group(group_id),
            Err("joined_group_not_found")
        );
        drop(service);

        let restored = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(key_store),
        )
        .unwrap();
        assert!(!restored.has_group(group_id).unwrap());
    }

    #[test]
    fn member_admission_persists_the_event_and_advanced_group_atomically() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("charp2p.sqlite3");
        let key_store = MemoryWrappingKeyStore::default();
        let group_id = GroupIdentity::generate().group_id();
        let owner = DeviceIdentity::generate();
        let member_id = DeviceIdentity::generate().peer_id();
        let (member_provider, key_package) = member_key_package(member_id);
        let service = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(key_store.clone()),
        )
        .unwrap();
        service.initialize_owner_group(group_id, &owner).unwrap();

        let response = service
            .admit_member_at(group_id, &owner, member_id, key_package.encoded(), 42)
            .unwrap();
        let staged = stage_profile_welcome(&member_provider, response.welcome().unwrap()).unwrap();
        let joined = staged.into_group(&member_provider).unwrap();
        assert_eq!(joined.group_id().as_slice(), group_id.to_bytes());

        let first_response = response.encode().unwrap();
        drop(service);
        let service = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(key_store.clone()),
        )
        .unwrap();
        let retried = service
            .admit_member_at(group_id, &owner, member_id, key_package.encoded(), 99)
            .unwrap();
        assert_eq!(
            retried.encode().unwrap().as_slice(),
            first_response.as_slice()
        );
        let members = service.group_members(group_id).unwrap();
        assert_eq!(members.len(), 2);
        assert!(members
            .iter()
            .any(|member| member.device_id == owner.peer_id().to_string()));
        assert!(members
            .iter()
            .any(|member| member.device_id == member_id.to_string()));
        let (_, replacement_key_package) = member_key_package(member_id);
        assert!(matches!(
            service.admit_member_at(
                group_id,
                &owner,
                member_id,
                replacement_key_package.encoded(),
                100,
            ),
            Err(MemberAdmissionError::Unauthorized)
        ));

        let second_member_id = DeviceIdentity::generate().peer_id();
        let (second_member_provider, second_key_package) = member_key_package(second_member_id);
        let second_response = service
            .admit_member_at(
                group_id,
                &owner,
                second_member_id,
                second_key_package.encoded(),
                43,
            )
            .unwrap();
        let second_staged =
            stage_profile_welcome(&second_member_provider, second_response.welcome().unwrap())
                .unwrap();
        second_staged.into_group(&second_member_provider).unwrap();

        let store = EventStore::open(&path).unwrap();
        let event_ids = store
            .event_ids_after(group_id, owner.peer_id(), 0, 3)
            .unwrap();
        let created = store.get_event(event_ids[0]).unwrap().unwrap();
        let first = store.get_event(event_ids[1]).unwrap().unwrap();
        let second = store.get_event(event_ids[2]).unwrap().unwrap();
        assert_eq!(created.kind(), EventKind::GroupCreated);
        assert_eq!(created.author_sequence(), 1);
        assert_eq!(first.kind(), EventKind::MemberAdded);
        assert_eq!(first.author_sequence(), 2);
        assert_eq!(first.causal_parents(), &[created.id()]);
        assert_eq!(first.created_at_unix_ms(), 42);
        assert_eq!(second.kind(), EventKind::MemberAdded);
        assert_eq!(second.author_sequence(), 3);
        assert_eq!(second.causal_parents(), &[first.id()]);
        assert_eq!(second.created_at_unix_ms(), 43);
        drop(store);
        drop(service);

        let restored = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(key_store),
        )
        .unwrap();
        let members = restored
            .read(|provider| {
                MlsGroup::load(
                    provider.storage(),
                    &GroupId::from_slice(&group_id.to_bytes()),
                )
                .unwrap()
                .unwrap()
                .members()
                .map(|member| device_id_from_credential(&member.credential).unwrap())
                .collect::<Vec<_>>()
            })
            .unwrap();
        assert!(members.contains(&owner.peer_id()));
        assert!(members.contains(&member_id));
        assert!(members.contains(&second_member_id));
    }

    #[test]
    fn single_use_invitation_admits_one_device_and_replays_only_its_retry() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("charp2p.sqlite3");
        let group_identity = GroupIdentity::generate();
        let group_id = group_identity.group_id();
        let invitation_id = invitation(&group_identity).invitation_id();
        let owner = DeviceIdentity::generate();
        let first_id = DeviceIdentity::generate().peer_id();
        let second_id = DeviceIdentity::generate().peer_id();
        let (_, first_package) = member_key_package(first_id);
        let (_, second_package) = member_key_package(second_id);
        let service = test_service(&path);
        service.initialize_owner_group(group_id, &owner).unwrap();

        let (welcome, admitted) = service
            .admit_member_once_at(
                group_id,
                &owner,
                first_id,
                first_package.encoded(),
                Some(invitation_id),
                42,
            )
            .unwrap();
        assert!(admitted);
        let (retried, admitted) = service
            .admit_member_once_at(
                group_id,
                &owner,
                first_id,
                first_package.encoded(),
                Some(invitation_id),
                43,
            )
            .unwrap();
        assert!(!admitted);
        assert_eq!(retried.encode().unwrap(), welcome.encode().unwrap());
        assert!(matches!(
            service.admit_member_once_at(
                group_id,
                &owner,
                second_id,
                second_package.encoded(),
                Some(invitation_id),
                44,
            ),
            Err(MemberAdmissionError::Unauthorized)
        ));
        assert_eq!(service.group_members(group_id).unwrap().len(), 2);
        let store = EventStore::open(&path).unwrap();
        assert_eq!(
            store
                .single_use_invitation_consumer(group_id, invitation_id)
                .unwrap(),
            Some(first_id)
        );
        assert!(store
            .mls_join_admission(group_id, second_id)
            .unwrap()
            .is_none());
        assert_eq!(
            store
                .event_ids_after(group_id, owner.peer_id(), 0, 10)
                .unwrap()
                .len(),
            2
        );
        drop(store);

        // A reusable invitation keeps admitting other devices.
        service
            .admit_member_once_at(
                group_id,
                &owner,
                second_id,
                second_package.encoded(),
                None,
                45,
            )
            .unwrap();
        assert_eq!(service.group_members(group_id).unwrap().len(), 3);
    }

    #[test]
    fn owner_removal_persists_and_blocks_invitation_reuse() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("charp2p.sqlite3");
        let key_store = MemoryWrappingKeyStore::default();
        let group_id = GroupIdentity::generate().group_id();
        let owner = DeviceIdentity::generate();
        let member_id = DeviceIdentity::generate().peer_id();
        let (_, key_package) = member_key_package(member_id);
        let service = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(key_store.clone()),
        )
        .unwrap();
        service.initialize_owner_group(group_id, &owner).unwrap();
        service
            .admit_member_at(group_id, &owner, member_id, key_package.encoded(), 42)
            .unwrap();

        let members = service
            .remove_member_at(group_id, &owner, member_id, 43)
            .unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].device_id, owner.peer_id().to_string());
        assert!(matches!(
            service.admit_member_at(group_id, &owner, member_id, key_package.encoded(), 44),
            Err(MemberAdmissionError::Unauthorized)
        ));
        let store = EventStore::open(&path).unwrap();
        assert!(store.is_removed_mls_member(group_id, member_id).unwrap());
        assert!(store
            .mls_join_admission(group_id, member_id)
            .unwrap()
            .is_none());
        let event_ids = store
            .event_ids_after(group_id, owner.peer_id(), 0, 3)
            .unwrap();
        let removal = store.get_event(event_ids[2]).unwrap().unwrap();
        assert_eq!(removal.kind(), EventKind::MemberRemoved);
        assert_eq!(removal.author_sequence(), 3);
        assert_eq!(
            removal.causal_parents(),
            &[store.get_event(event_ids[1]).unwrap().unwrap().id()]
        );
        drop(store);
        drop(service);

        let restored = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(key_store),
        )
        .unwrap();
        assert_eq!(restored.group_members(group_id).unwrap().len(), 1);
        let (_, replacement) = member_key_package(member_id);
        assert!(matches!(
            restored.admit_member_at(group_id, &owner, member_id, replacement.encoded(), 45),
            Err(MemberAdmissionError::Unauthorized)
        ));
        assert_eq!(
            restored.removed_members(group_id).unwrap(),
            vec![member_id.to_string()]
        );
    }

    #[test]
    fn owner_allows_removed_device_to_join_again_with_a_new_key_package() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("charp2p.sqlite3");
        let group_id = GroupIdentity::generate().group_id();
        let owner = DeviceIdentity::generate();
        let member_id = DeviceIdentity::generate().peer_id();
        let (_, key_package) = member_key_package(member_id);
        let service = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(MemoryWrappingKeyStore::default()),
        )
        .unwrap();
        service.initialize_owner_group(group_id, &owner).unwrap();
        service
            .admit_member_at(group_id, &owner, member_id, key_package.encoded(), 42)
            .unwrap();
        service
            .remove_member_at(group_id, &owner, member_id, 43)
            .unwrap();

        assert!(matches!(
            service.allow_member_readmission(group_id, &DeviceIdentity::generate(), member_id),
            Err("member_readmission_not_allowed")
        ));
        assert!(matches!(
            service.allow_member_readmission(
                group_id,
                &owner,
                DeviceIdentity::generate().peer_id()
            ),
            Err("member_not_removed")
        ));
        assert!(service
            .allow_member_readmission(group_id, &owner, member_id)
            .unwrap()
            .is_empty());
        assert!(service.removed_members(group_id).unwrap().is_empty());

        let (member_provider, replacement) = member_key_package(member_id);
        let response = service
            .admit_member_at(group_id, &owner, member_id, replacement.encoded(), 44)
            .unwrap();
        let staged = stage_profile_welcome(&member_provider, response.welcome().unwrap()).unwrap();
        staged.into_group(&member_provider).unwrap();
        let members = service.group_members(group_id).unwrap();
        assert_eq!(members.len(), 2);
        assert!(members
            .iter()
            .any(|member| member.device_id == member_id.to_string()));
    }

    #[test]
    fn message_event_is_mls_protected_and_sender_state_survives_restart() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("charp2p.sqlite3");
        let key_store = MemoryWrappingKeyStore::default();
        let group_id = GroupIdentity::generate().group_id();
        let owner = DeviceIdentity::generate();
        let member_id = DeviceIdentity::generate().peer_id();
        let (member_provider, key_package) = member_key_package(member_id);
        let service = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(key_store.clone()),
        )
        .unwrap();
        service.initialize_owner_group(group_id, &owner).unwrap();
        let response = service
            .admit_member_at(group_id, &owner, member_id, key_package.encoded(), 41)
            .unwrap();
        let staged = stage_profile_welcome(&member_provider, response.welcome().unwrap()).unwrap();
        let mut member_group = staged.into_group(&member_provider).unwrap();

        assert!(matches!(
            service.create_message_at(group_id, &owner, "   ", 42),
            Err("message_invalid")
        ));
        let first = service
            .create_message_at(group_id, &owner, "Protected hello", 42)
            .unwrap();
        assert_eq!(first.kind(), EventKind::MessageCreated);
        assert_eq!(first.author_sequence(), 3);
        assert_eq!(first.created_at_unix_ms(), 42);
        assert_eq!(first.causal_parents().len(), 1);
        assert_eq!(
            decrypt_application_message(&mut member_group, &member_provider, &first),
            b"Protected hello"
        );
        drop(service);

        let restored = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(key_store),
        )
        .unwrap();
        let second = restored
            .create_message_at(group_id, &owner, "After restart", 43)
            .unwrap();
        assert_eq!(second.author_sequence(), 4);
        assert_eq!(second.causal_parents(), &[first.id()]);
        assert_eq!(
            decrypt_application_message(&mut member_group, &member_provider, &second),
            b"After restart"
        );
        let messages = restored.messages(group_id, owner.peer_id()).unwrap();
        assert_eq!(messages.messages.len(), 2);
        assert!(!messages.has_earlier);
        assert_eq!(messages.messages[0].text, "Protected hello");
        assert_eq!(messages.messages[0].author_id, owner.peer_id().to_string());
        assert_eq!(messages.messages[0].delivery_state, "local");
        assert_eq!(messages.messages[1].text, "After restart");
        let other_group = GroupIdentity::generate().group_id();
        assert_eq!(
            restored.message_previews(&[other_group, group_id]).unwrap(),
            vec![GroupMessagePreview {
                group_id: group_id.to_string(),
                author_id: owner.peer_id().to_string(),
                created_at_unix_ms: 43,
                text: "After restart".to_owned(),
            }]
        );
        restored
            .acknowledge_messages_shared(
                group_id,
                DeviceIdentity::generate().peer_id(),
                owner.peer_id(),
                3,
            )
            .unwrap();
        let messages = restored.messages(group_id, owner.peer_id()).unwrap();
        assert_eq!(messages.messages[0].delivery_state, "sharedWithPeer");
        assert_eq!(messages.messages[1].delivery_state, "local");
        assert_eq!(
            restored.answer_sync_request(
                member_id,
                &SyncRequest::ReportHeads {
                    group_id,
                    heads: vec![SyncAuthorHead {
                        author_id: owner.peer_id(),
                        contiguous_sequence: 3,
                    }],
                },
            ),
            SyncResponse::ObservedHeads {
                group_id,
                peers: vec![SyncPeerHead {
                    peer_id: owner.peer_id(),
                    contiguous_sequence: 0,
                }],
            }
        );
        let messages = restored.messages(group_id, owner.peer_id()).unwrap();
        assert_eq!(messages.messages[0].delivery_state, "observedByAll");
        assert_eq!(messages.messages[1].delivery_state, "local");
        restored
            .record_observed_heads(
                group_id,
                owner.peer_id(),
                &[SyncPeerHead {
                    peer_id: member_id,
                    contiguous_sequence: 4,
                }],
            )
            .unwrap();
        let messages = restored.messages(group_id, owner.peer_id()).unwrap();
        assert_eq!(messages.messages[1].delivery_state, "observedByAll");
        restored
            .hide_message_locally(group_id, first.id().as_bytes())
            .unwrap();
        let messages = restored.messages(group_id, owner.peer_id()).unwrap();
        assert_eq!(messages.messages.len(), 1);
        assert_eq!(messages.messages[0].text, "After restart");
        let stored = EventStore::open(path).unwrap();
        let encrypted_messages = stored.encrypted_messages(group_id).unwrap();
        assert_eq!(encrypted_messages.messages.len(), 1);
        assert!(encrypted_messages.messages.iter().all(|message| !message
            .encrypted_body
            .windows(b"After restart".len())
            .any(|window| window == b"After restart")));
        assert_eq!(
            stored
                .event_ids_after(group_id, owner.peer_id(), 0, 3)
                .unwrap()
                .len(),
            3
        );
    }

    #[test]
    fn joined_member_can_create_a_protected_local_message() {
        let directory = tempdir().unwrap();
        let owner_path = directory.path().join("owner.sqlite3");
        let member_path = directory.path().join("member.sqlite3");
        let group_identity = GroupIdentity::generate();
        let group_id = group_identity.group_id();
        let invitation = invitation(&group_identity);
        let owner = DeviceIdentity::generate();
        let member = DeviceIdentity::generate();
        let owner_service = MlsProviderService::open_with_key_store(
            &owner_path,
            Arc::new(Mutex::new(())),
            Box::new(MemoryWrappingKeyStore::default()),
        )
        .unwrap();
        owner_service
            .initialize_owner_group(group_id, &owner)
            .unwrap();
        let member_service = MlsProviderService::open_with_key_store(
            &member_path,
            Arc::new(Mutex::new(())),
            Box::new(MemoryWrappingKeyStore::default()),
        )
        .unwrap();
        let request = member_service
            .prepare_join_request(member.peer_id(), &invitation)
            .unwrap();
        let welcome = owner_service
            .admit_member_at(
                group_id,
                &owner,
                member.peer_id(),
                request.key_package(),
                41,
            )
            .unwrap();
        member_service
            .complete_join(group_id, welcome.welcome().unwrap())
            .unwrap();

        let event = member_service
            .create_message_at(group_id, &member, "Hello from member", 42)
            .unwrap();
        assert_eq!(
            member_service
                .messages(group_id, member.peer_id())
                .unwrap()
                .messages[0]
                .text,
            "Hello from member"
        );
        assert_eq!(
            owner_service
                .read(|provider| {
                    let mut owner_group = MlsGroup::load(
                        provider.storage(),
                        &GroupId::from_slice(&group_id.to_bytes()),
                    )
                    .unwrap()
                    .unwrap();
                    decrypt_application_message(&mut owner_group, provider, &event)
                })
                .unwrap(),
            b"Hello from member"
        );
    }

    #[test]
    fn owner_accepts_and_materializes_an_authenticated_member_message_push() {
        let directory = tempdir().unwrap();
        let group_identity = GroupIdentity::generate();
        let group_id = group_identity.group_id();
        let invitation = invitation(&group_identity);
        let owner = DeviceIdentity::generate();
        let member = DeviceIdentity::generate();
        let owner_service = MlsProviderService::open_with_key_store(
            directory.path().join("owner.sqlite3"),
            Arc::new(Mutex::new(())),
            Box::new(MemoryWrappingKeyStore::default()),
        )
        .unwrap();
        owner_service
            .initialize_owner_group(group_id, &owner)
            .unwrap();
        let member_service = MlsProviderService::open_with_key_store(
            directory.path().join("member.sqlite3"),
            Arc::new(Mutex::new(())),
            Box::new(MemoryWrappingKeyStore::default()),
        )
        .unwrap();
        let join = member_service
            .prepare_join_request(member.peer_id(), &invitation)
            .unwrap();
        let welcome = owner_service
            .admit_member_at(group_id, &owner, member.peer_id(), join.key_package(), 41)
            .unwrap();
        member_service
            .complete_join(group_id, welcome.welcome().unwrap())
            .unwrap();
        member_service
            .create_message_at(group_id, &member, "Hello from member", 42)
            .unwrap();

        let (request, sequence) = member_service
            .next_push_request(group_id, member.peer_id(), 0)
            .unwrap()
            .unwrap();
        assert_eq!(sequence, 1);
        assert_eq!(
            owner_service.answer_sync_request(member.peer_id(), &request),
            SyncResponse::EventsAccepted {
                group_id,
                inserted: 1,
            }
        );
        assert_eq!(
            owner_service
                .messages(group_id, owner.peer_id())
                .unwrap()
                .messages[0]
                .text,
            "Hello from member"
        );
        assert_eq!(
            owner_service.answer_sync_request(member.peer_id(), &request),
            SyncResponse::EventsAccepted {
                group_id,
                inserted: 0,
            }
        );
    }

    #[test]
    fn membership_commits_advance_existing_members_for_message_fanout() {
        let directory = tempdir().unwrap();
        let group_identity = GroupIdentity::generate();
        let group_id = group_identity.group_id();
        let invitation = invitation(&group_identity);
        let owner = DeviceIdentity::generate();
        let first_member = DeviceIdentity::generate();
        let second_member = DeviceIdentity::generate();
        let owner_service = test_service(directory.path().join("owner.sqlite3"));
        let first_service = test_service(directory.path().join("first.sqlite3"));
        let second_service = test_service(directory.path().join("second.sqlite3"));
        owner_service
            .initialize_owner_group(group_id, &owner)
            .unwrap();

        let first_join = first_service
            .prepare_join_request(first_member.peer_id(), &invitation)
            .unwrap();
        let first_welcome = owner_service
            .admit_member_at(
                group_id,
                &owner,
                first_member.peer_id(),
                first_join.key_package(),
                41,
            )
            .unwrap();
        first_service
            .complete_join(group_id, first_welcome.welcome().unwrap())
            .unwrap();
        pin_joined_owner(&first_service, group_id, owner.peer_id());

        let second_join = second_service
            .prepare_join_request(second_member.peer_id(), &invitation)
            .unwrap();
        let second_welcome = owner_service
            .admit_member_at(
                group_id,
                &owner,
                second_member.peer_id(),
                second_join.key_package(),
                42,
            )
            .unwrap();
        second_service
            .complete_join(group_id, second_welcome.welcome().unwrap())
            .unwrap();
        pin_joined_owner(&second_service, group_id, owner.peer_id());

        pull_all(
            &owner_service,
            &first_service,
            first_member.peer_id(),
            group_id,
        );
        first_service
            .create_message_at(group_id, &first_member, "Hello everyone", 43)
            .unwrap();
        let (push, _) = first_service
            .next_push_request(group_id, first_member.peer_id(), 0)
            .unwrap()
            .unwrap();
        assert_eq!(
            owner_service.answer_sync_request(first_member.peer_id(), &push),
            SyncResponse::EventsAccepted {
                group_id,
                inserted: 1,
            }
        );

        pull_all(
            &owner_service,
            &second_service,
            second_member.peer_id(),
            group_id,
        );
        assert_eq!(
            second_service
                .messages(group_id, second_member.peer_id())
                .unwrap()
                .messages[0]
                .text,
            "Hello everyone"
        );

        owner_service
            .remove_member_at(group_id, &owner, first_member.peer_id(), 44)
            .unwrap();
        pull_all(
            &owner_service,
            &second_service,
            second_member.peer_id(),
            group_id,
        );
        assert!(!second_service
            .group_members(group_id)
            .unwrap()
            .iter()
            .any(|member| member.device_id == first_member.peer_id().to_string()));
        owner_service
            .create_message_at(group_id, &owner, "After removal", 45)
            .unwrap();
        pull_all(
            &owner_service,
            &second_service,
            second_member.peer_id(),
            group_id,
        );
        assert_eq!(
            second_service
                .messages(group_id, second_member.peer_id())
                .unwrap()
                .messages
                .last()
                .unwrap()
                .text,
            "After removal"
        );
        assert_eq!(
            owner_service
                .answer_sync_request(first_member.peer_id(), &SyncRequest::Summary { group_id },),
            SyncResponse::Rejected {
                reason: SyncRejectReason::Unauthorized,
            }
        );
    }

    #[test]
    fn owner_key_refresh_advances_members_without_changing_membership() {
        let directory = tempdir().unwrap();
        let group_identity = GroupIdentity::generate();
        let group_id = group_identity.group_id();
        let invitation = invitation(&group_identity);
        let owner = DeviceIdentity::generate();
        let member = DeviceIdentity::generate();
        let owner_service = test_service(directory.path().join("owner.sqlite3"));
        let member_service = test_service(directory.path().join("member.sqlite3"));
        owner_service
            .initialize_owner_group(group_id, &owner)
            .unwrap();
        let join = member_service
            .prepare_join_request(member.peer_id(), &invitation)
            .unwrap();
        let welcome = owner_service
            .admit_member_at(group_id, &owner, member.peer_id(), join.key_package(), 41)
            .unwrap();
        member_service
            .complete_join(group_id, welcome.welcome().unwrap())
            .unwrap();
        pin_joined_owner(&member_service, group_id, owner.peer_id());
        pull_all(&owner_service, &member_service, member.peer_id(), group_id);

        // Only the owner may refresh the group keys.
        assert_eq!(
            member_service.refresh_group_keys_at(group_id, &member, 42),
            Err("key_refresh_not_allowed")
        );
        owner_service
            .refresh_group_keys_at(group_id, &owner, 43)
            .unwrap();
        let owner_state = owner_service
            .store
            .lock()
            .unwrap()
            .membership_state(group_id)
            .unwrap();
        assert_eq!(owner_state.commits, 2);

        pull_all(&owner_service, &member_service, member.peer_id(), group_id);
        {
            let store = member_service.store.lock().unwrap();
            assert!(store
                .unapplied_mls_commit_events(group_id, charp2p_store::MAX_SYNC_BATCH_EVENTS)
                .unwrap()
                .is_empty());
            assert_eq!(store.membership_state(group_id).unwrap(), owner_state);
        }
        assert_eq!(member_service.group_members(group_id).unwrap().len(), 2);
        owner_service
            .create_message_at(group_id, &owner, "After refresh", 44)
            .unwrap();
        pull_all(&owner_service, &member_service, member.peer_id(), group_id);
        assert_eq!(
            member_service
                .messages(group_id, member.peer_id())
                .unwrap()
                .messages
                .last()
                .unwrap()
                .text,
            "After refresh"
        );
    }

    #[test]
    fn member_serves_pulls_to_current_members_but_not_uploads() {
        let directory = tempdir().unwrap();
        let group_identity = GroupIdentity::generate();
        let group_id = group_identity.group_id();
        let invitation = invitation(&group_identity);
        let owner = DeviceIdentity::generate();
        let first_member = DeviceIdentity::generate();
        let second_member = DeviceIdentity::generate();
        let owner_service = test_service(directory.path().join("owner.sqlite3"));
        let first_service = test_service(directory.path().join("first.sqlite3"));
        let second_service = test_service(directory.path().join("second.sqlite3"));
        owner_service
            .initialize_owner_group(group_id, &owner)
            .unwrap();
        for (service, member, at) in [
            (&first_service, &first_member, 41),
            (&second_service, &second_member, 42),
        ] {
            let join = service
                .prepare_join_request(member.peer_id(), &invitation)
                .unwrap();
            let welcome = owner_service
                .admit_member_at(group_id, &owner, member.peer_id(), join.key_package(), at)
                .unwrap();
            service
                .complete_join(group_id, welcome.welcome().unwrap())
                .unwrap();
            pin_joined_owner(service, group_id, owner.peer_id());
        }
        pull_all(
            &owner_service,
            &first_service,
            first_member.peer_id(),
            group_id,
        );
        first_service
            .create_message_at(group_id, &first_member, "While the owner sleeps", 43)
            .unwrap();

        // The second member pulls the first member's message from it alone.
        pull_all(
            &first_service,
            &second_service,
            second_member.peer_id(),
            group_id,
        );
        assert_eq!(
            second_service
                .messages(group_id, second_member.peer_id())
                .unwrap()
                .messages[0]
                .text,
            "While the owner sleeps"
        );
        assert_eq!(
            first_service.answer_sync_request(
                DeviceIdentity::generate().peer_id(),
                &SyncRequest::Summary { group_id },
            ),
            SyncResponse::Rejected {
                reason: SyncRejectReason::Unauthorized,
            }
        );

        second_service
            .create_message_at(group_id, &second_member, "Upload attempt", 44)
            .unwrap();
        let (push, _) = second_service
            .next_push_request(group_id, second_member.peer_id(), 0)
            .unwrap()
            .unwrap();
        let heads = second_service.report_heads_request(group_id).unwrap();
        for request in [&push, &heads] {
            assert_eq!(
                first_service.answer_sync_request(second_member.peer_id(), request),
                SyncResponse::Rejected {
                    reason: SyncRejectReason::Unauthorized,
                }
            );
        }
        assert_eq!(
            owner_service.answer_sync_request(second_member.peer_id(), &push),
            SyncResponse::EventsAccepted {
                group_id,
                inserted: 1,
            }
        );
    }

    #[test]
    fn member_rendezvous_key_is_shared_per_epoch_and_left_behind_on_removal() {
        let directory = tempdir().unwrap();
        let group_identity = GroupIdentity::generate();
        let group_id = group_identity.group_id();
        let invitation = invitation(&group_identity);
        let owner = DeviceIdentity::generate();
        let first_member = DeviceIdentity::generate();
        let second_member = DeviceIdentity::generate();
        let owner_service = test_service(directory.path().join("owner.sqlite3"));
        let first_service = test_service(directory.path().join("first.sqlite3"));
        let second_service = test_service(directory.path().join("second.sqlite3"));
        owner_service
            .initialize_owner_group(group_id, &owner)
            .unwrap();
        assert_eq!(
            first_service.member_rendezvous_key(group_id),
            Err("mls_joined_group_missing")
        );

        let first_join = first_service
            .prepare_join_request(first_member.peer_id(), &invitation)
            .unwrap();
        let first_welcome = owner_service
            .admit_member_at(
                group_id,
                &owner,
                first_member.peer_id(),
                first_join.key_package(),
                41,
            )
            .unwrap();
        first_service
            .complete_join(group_id, first_welcome.welcome().unwrap())
            .unwrap();
        pin_joined_owner(&first_service, group_id, owner.peer_id());
        let first_epoch_key = owner_service.member_rendezvous_key(group_id).unwrap();
        assert_eq!(
            first_service.member_rendezvous_key(group_id).unwrap(),
            first_epoch_key
        );
        assert_ne!(first_epoch_key, DiscoveryKey::from_invitation(&invitation));

        let second_join = second_service
            .prepare_join_request(second_member.peer_id(), &invitation)
            .unwrap();
        let second_welcome = owner_service
            .admit_member_at(
                group_id,
                &owner,
                second_member.peer_id(),
                second_join.key_package(),
                42,
            )
            .unwrap();
        second_service
            .complete_join(group_id, second_welcome.welcome().unwrap())
            .unwrap();
        pin_joined_owner(&second_service, group_id, owner.peer_id());
        let second_epoch_key = owner_service.member_rendezvous_key(group_id).unwrap();
        assert_ne!(second_epoch_key, first_epoch_key);
        assert_eq!(
            second_service.member_rendezvous_key(group_id).unwrap(),
            second_epoch_key
        );
        // A member behind by a commit still derives the earlier key.
        assert_eq!(
            first_service.member_rendezvous_key(group_id).unwrap(),
            first_epoch_key
        );
        pull_all(
            &owner_service,
            &first_service,
            first_member.peer_id(),
            group_id,
        );
        assert_eq!(
            first_service.member_rendezvous_key(group_id).unwrap(),
            second_epoch_key
        );

        owner_service
            .remove_member_at(group_id, &owner, first_member.peer_id(), 43)
            .unwrap();
        pull_all(
            &owner_service,
            &second_service,
            second_member.peer_id(),
            group_id,
        );
        let third_epoch_key = owner_service.member_rendezvous_key(group_id).unwrap();
        assert_ne!(third_epoch_key, second_epoch_key);
        assert_eq!(
            second_service.member_rendezvous_key(group_id).unwrap(),
            third_epoch_key
        );
        assert_ne!(
            first_service.member_rendezvous_key(group_id).ok(),
            Some(third_epoch_key)
        );
    }

    fn test_service(path: impl AsRef<Path>) -> MlsProviderService {
        MlsProviderService::open_with_key_store(
            path,
            Arc::new(Mutex::new(())),
            Box::new(MemoryWrappingKeyStore::default()),
        )
        .unwrap()
    }

    fn pin_joined_owner(service: &MlsProviderService, group_id: PeerId, owner_id: PeerId) {
        let mut store = service.store.lock().unwrap();
        store
            .put_pending_invitation(&charp2p_store::PendingInvitationMetadata {
                group_id,
                group_name: "Design Crew".to_owned(),
                inviter_name: "Owner".to_owned(),
                expires_at_unix: u64::from(u32::MAX),
                history_policy: charp2p_core::HistoryPolicy::None,
                reusable: true,
            })
            .unwrap();
        assert!(store
            .promote_pending_invitation_to_joined_group(group_id, owner_id)
            .unwrap());
    }

    #[test]
    fn members_apply_membership_commits_only_from_the_pinned_owner() {
        let directory = tempdir().unwrap();
        let group_identity = GroupIdentity::generate();
        let group_id = group_identity.group_id();
        let invitation = invitation(&group_identity);
        let owner = DeviceIdentity::generate();
        let removed = DeviceIdentity::generate();
        let member = DeviceIdentity::generate();
        let owner_service = test_service(directory.path().join("owner.sqlite3"));
        let removed_service = test_service(directory.path().join("removed.sqlite3"));
        let member_service = test_service(directory.path().join("member.sqlite3"));
        owner_service
            .initialize_owner_group(group_id, &owner)
            .unwrap();
        for (service, device, created_at) in [
            (&removed_service, &removed, 41),
            (&member_service, &member, 42),
        ] {
            let join = service
                .prepare_join_request(device.peer_id(), &invitation)
                .unwrap();
            let welcome = owner_service
                .admit_member_at(
                    group_id,
                    &owner,
                    device.peer_id(),
                    join.key_package(),
                    created_at,
                )
                .unwrap();
            service
                .complete_join(group_id, welcome.welcome().unwrap())
                .unwrap();
        }
        // The member pinned a different device as its group owner.
        pin_joined_owner(
            &member_service,
            group_id,
            DeviceIdentity::generate().peer_id(),
        );
        owner_service
            .remove_member_at(group_id, &owner, removed.peer_id(), 43)
            .unwrap();

        pull_all(&owner_service, &member_service, member.peer_id(), group_id);

        let unapplied = member_service
            .store
            .lock()
            .unwrap()
            .unapplied_mls_commit_events(group_id, charp2p_store::MAX_SYNC_BATCH_EVENTS)
            .unwrap();
        assert!(unapplied
            .iter()
            .any(|event| event.kind() == EventKind::MemberRemoved));
        assert!(member_service
            .group_members(group_id)
            .unwrap()
            .iter()
            .any(|entry| entry.device_id == removed.peer_id().to_string()));
    }

    fn pull_all(
        source: &MlsProviderService,
        target: &MlsProviderService,
        target_id: PeerId,
        group_id: PeerId,
    ) {
        let (mut session, mut request) = PullSession::start(group_id);
        loop {
            let response = source.answer_sync_request(target_id, &request);
            let progress = target
                .advance_pull_session(&mut session, &response)
                .unwrap();
            if progress.complete {
                return;
            }
            request = progress.next_request.unwrap();
        }
    }

    fn decrypt_application_message(
        group: &mut MlsGroup,
        provider: &ProfileProvider,
        event: &SignedEvent,
    ) -> Vec<u8> {
        let message = decode_profile_message(event.protected_payload()).unwrap();
        let protocol: ProtocolMessage = message.try_into_protocol_message().unwrap();
        let processed = group.process_message(provider, protocol).unwrap();
        let ProcessedMessageContent::ApplicationMessage(application) = processed.into_content()
        else {
            panic!("expected an MLS application message");
        };
        application.into_bytes()
    }

    #[test]
    fn synchronization_is_served_only_to_an_mls_group_member() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("charp2p.sqlite3");
        let group_id = GroupIdentity::generate().group_id();
        let owner = DeviceIdentity::generate();
        let member_id = DeviceIdentity::generate().peer_id();
        let (_, key_package) = member_key_package(member_id);
        let service = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(MemoryWrappingKeyStore::default()),
        )
        .unwrap();
        service.initialize_owner_group(group_id, &owner).unwrap();
        service
            .admit_member_at(group_id, &owner, member_id, key_package.encoded(), 42)
            .unwrap();

        let request = SyncRequest::Summary { group_id };
        let response = service.answer_sync_request(member_id, &request);
        let SyncResponse::Summary {
            group_id: response_group,
            heads,
            membership,
        } = response
        else {
            panic!("member should receive a synchronization summary");
        };
        assert_eq!(response_group, group_id);
        assert_eq!(heads.len(), 1);
        assert_eq!(heads[0].author_id, owner.peer_id());
        assert_eq!(heads[0].contiguous_sequence, 2);
        assert_eq!(membership.commits, 1);
        assert!(membership.latest_commit.is_some());
        assert_eq!(
            service.answer_sync_request(DeviceIdentity::generate().peer_id(), &request),
            SyncResponse::Rejected {
                reason: SyncRejectReason::Unauthorized,
            }
        );
    }

    #[test]
    fn joined_member_materializes_only_messages_from_readable_epochs() {
        let directory = tempdir().unwrap();
        let owner_path = directory.path().join("owner.sqlite3");
        let member_path = directory.path().join("member.sqlite3");
        let group_identity = GroupIdentity::generate();
        let group_id = group_identity.group_id();
        let invitation = invitation(&group_identity);
        let owner = DeviceIdentity::generate();
        let member_id = DeviceIdentity::generate().peer_id();
        let owner_service = MlsProviderService::open_with_key_store(
            &owner_path,
            Arc::new(Mutex::new(())),
            Box::new(MemoryWrappingKeyStore::default()),
        )
        .unwrap();
        owner_service
            .initialize_owner_group(group_id, &owner)
            .unwrap();
        owner_service
            .create_message_at(group_id, &owner, "Before join", 41)
            .unwrap();
        let member_service = MlsProviderService::open_with_key_store(
            &member_path,
            Arc::new(Mutex::new(())),
            Box::new(MemoryWrappingKeyStore::default()),
        )
        .unwrap();
        let request = member_service
            .prepare_join_request(member_id, &invitation)
            .unwrap();
        let welcome = owner_service
            .admit_member_at(group_id, &owner, member_id, request.key_package(), 42)
            .unwrap();
        member_service
            .complete_join(group_id, welcome.welcome().unwrap())
            .unwrap();
        owner_service
            .create_message_at(group_id, &owner, "After join", 43)
            .unwrap();

        let (mut session, mut request) = PullSession::start(group_id);
        let mut inserted = 0;
        loop {
            let response = owner_service.answer_sync_request(member_id, &request);
            let progress = member_service
                .advance_pull_session(&mut session, &response)
                .unwrap();
            inserted += progress.applied.inserted;
            if progress.complete {
                break;
            }
            request = progress.next_request.unwrap();
        }

        assert_eq!(inserted, 4);
        assert_eq!(
            member_service.unread_message_counts().unwrap(),
            vec![UnreadMessageCount {
                group_id: group_id.to_string(),
                count: 1,
            }]
        );
        assert_eq!(
            member_service
                .messages(group_id, member_id)
                .unwrap()
                .messages
                .iter()
                .map(|message| message.text.as_str())
                .collect::<Vec<_>>(),
            vec!["After join"]
        );
        assert!(member_service.unread_message_counts().unwrap().is_empty());
        let store = EventStore::open(member_path).unwrap();
        let event_ids = store
            .event_ids_after(group_id, owner.peer_id(), 0, 4)
            .unwrap();
        assert_eq!(event_ids.len(), 4);
        assert_eq!(
            store.get_event(event_ids[2]).unwrap().unwrap().kind(),
            EventKind::MemberAdded
        );
    }

    #[test]
    fn locally_blocked_device_still_advances_sync_but_stays_hidden() {
        let directory = tempdir().unwrap();
        let group_identity = GroupIdentity::generate();
        let group_id = group_identity.group_id();
        let invitation = invitation(&group_identity);
        let owner = DeviceIdentity::generate();
        let member_id = DeviceIdentity::generate().peer_id();
        let owner_service = MlsProviderService::open_with_key_store(
            directory.path().join("owner.sqlite3"),
            Arc::new(Mutex::new(())),
            Box::new(MemoryWrappingKeyStore::default()),
        )
        .unwrap();
        owner_service
            .initialize_owner_group(group_id, &owner)
            .unwrap();
        let member_service = MlsProviderService::open_with_key_store(
            directory.path().join("member.sqlite3"),
            Arc::new(Mutex::new(())),
            Box::new(MemoryWrappingKeyStore::default()),
        )
        .unwrap();
        let request = member_service
            .prepare_join_request(member_id, &invitation)
            .unwrap();
        let welcome = owner_service
            .admit_member_at(group_id, &owner, member_id, request.key_package(), 42)
            .unwrap();
        member_service
            .complete_join(group_id, welcome.welcome().unwrap())
            .unwrap();
        owner_service
            .create_message_at(group_id, &owner, "Blocked text", 43)
            .unwrap();

        assert_eq!(
            member_service
                .set_device_blocked_locally(group_id, owner.peer_id(), true)
                .unwrap(),
            vec![owner.peer_id().to_string()]
        );
        let (mut session, mut request) = PullSession::start(group_id);
        loop {
            let response = owner_service.answer_sync_request(member_id, &request);
            let progress = member_service
                .advance_pull_session(&mut session, &response)
                .unwrap();
            if progress.complete {
                break;
            }
            request = progress.next_request.unwrap();
        }

        assert!(member_service.unread_message_counts().unwrap().is_empty());
        assert!(member_service
            .messages(group_id, member_id)
            .unwrap()
            .messages
            .is_empty());
        assert!(member_service
            .set_device_blocked_locally(group_id, owner.peer_id(), false)
            .unwrap()
            .is_empty());
        assert!(member_service.blocked_devices(group_id).unwrap().is_empty());
        assert_eq!(
            member_service
                .messages(group_id, member_id)
                .unwrap()
                .messages
                .iter()
                .map(|message| message.text.as_str())
                .collect::<Vec<_>>(),
            vec!["Blocked text"]
        );
    }

    #[test]
    fn new_admission_shares_current_metadata_with_the_late_joiner_once() {
        let directory = tempdir().unwrap();
        let group_identity = GroupIdentity::generate();
        let group_id = group_identity.group_id();
        let invitation = invitation(&group_identity);
        let owner = DeviceIdentity::generate();
        let member_id = DeviceIdentity::generate().peer_id();
        let owner_service = test_service(directory.path().join("owner.sqlite3"));
        owner_service
            .initialize_owner_group(group_id, &owner)
            .unwrap();
        // Renamed before the member joins, in an epoch it cannot decrypt.
        owner_service
            .change_group_metadata(
                group_id,
                &owner,
                &charp2p_core::GroupMetadata::new("Renamed Crew")
                    .unwrap()
                    .with_icon(1)
                    .unwrap(),
            )
            .unwrap();
        let member_service = test_service(directory.path().join("member.sqlite3"));
        let request = member_service
            .prepare_join_request(member_id, &invitation)
            .unwrap();
        let welcome = owner_service
            .admit_member_sharing_metadata_at(
                group_id,
                &owner,
                member_id,
                request.key_package(),
                None,
                "Design Crew",
                4,
                42,
            )
            .unwrap();
        let retried = owner_service
            .admit_member_sharing_metadata_at(
                group_id,
                &owner,
                member_id,
                request.key_package(),
                None,
                "Design Crew",
                4,
                43,
            )
            .unwrap();
        assert_eq!(retried.encode().unwrap(), welcome.encode().unwrap());
        {
            let store = owner_service.store.lock().unwrap();
            let kinds = store
                .event_ids_after(group_id, owner.peer_id(), 0, 10)
                .unwrap()
                .into_iter()
                .map(|id| store.get_event(id).unwrap().unwrap().kind())
                .collect::<Vec<_>>();
            assert_eq!(
                kinds,
                vec![
                    EventKind::GroupCreated,
                    EventKind::GroupMetadataChanged,
                    EventKind::MemberAdded,
                    EventKind::GroupMetadataChanged,
                ]
            );
        }

        member_service
            .complete_join(group_id, welcome.welcome().unwrap())
            .unwrap();
        {
            let mut store = member_service.store.lock().unwrap();
            store
                .put_pending_invitation(&charp2p_store::PendingInvitationMetadata {
                    group_id,
                    group_name: "Design Crew".to_owned(),
                    inviter_name: "Owner".to_owned(),
                    expires_at_unix: u64::from(u32::MAX),
                    history_policy: charp2p_core::HistoryPolicy::None,
                    reusable: false,
                })
                .unwrap();
            assert!(store
                .promote_pending_invitation_to_joined_group(group_id, owner.peer_id())
                .unwrap());
        }
        pull_all(&owner_service, &member_service, member_id, group_id);
        assert_eq!(
            member_service.current_group_names().unwrap(),
            vec![(group_id, "Renamed Crew".to_owned())]
        );
        assert_eq!(
            member_service.current_group_icons().unwrap(),
            vec![(group_id, 4)]
        );
    }

    #[test]
    fn owner_rename_reaches_members_and_other_authors_are_ignored() {
        let directory = tempdir().unwrap();
        let group_identity = GroupIdentity::generate();
        let group_id = group_identity.group_id();
        let invitation = invitation(&group_identity);
        let owner = DeviceIdentity::generate();
        let member = DeviceIdentity::generate();
        let member_id = member.peer_id();
        let owner_service = test_service(directory.path().join("owner.sqlite3"));
        owner_service
            .initialize_owner_group(group_id, &owner)
            .unwrap();
        let member_service = test_service(directory.path().join("member.sqlite3"));
        let request = member_service
            .prepare_join_request(member_id, &invitation)
            .unwrap();
        let welcome = owner_service
            .admit_member_at(group_id, &owner, member_id, request.key_package(), 42)
            .unwrap();
        member_service
            .complete_join(group_id, welcome.welcome().unwrap())
            .unwrap();
        {
            let mut store = member_service.store.lock().unwrap();
            store
                .put_pending_invitation(&charp2p_store::PendingInvitationMetadata {
                    group_id,
                    group_name: "Design Crew".to_owned(),
                    inviter_name: "Owner".to_owned(),
                    expires_at_unix: u64::from(u32::MAX),
                    history_policy: charp2p_core::HistoryPolicy::None,
                    reusable: false,
                })
                .unwrap();
            assert!(store
                .promote_pending_invitation_to_joined_group(group_id, owner.peer_id())
                .unwrap());
        }

        // A member device cannot rename the group for others.
        assert_eq!(
            member_service.change_group_metadata(
                group_id,
                &member,
                &charp2p_core::GroupMetadata::new("Hijacked").unwrap()
            ),
            Err("group_not_owned")
        );
        let hijack = charp2p_core::GroupMetadata::new("Hijacked")
            .unwrap()
            .encode()
            .unwrap();
        let forged = member_service
            .create_application_event_at(
                group_id,
                &member,
                EventKind::GroupMetadataChanged,
                &hijack,
                42,
                |store, event, _, _| {
                    store.put_event(event).unwrap();
                    Ok(())
                },
            )
            .unwrap();
        owner_service
            .change_group_metadata(
                group_id,
                &owner,
                &charp2p_core::GroupMetadata::new("Old Name").unwrap(),
            )
            .unwrap();
        owner_service
            .create_message_at(group_id, &owner, "After rename", 43)
            .unwrap();
        owner_service
            .change_group_metadata(
                group_id,
                &owner,
                &charp2p_core::GroupMetadata::new("Renamed Crew")
                    .unwrap()
                    .with_icon(3)
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(
            owner_service.current_group_names().unwrap(),
            vec![(group_id, "Renamed Crew".to_owned())]
        );
        {
            let mut owner_store = owner_service.store.lock().unwrap();
            owner_store.put_event(&forged).unwrap();
            let mut provider = owner_service.provider.lock().unwrap();
            owner_service
                .materialize_pending_messages(&mut provider, &mut owner_store, group_id)
                .unwrap();
        }
        assert_eq!(
            owner_service.current_group_names().unwrap(),
            vec![(group_id, "Renamed Crew".to_owned())]
        );

        pull_all(&owner_service, &member_service, member_id, group_id);
        assert_eq!(
            member_service.current_group_names().unwrap(),
            vec![(group_id, "Renamed Crew".to_owned())]
        );
        assert_eq!(
            member_service.current_group_icons().unwrap(),
            vec![(group_id, 3)]
        );
        assert_eq!(
            member_service
                .messages(group_id, member_id)
                .unwrap()
                .messages
                .iter()
                .map(|message| message.text.as_str())
                .collect::<Vec<_>>(),
            vec!["After rename"]
        );
    }

    #[test]
    fn owner_invite_permission_reaches_members_and_member_grants_are_ignored() {
        let directory = tempdir().unwrap();
        let group_identity = GroupIdentity::generate();
        let group_id = group_identity.group_id();
        let invitation = invitation(&group_identity);
        let owner = DeviceIdentity::generate();
        let member = DeviceIdentity::generate();
        let member_id = member.peer_id();
        let owner_service = test_service(directory.path().join("owner.sqlite3"));
        owner_service
            .initialize_owner_group(group_id, &owner)
            .unwrap();
        let member_service = test_service(directory.path().join("member.sqlite3"));
        let request = member_service
            .prepare_join_request(member_id, &invitation)
            .unwrap();
        let welcome = owner_service
            .admit_member_at(group_id, &owner, member_id, request.key_package(), 42)
            .unwrap();
        member_service
            .complete_join(group_id, welcome.welcome().unwrap())
            .unwrap();
        {
            let mut store = member_service.store.lock().unwrap();
            store
                .put_pending_invitation(&charp2p_store::PendingInvitationMetadata {
                    group_id,
                    group_name: "Design Crew".to_owned(),
                    inviter_name: "Owner".to_owned(),
                    expires_at_unix: u64::from(u32::MAX),
                    history_policy: charp2p_core::HistoryPolicy::None,
                    reusable: false,
                })
                .unwrap();
            assert!(store
                .promote_pending_invitation_to_joined_group(group_id, owner.peer_id())
                .unwrap());
        }

        // A member cannot grant itself permission on the owner's device.
        let forged = member_service
            .create_application_event_at(
                group_id,
                &member,
                EventKind::InvitePermissionChanged,
                &charp2p_core::InvitePermission::new(member_id, true)
                    .encode()
                    .unwrap(),
                42,
                |store, event, _, _| {
                    store.put_event(event).unwrap();
                    Ok(())
                },
            )
            .unwrap();
        {
            let mut owner_store = owner_service.store.lock().unwrap();
            owner_store.put_event(&forged).unwrap();
            let mut provider = owner_service.provider.lock().unwrap();
            owner_service
                .materialize_pending_messages(&mut provider, &mut owner_store, group_id)
                .unwrap();
            assert!(!owner_store
                .has_invite_permission(group_id, member_id)
                .unwrap());
        }

        let grant = charp2p_core::InvitePermission::new(member_id, true);
        owner_service
            .create_application_event_at(
                group_id,
                &owner,
                EventKind::InvitePermissionChanged,
                &grant.encode().unwrap(),
                43,
                |store, event, snapshot, _| {
                    store
                        .put_invite_permission_and_encrypted_mls_provider_snapshot(
                            event, snapshot, &grant,
                        )
                        .map(|_| ())
                        .map_err(|_| "message_store_unavailable")
                },
            )
            .unwrap();
        pull_all(&owner_service, &member_service, member_id, group_id);
        assert_eq!(
            member_service
                .store
                .lock()
                .unwrap()
                .invite_permitted_devices(group_id)
                .unwrap(),
            vec![member_id]
        );
    }

    #[test]
    fn owner_grants_and_withdraws_invite_permission_for_current_members_only() {
        let directory = tempdir().unwrap();
        let group_identity = GroupIdentity::generate();
        let group_id = group_identity.group_id();
        let invitation = invitation(&group_identity);
        let owner = DeviceIdentity::generate();
        let member = DeviceIdentity::generate();
        let member_id = member.peer_id();
        let owner_service = test_service(directory.path().join("owner.sqlite3"));
        owner_service
            .initialize_owner_group(group_id, &owner)
            .unwrap();
        let member_service = test_service(directory.path().join("member.sqlite3"));
        let request = member_service
            .prepare_join_request(member_id, &invitation)
            .unwrap();
        let welcome = owner_service
            .admit_member_at(group_id, &owner, member_id, request.key_package(), 42)
            .unwrap();
        member_service
            .complete_join(group_id, welcome.welcome().unwrap())
            .unwrap();

        assert_eq!(
            owner_service.change_invite_permission_at(group_id, &owner, owner.peer_id(), true, 43),
            Err("invite_permission_owner")
        );
        assert_eq!(
            owner_service.change_invite_permission_at(
                group_id,
                &owner,
                DeviceIdentity::generate().peer_id(),
                true,
                43
            ),
            Err("member_not_found")
        );
        assert_eq!(
            owner_service
                .change_invite_permission_at(group_id, &owner, member_id, true, 43)
                .unwrap(),
            vec![member_id]
        );
        // Repeating the current state authors no further event.
        let events = owner_events(&owner_service, group_id, &owner);
        assert_eq!(
            owner_service
                .change_invite_permission_at(group_id, &owner, member_id, true, 44)
                .unwrap(),
            vec![member_id]
        );
        assert_eq!(owner_events(&owner_service, group_id, &owner), events);
        assert_eq!(
            owner_service
                .change_invite_permission_at(group_id, &owner, member_id, false, 45)
                .unwrap(),
            Vec::<PeerId>::new()
        );
        assert!(owner_service
            .invite_permitted_devices(group_id)
            .unwrap()
            .is_empty());
    }

    fn owner_events(
        service: &MlsProviderService,
        group_id: PeerId,
        owner: &DeviceIdentity,
    ) -> usize {
        service
            .store
            .lock()
            .unwrap()
            .event_ids_after(group_id, owner.peer_id(), 0, 100)
            .unwrap()
            .len()
    }

    #[test]
    fn own_message_edits_reach_peers_and_foreign_edits_are_refused() {
        let directory = tempdir().unwrap();
        let group_identity = GroupIdentity::generate();
        let group_id = group_identity.group_id();
        let invitation = invitation(&group_identity);
        let owner = DeviceIdentity::generate();
        let member = DeviceIdentity::generate();
        let member_id = member.peer_id();
        let owner_service = test_service(directory.path().join("owner.sqlite3"));
        owner_service
            .initialize_owner_group(group_id, &owner)
            .unwrap();
        let member_service = test_service(directory.path().join("member.sqlite3"));
        let request = member_service
            .prepare_join_request(member_id, &invitation)
            .unwrap();
        let welcome = owner_service
            .admit_member_at(group_id, &owner, member_id, request.key_package(), 42)
            .unwrap();
        member_service
            .complete_join(group_id, welcome.welcome().unwrap())
            .unwrap();

        let owner_message = owner_service
            .create_message_at(group_id, &owner, "Owner typo", 43)
            .unwrap();
        let member_message = member_service
            .create_message_at(group_id, &member, "Member typo", 44)
            .unwrap();
        let owner_target = *owner_message.id().as_bytes();
        let member_target = *member_message.id().as_bytes();
        owner_service
            .edit_message(group_id, &owner, &owner_target, "Owner fixed")
            .unwrap();
        member_service
            .edit_message(group_id, &member, &member_target, "Member fixed")
            .unwrap();
        assert_eq!(
            member_service.edit_message(group_id, &member, &owner_target, "Hijacked"),
            Err("message_not_found")
        );
        assert_eq!(
            member_service.edit_message(group_id, &member, &member_target, " "),
            Err("message_invalid")
        );

        let (push, sequence) = member_service
            .next_push_request(group_id, member_id, 0)
            .unwrap()
            .unwrap();
        assert_eq!(sequence, 2);
        assert_eq!(
            owner_service.answer_sync_request(member_id, &push),
            SyncResponse::EventsAccepted {
                group_id,
                inserted: 2,
            }
        );
        assert_eq!(
            owner_service.edit_message(group_id, &owner, &member_target, "Hijacked"),
            Err("message_not_own")
        );
        pull_all(&owner_service, &member_service, member_id, group_id);

        for (service, local) in [
            (&owner_service, owner.peer_id()),
            (&member_service, member_id),
        ] {
            let mut messages = service
                .messages(group_id, local)
                .unwrap()
                .messages
                .into_iter()
                .map(|message| (message.text, message.edited))
                .collect::<Vec<_>>();
            messages.sort();
            assert_eq!(
                messages,
                vec![
                    ("Member fixed".to_owned(), true),
                    ("Owner fixed".to_owned(), true)
                ]
            );
        }
    }

    #[test]
    fn own_message_deletions_reach_peers_and_foreign_deletions_are_refused() {
        let directory = tempdir().unwrap();
        let group_identity = GroupIdentity::generate();
        let group_id = group_identity.group_id();
        let invitation = invitation(&group_identity);
        let owner = DeviceIdentity::generate();
        let member = DeviceIdentity::generate();
        let member_id = member.peer_id();
        let owner_service = test_service(directory.path().join("owner.sqlite3"));
        owner_service
            .initialize_owner_group(group_id, &owner)
            .unwrap();
        let member_service = test_service(directory.path().join("member.sqlite3"));
        let request = member_service
            .prepare_join_request(member_id, &invitation)
            .unwrap();
        let welcome = owner_service
            .admit_member_at(group_id, &owner, member_id, request.key_package(), 42)
            .unwrap();
        member_service
            .complete_join(group_id, welcome.welcome().unwrap())
            .unwrap();

        let owner_message = owner_service
            .create_message_at(group_id, &owner, "Owner kept", 43)
            .unwrap();
        let member_message = member_service
            .create_message_at(group_id, &member, "Member regret", 44)
            .unwrap();
        member_service
            .create_message_at(group_id, &member, "Member kept", 45)
            .unwrap();
        let owner_target = *owner_message.id().as_bytes();
        let member_target = *member_message.id().as_bytes();
        member_service
            .delete_message(group_id, &member, &member_target)
            .unwrap();
        assert_eq!(
            member_service.delete_message(group_id, &member, &member_target),
            Err("message_not_found")
        );
        assert_eq!(
            member_service.delete_message(group_id, &member, &owner_target),
            Err("message_not_found")
        );

        let (push, sequence) = member_service
            .next_push_request(group_id, member_id, 0)
            .unwrap()
            .unwrap();
        assert_eq!(sequence, 3);
        assert_eq!(
            owner_service.answer_sync_request(member_id, &push),
            SyncResponse::EventsAccepted {
                group_id,
                inserted: 3,
            }
        );
        assert_eq!(
            owner_service.delete_message(group_id, &owner, &member_target),
            Err("message_not_found")
        );
        pull_all(&owner_service, &member_service, member_id, group_id);

        for (service, local) in [
            (&owner_service, owner.peer_id()),
            (&member_service, member_id),
        ] {
            let mut messages = service
                .messages(group_id, local)
                .unwrap()
                .messages
                .into_iter()
                .map(|message| message.text)
                .collect::<Vec<_>>();
            messages.sort();
            assert_eq!(
                messages,
                vec!["Member kept".to_owned(), "Owner kept".to_owned()]
            );
        }
    }

    #[test]
    fn evidence_exports_selected_signed_envelopes_with_displayed_text() {
        let directory = tempdir().unwrap();
        let group_id = GroupIdentity::generate().group_id();
        let other_group_id = GroupIdentity::generate().group_id();
        let owner = DeviceIdentity::generate();
        let service = test_service(directory.path().join("owner.sqlite3"));
        service.initialize_owner_group(group_id, &owner).unwrap();
        service
            .initialize_owner_group(other_group_id, &owner)
            .unwrap();
        let first = service
            .create_message_at(group_id, &owner, "First", 43)
            .unwrap();
        let second = service
            .create_message_at(group_id, &owner, "Second typo", 44)
            .unwrap();
        let foreign = service
            .create_message_at(other_group_id, &owner, "Elsewhere", 45)
            .unwrap();
        let second_id = *second.id().as_bytes();
        service
            .edit_message(group_id, &owner, &second_id, "Second fixed")
            .unwrap();

        let export = service
            .evidence(
                group_id,
                owner.peer_id(),
                &[second_id, *first.id().as_bytes(), second_id],
                99,
            )
            .unwrap();
        assert_eq!(export.format, "charp2p-evidence-v1");
        assert_eq!(export.generated_at_unix_ms, 99);
        assert_eq!(export.group_id, group_id.to_string());
        assert_eq!(export.exported_by_device_id, owner.peer_id().to_string());
        assert_eq!(
            export
                .events
                .iter()
                .map(|event| (event.displayed_text.as_str(), event.edit.is_some()))
                .collect::<Vec<_>>(),
            vec![("First", false), ("Second fixed", true)]
        );
        for event in &export.events {
            let envelope = SignedEvent::decode(&decode_hex(&event.signed_event_hex)).unwrap();
            assert_eq!(hex_bytes(envelope.id().as_bytes()), event.event_id);
            assert_eq!(envelope.author_id().to_string(), event.author_id);
            assert_eq!(envelope.kind(), EventKind::MessageCreated);
        }
        let edit = export.events[1].edit.as_ref().unwrap();
        let edit_envelope = SignedEvent::decode(&decode_hex(&edit.signed_event_hex)).unwrap();
        assert_eq!(hex_bytes(edit_envelope.id().as_bytes()), edit.event_id);
        assert_eq!(edit_envelope.kind(), EventKind::MessageEdited);

        assert_eq!(
            service.evidence(group_id, owner.peer_id(), &[], 99),
            Err("evidence_selection_invalid")
        );
        assert_eq!(
            service.evidence(
                group_id,
                owner.peer_id(),
                &[[7; 32]; MAX_EVIDENCE_EVENTS + 1],
                99
            ),
            Err("evidence_selection_invalid")
        );
        assert_eq!(
            service.evidence(group_id, owner.peer_id(), &[*foreign.id().as_bytes()], 99),
            Err("message_not_found")
        );
        assert_eq!(
            service.evidence(
                group_id,
                owner.peer_id(),
                &[*edit_envelope.id().as_bytes()],
                99
            ),
            Err("message_not_found")
        );
    }

    fn decode_hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|offset| u8::from_str_radix(&text[offset..offset + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn reply_reference_reaches_peers_inside_the_protected_payload() {
        let directory = tempdir().unwrap();
        let group_identity = GroupIdentity::generate();
        let group_id = group_identity.group_id();
        let invitation = invitation(&group_identity);
        let owner = DeviceIdentity::generate();
        let member = DeviceIdentity::generate();
        let member_id = member.peer_id();
        let owner_service = test_service(directory.path().join("owner.sqlite3"));
        owner_service
            .initialize_owner_group(group_id, &owner)
            .unwrap();
        let member_service = test_service(directory.path().join("member.sqlite3"));
        let request = member_service
            .prepare_join_request(member_id, &invitation)
            .unwrap();
        let welcome = owner_service
            .admit_member_at(group_id, &owner, member_id, request.key_package(), 42)
            .unwrap();
        member_service
            .complete_join(group_id, welcome.welcome().unwrap())
            .unwrap();
        let question = owner_service
            .create_message_at(group_id, &owner, "Lunch at noon?", 43)
            .unwrap();
        let target = *question.id().as_bytes();
        assert!(matches!(
            member_service.create_body_at(
                group_id,
                &member,
                &super::MessageBody::new("Yes", Some(target)).unwrap(),
                44,
            ),
            Err("message_not_found")
        ));
        pull_all(&owner_service, &member_service, member_id, group_id);

        let reply = member_service
            .create_body_at(
                group_id,
                &member,
                &super::MessageBody::new("Yes", Some(target)).unwrap(),
                44,
            )
            .unwrap();
        assert!(
            !reply
                .protected_payload()
                .windows(target.len())
                .any(|window| window == target),
            "reply reference is MLS-protected"
        );
        let (push, _) = member_service
            .next_push_request(group_id, member_id, 0)
            .unwrap()
            .unwrap();
        assert_eq!(
            owner_service.answer_sync_request(member_id, &push),
            SyncResponse::EventsAccepted {
                group_id,
                inserted: 1,
            }
        );

        let target_hex = super::hex_bytes(&target);
        for (service, local) in [
            (&owner_service, owner.peer_id()),
            (&member_service, member_id),
        ] {
            let messages = service
                .messages(group_id, local)
                .unwrap()
                .messages
                .into_iter()
                .map(|message| (message.text, message.reply_to_event_id))
                .collect::<Vec<_>>();
            assert_eq!(
                messages,
                vec![
                    ("Lunch at noon?".to_owned(), None),
                    ("Yes".to_owned(), Some(target_hex.clone())),
                ]
            );
        }
    }

    #[test]
    fn rejected_member_admission_restores_provider_and_writes_no_event() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("charp2p.sqlite3");
        let group_id = GroupIdentity::generate().group_id();
        let owner = DeviceIdentity::generate();
        let service = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(MemoryWrappingKeyStore::default()),
        )
        .unwrap();
        service.initialize_owner_group(group_id, &owner).unwrap();
        let before = service
            .read(|provider| provider.snapshot().unwrap())
            .unwrap();

        assert!(matches!(
            service.admit_member_at(
                group_id,
                &owner,
                DeviceIdentity::generate().peer_id(),
                &[1],
                42,
            ),
            Err(MemberAdmissionError::Unauthorized)
        ));
        assert_eq!(
            service
                .read(|provider| provider.snapshot().unwrap())
                .unwrap()
                .as_slice(),
            before.as_slice()
        );
        let store = EventStore::open(&path).unwrap();
        let event_ids = store
            .event_ids_after(group_id, owner.peer_id(), 0, 2)
            .unwrap();
        assert_eq!(event_ids.len(), 1);
        assert_eq!(
            store.get_event(event_ids[0]).unwrap().unwrap().kind(),
            EventKind::GroupCreated
        );
    }

    #[test]
    fn restored_owner_group_rejects_a_different_device() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("charp2p.sqlite3");
        let group_id = GroupIdentity::generate().group_id();
        let owner = DeviceIdentity::generate();
        let service = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(MemoryWrappingKeyStore::default()),
        )
        .unwrap();
        service.initialize_owner_group(group_id, &owner).unwrap();
        let before = service
            .read(|provider| provider.snapshot().unwrap())
            .unwrap();

        assert_eq!(
            service.initialize_owner_group(group_id, &DeviceIdentity::generate()),
            Err("mls_group_owner_mismatch")
        );
        assert_eq!(
            service
                .read(|provider| provider.snapshot().unwrap())
                .unwrap()
                .as_slice(),
            before.as_slice()
        );
    }

    #[test]
    fn encrypted_snapshot_restores_provider_after_restart() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("charp2p.sqlite3");
        let key_store = MemoryWrappingKeyStore::default();
        let service = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(key_store.clone()),
        )
        .unwrap();

        service
            .mutate(|provider| {
                add_key_package(provider);
                Ok::<_, ()>(())
            })
            .unwrap();
        let expected = service
            .read(|provider| provider.snapshot().unwrap())
            .unwrap();
        drop(service);

        let encrypted = EventStore::open(&path)
            .unwrap()
            .encrypted_mls_provider_snapshot()
            .unwrap()
            .unwrap();
        assert_ne!(encrypted.as_slice(), expected.as_slice());

        let restored = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(key_store),
        )
        .unwrap();
        assert_eq!(
            restored
                .read(|provider| provider.snapshot().unwrap())
                .unwrap()
                .as_slice(),
            expected.as_slice()
        );
    }

    #[test]
    fn tampered_snapshot_fails_closed() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("charp2p.sqlite3");
        let key_store = MemoryWrappingKeyStore::default();
        let service = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(key_store.clone()),
        )
        .unwrap();
        service
            .mutate(|provider| {
                add_key_package(provider);
                Ok::<_, ()>(())
            })
            .unwrap();
        drop(service);

        let mut store = EventStore::open(&path).unwrap();
        let mut encrypted = store.encrypted_mls_provider_snapshot().unwrap().unwrap();
        *encrypted.last_mut().unwrap() ^= 1;
        store
            .put_encrypted_mls_provider_snapshot(&encrypted)
            .unwrap();
        drop(store);

        let error = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(key_store),
        )
        .err();
        assert_eq!(error, Some("mls_provider_snapshot_invalid"));
    }

    #[test]
    fn persisted_snapshot_without_wrapping_key_fails_closed() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("charp2p.sqlite3");
        let service = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(MemoryWrappingKeyStore::default()),
        )
        .unwrap();
        service
            .mutate(|provider| {
                add_key_package(provider);
                Ok::<_, ()>(())
            })
            .unwrap();
        drop(service);

        let error = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(MemoryWrappingKeyStore::default()),
        )
        .err();
        assert_eq!(error, Some("mls_wrapping_key_missing"));
    }

    #[test]
    fn failed_mutation_restores_provider_without_persisting() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("charp2p.sqlite3");
        let service = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(MemoryWrappingKeyStore::default()),
        )
        .unwrap();
        let before = service
            .read(|provider| provider.snapshot().unwrap())
            .unwrap();

        let result = service.mutate(|provider| {
            add_key_package(provider);
            Err::<(), _>("rejected")
        });
        assert!(matches!(
            result,
            Err(MlsProviderMutationError::Operation("rejected"))
        ));
        assert_eq!(
            service
                .read(|provider| provider.snapshot().unwrap())
                .unwrap()
                .as_slice(),
            before.as_slice()
        );
        assert!(EventStore::open(&path)
            .unwrap()
            .encrypted_mls_provider_snapshot()
            .unwrap()
            .is_none());
    }
}
