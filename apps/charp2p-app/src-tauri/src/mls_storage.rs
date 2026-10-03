use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use charp2p_core::{
    DeviceIdentity, EventId, EventKind, EventSpec, Invitation, JoinRequest, JoinResponse, PeerId,
    SignedEvent, SyncRejectReason, SyncRequest, SyncResponse, MAX_SYNC_BATCH_ITEMS,
    MAX_SYNC_RESPONSE_BYTES,
};
use charp2p_mls::{
    decode_profile_message, device_credential, device_id_from_credential, group_create_config,
    merge_prepared_member_admission, prepare_profile_key_package, prepare_profile_member_admission,
    stage_profile_welcome, validate_group_profile, validate_profile_key_package,
    PrepareMemberAdmissionError, ProfileKeyPackageError, ProfileProvider, CIPHERSUITE,
    MAX_MLS_WIRE_BYTES,
};
use charp2p_store::{
    EventStore, MAX_ENCRYPTED_MESSAGE_BODY_BYTES, MAX_ENCRYPTED_MLS_PROVIDER_SNAPSHOT_BYTES,
};
use charp2p_sync::{
    accept_pushed_events, build_authorized_response, PullSession, SessionProgress,
    SynchronizationError,
};
use keyring_core::Error as KeyringError;
use openmls::prelude::{
    CredentialWithKey, GroupId, MlsGroup, OpenMlsProvider, ProcessedMessageContent, ProtocolMessage,
};
use openmls_basic_credential::SignatureKeyPair;
use serde::Serialize as SerdeSerialize;
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
const MAX_MESSAGE_TEXT_BYTES: usize = 16 * 1024;

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
    pub created_at_unix_ms: u64,
    pub text: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MemberAdmissionError {
    Unauthorized,
    UnsupportedProfile,
    Unavailable,
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
        device_id: PeerId,
    ) -> Result<(), &'static str> {
        self.mutate(|provider| initialize_owner_group(provider, group_id, device_id))
            .map_err(|error| match error {
                MlsProviderMutationError::Operation(error)
                | MlsProviderMutationError::Unavailable(error) => error,
            })
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

    pub(crate) fn create_message(
        &self,
        group_id: PeerId,
        author: &DeviceIdentity,
        message: &str,
    ) -> Result<CreatedMessage, &'static str> {
        let created_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .ok_or("system_clock_invalid")?;
        let event = self.create_message_at(group_id, author, message, created_at_unix_ms)?;
        Ok(CreatedMessage {
            event_id: hex_bytes(event.id().as_bytes()),
            group_id: event.group_id().to_string(),
            author_id: event.author_id().to_string(),
            author_sequence: event.author_sequence(),
            created_at_unix_ms: event.created_at_unix_ms(),
        })
    }

    pub(crate) fn messages(&self, group_id: PeerId) -> Result<Vec<StoredMessage>, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let store = self
            .store
            .lock()
            .map_err(|_| "mls_provider_service_unavailable")?;
        let encrypted = store
            .encrypted_messages(group_id)
            .map_err(|_| "message_list_unavailable")?;
        if encrypted.is_empty() {
            return Ok(Vec::new());
        }
        let key = self
            .wrapping_keys
            .get_optional()?
            .ok_or("mls_wrapping_key_missing")?;
        encrypted
            .into_iter()
            .map(|message| {
                let plaintext =
                    decrypt_local_message(&message.encrypted_body, &key, &message.event_id)?;
                let text = std::str::from_utf8(&plaintext)
                    .map_err(|_| "message_record_invalid")?
                    .to_owned();
                if text.trim().is_empty() || text.len() > MAX_MESSAGE_TEXT_BYTES {
                    return Err("message_record_invalid");
                }
                Ok(StoredMessage {
                    event_id: hex_bytes(&message.event_id),
                    group_id: message.group_id.to_string(),
                    author_id: message.author_id.to_string(),
                    created_at_unix_ms: message.created_at_unix_ms,
                    text,
                })
            })
            .collect()
    }

    fn create_message_at(
        &self,
        group_id: PeerId,
        author: &DeviceIdentity,
        message: &str,
        created_at_unix_ms: u64,
    ) -> Result<SignedEvent, &'static str> {
        if message.trim().is_empty() || message.len() > MAX_MESSAGE_TEXT_BYTES {
            return Err("message_invalid");
        }
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
                .create_message(&*provider, &signer, message.as_bytes())
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
                    kind: EventKind::MessageCreated,
                    protected_payload: &protected,
                },
            )
            .map_err(|_| "message_creation_failed")?;
            let snapshot = provider
                .snapshot()
                .map_err(|_| "mls_provider_snapshot_invalid")?;
            let key = self.load_or_create_wrapping_key()?;
            let encrypted = encrypt_snapshot(&snapshot, &key)?;
            let encrypted_body =
                encrypt_local_message(message.as_bytes(), &key, event.id().as_bytes())?;
            store
                .put_message_and_encrypted_mls_provider_snapshot(
                    &event,
                    &encrypted,
                    &encrypted_body,
                )
                .map_err(|_| "message_store_unavailable")?;
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
        drop(group);
        let Ok(mut store) = self.store.lock() else {
            return SyncResponse::Rejected {
                reason: SyncRejectReason::Busy,
            };
        };
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
            if event.kind() != EventKind::MessageCreated {
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
        self.materialize_pending_messages(&mut provider, &mut store, session.group_id())?;
        Ok(progress)
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
        let text =
            std::str::from_utf8(&plaintext).map_err(|_| MaterializeMessageError::Unreadable)?;
        if text.trim().is_empty() || text.len() > MAX_MESSAGE_TEXT_BYTES {
            return Err(MaterializeMessageError::Unreadable);
        }
        let snapshot = provider
            .snapshot()
            .map_err(|_| MaterializeMessageError::Unavailable("mls_provider_snapshot_invalid"))?;
        let key = self
            .load_or_create_wrapping_key()
            .map_err(MaterializeMessageError::Unavailable)?;
        let encrypted_snapshot =
            encrypt_snapshot(&snapshot, &key).map_err(MaterializeMessageError::Unavailable)?;
        let encrypted_body = encrypt_local_message(&plaintext, &key, event.id().as_bytes())
            .map_err(MaterializeMessageError::Unavailable)?;
        store
            .put_message_and_encrypted_mls_provider_snapshot(
                event,
                &encrypted_snapshot,
                &encrypted_body,
            )
            .map_err(|_| MaterializeMessageError::Unavailable("message_store_unavailable"))?;
        Ok(())
    }

    /// Adds one transport-authenticated device, publishes the resulting MLS
    /// Commit as a signed event, and persists the advanced MLS state in the
    /// same SQLite transaction before returning its Welcome.
    pub(crate) fn admit_member(
        &self,
        group_id: PeerId,
        owner_identity: &DeviceIdentity,
        authenticated_peer: PeerId,
        encoded_key_package: &[u8],
    ) -> Result<JoinResponse, MemberAdmissionError> {
        let created_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| u64::try_from(duration.as_millis()).ok())
            .ok_or(MemberAdmissionError::Unavailable)?;
        self.admit_member_at(
            group_id,
            owner_identity,
            authenticated_peer,
            encoded_key_package,
            created_at_unix_ms,
        )
    }

    fn admit_member_at(
        &self,
        group_id: PeerId,
        owner_identity: &DeviceIdentity,
        authenticated_peer: PeerId,
        encoded_key_package: &[u8],
        created_at_unix_ms: u64,
    ) -> Result<JoinResponse, MemberAdmissionError> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| MemberAdmissionError::Unavailable)?;
        let mut provider = self
            .provider
            .lock()
            .map_err(|_| MemberAdmissionError::Unavailable)?;
        let previous = provider
            .snapshot()
            .map_err(|_| MemberAdmissionError::Unavailable)?;
        let result = (|| {
            let mut store = self
                .store
                .lock()
                .map_err(|_| MemberAdmissionError::Unavailable)?;
            let mls_group_id = GroupId::from_slice(&group_id.to_bytes());
            let mut group = MlsGroup::load(provider.storage(), &mls_group_id)
                .map_err(|_| MemberAdmissionError::Unavailable)?
                .ok_or(MemberAdmissionError::Unavailable)?;
            validate_owner_group(&group, group_id, owner_identity.peer_id())
                .map_err(|_| MemberAdmissionError::Unavailable)?;
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
            store
                .put_event_and_encrypted_mls_provider_snapshot(&event, &encrypted)
                .map_err(|_| MemberAdmissionError::Unavailable)?;
            Ok(response)
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

fn hex_bytes(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    encoded
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
#[derive(Debug)]
enum MlsProviderMutationError<E> {
    Operation(E),
    Unavailable(&'static str),
}

enum MaterializeMessageError {
    Unreadable,
    Unavailable(&'static str),
}

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
        | SyncRequest::PushEvents { group_id, .. } => *group_id,
    }
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
    use std::sync::{Arc, Mutex};

    use charp2p_core::{
        DeviceIdentity, EventKind, GroupIdentity, HistoryPolicy, Invitation, InvitationSpec,
        SignedEvent, SyncRejectReason, SyncRequest, SyncResponse,
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
        decrypt_local_message, decrypt_snapshot, encrypt_local_message, encrypt_snapshot,
        MemberAdmissionError, MlsProviderMutationError, MlsProviderService, WrappingKeyStore,
        WRAPPING_KEY_BYTES,
    };
    use charp2p_store::EventStore;

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
    fn owner_group_is_idempotent_and_survives_restart() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("charp2p.sqlite3");
        let key_store = MemoryWrappingKeyStore::default();
        let group_id = GroupIdentity::generate().group_id();
        let device_id = DeviceIdentity::generate().peer_id();
        let service = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(key_store.clone()),
        )
        .unwrap();

        service.initialize_owner_group(group_id, device_id).unwrap();
        service.initialize_owner_group(group_id, device_id).unwrap();
        drop(service);

        let restored = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(key_store),
        )
        .unwrap();
        restored
            .initialize_owner_group(group_id, device_id)
            .unwrap();
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
        service
            .initialize_owner_group(group_id, owner.peer_id())
            .unwrap();

        let response = service
            .admit_member_at(group_id, &owner, member_id, key_package.encoded(), 42)
            .unwrap();
        let staged = stage_profile_welcome(&member_provider, response.welcome().unwrap()).unwrap();
        let joined = staged.into_group(&member_provider).unwrap();
        assert_eq!(joined.group_id().as_slice(), group_id.to_bytes());

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
            .event_ids_after(group_id, owner.peer_id(), 0, 2)
            .unwrap();
        let first = store.get_event(event_ids[0]).unwrap().unwrap();
        let second = store.get_event(event_ids[1]).unwrap().unwrap();
        assert_eq!(first.kind(), EventKind::MemberAdded);
        assert_eq!(first.author_sequence(), 1);
        assert_eq!(first.created_at_unix_ms(), 42);
        assert_eq!(second.kind(), EventKind::MemberAdded);
        assert_eq!(second.author_sequence(), 2);
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
        service
            .initialize_owner_group(group_id, owner.peer_id())
            .unwrap();
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
        assert_eq!(first.author_sequence(), 2);
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
        assert_eq!(second.author_sequence(), 3);
        assert_eq!(second.causal_parents(), &[first.id()]);
        assert_eq!(
            decrypt_application_message(&mut member_group, &member_provider, &second),
            b"After restart"
        );
        let messages = restored.messages(group_id).unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].text, "Protected hello");
        assert_eq!(messages[0].author_id, owner.peer_id().to_string());
        assert_eq!(messages[1].text, "After restart");
        let stored = EventStore::open(path).unwrap();
        assert!(stored
            .encrypted_messages(group_id)
            .unwrap()
            .iter()
            .all(|message| !message
                .encrypted_body
                .windows(b"Protected hello".len())
                .any(|window| window == b"Protected hello")));
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
            .initialize_owner_group(group_id, owner.peer_id())
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
            member_service.messages(group_id).unwrap()[0].text,
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
            .initialize_owner_group(group_id, owner.peer_id())
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
            owner_service.messages(group_id).unwrap()[0].text,
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
        service
            .initialize_owner_group(group_id, owner.peer_id())
            .unwrap();
        service
            .admit_member_at(group_id, &owner, member_id, key_package.encoded(), 42)
            .unwrap();

        let request = SyncRequest::Summary { group_id };
        let response = service.answer_sync_request(member_id, &request);
        let SyncResponse::Summary {
            group_id: response_group,
            heads,
        } = response
        else {
            panic!("member should receive a synchronization summary");
        };
        assert_eq!(response_group, group_id);
        assert_eq!(heads.len(), 1);
        assert_eq!(heads[0].author_id, owner.peer_id());
        assert_eq!(heads[0].contiguous_sequence, 1);
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
            .initialize_owner_group(group_id, owner.peer_id())
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

        assert_eq!(inserted, 3);
        assert_eq!(
            member_service
                .messages(group_id)
                .unwrap()
                .iter()
                .map(|message| message.text.as_str())
                .collect::<Vec<_>>(),
            vec!["After join"]
        );
        let store = EventStore::open(member_path).unwrap();
        let event_ids = store
            .event_ids_after(group_id, owner.peer_id(), 0, 3)
            .unwrap();
        assert_eq!(event_ids.len(), 3);
        assert_eq!(
            store.get_event(event_ids[1]).unwrap().unwrap().kind(),
            EventKind::MemberAdded
        );
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
        service
            .initialize_owner_group(group_id, owner.peer_id())
            .unwrap();
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
        assert!(EventStore::open(&path)
            .unwrap()
            .event_ids_after(group_id, owner.peer_id(), 0, 1)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn restored_owner_group_rejects_a_different_device() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("charp2p.sqlite3");
        let group_id = GroupIdentity::generate().group_id();
        let device_id = DeviceIdentity::generate().peer_id();
        let service = MlsProviderService::open_with_key_store(
            &path,
            Arc::new(Mutex::new(())),
            Box::new(MemoryWrappingKeyStore::default()),
        )
        .unwrap();
        service.initialize_owner_group(group_id, device_id).unwrap();
        let before = service
            .read(|provider| provider.snapshot().unwrap())
            .unwrap();

        assert_eq!(
            service.initialize_owner_group(group_id, DeviceIdentity::generate().peer_id()),
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
