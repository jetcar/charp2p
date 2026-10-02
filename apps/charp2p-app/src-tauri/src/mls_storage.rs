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
    DeviceIdentity, EventId, EventKind, EventSpec, JoinResponse, PeerId, SignedEvent,
};
use charp2p_mls::{
    device_credential, device_id_from_credential, group_create_config,
    merge_prepared_member_admission, prepare_profile_member_admission, validate_group_profile,
    PrepareMemberAdmissionError, ProfileKeyPackageError, ProfileProvider, CIPHERSUITE,
};
use charp2p_store::{EventStore, MAX_ENCRYPTED_MLS_PROVIDER_SNAPSHOT_BYTES};
use keyring_core::Error as KeyringError;
use openmls::prelude::{CredentialWithKey, GroupId, MlsGroup, OpenMlsProvider};
use openmls_basic_credential::SignatureKeyPair;
use zeroize::Zeroizing;

use crate::identity::protected_entry;

const WRAPPING_KEY_CREDENTIAL_USER: &str = "mls-provider-wrapping-key-v1";
const WRAPPING_KEY_BYTES: usize = 32;
const ENVELOPE_VERSION: u16 = 1;
const NONCE_BYTES: usize = 24;
const TAG_BYTES: usize = 16;
const ENVELOPE_HEADER_BYTES: usize = 2 + NONCE_BYTES;
const SNAPSHOT_AAD: &[u8] = b"charp2p-mls-provider-snapshot-v1\0";

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

fn restore_provider<E>(
    provider: &mut ProfileProvider,
    snapshot: &[u8],
) -> Result<(), MlsProviderMutationError<E>> {
    *provider = ProfileProvider::from_snapshot(snapshot)
        .map_err(|_| MlsProviderMutationError::Unavailable("mls_provider_snapshot_invalid"))?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use charp2p_core::{DeviceIdentity, EventKind, GroupIdentity};
    use charp2p_mls::{
        device_credential, device_id_from_credential, prepare_profile_key_package,
        stage_profile_welcome, ProfileProvider, CIPHERSUITE,
    };
    use openmls::prelude::{CredentialWithKey, GroupId, MlsGroup, OpenMlsProvider};
    use openmls_basic_credential::SignatureKeyPair;
    use tempfile::tempdir;
    use zeroize::Zeroizing;

    use super::{
        decrypt_snapshot, encrypt_snapshot, MemberAdmissionError, MlsProviderMutationError,
        MlsProviderService, WrappingKeyStore, WRAPPING_KEY_BYTES,
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
