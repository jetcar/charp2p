use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use charp2p_mls::ProfileProvider;
use charp2p_store::{EventStore, MAX_ENCRYPTED_MLS_PROVIDER_SNAPSHOT_BYTES};
use keyring_core::Error as KeyringError;
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
pub struct MlsProviderService {
    operations: Arc<Mutex<()>>,
    store: Mutex<EventStore>,
    provider: Mutex<ProfileProvider>,
    wrapping_keys: Box<dyn WrappingKeyStore>,
}

impl MlsProviderService {
    pub fn open(path: impl AsRef<Path>, operations: Arc<Mutex<()>>) -> Result<Self, &'static str> {
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

    #[cfg(test)]
    pub fn read<T>(&self, operation: impl FnOnce(&ProfileProvider) -> T) -> Result<T, &'static str> {
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
    pub fn mutate<T, E>(
        &self,
        operation: impl FnOnce(&mut ProfileProvider) -> Result<T, E>,
    ) -> Result<T, MlsProviderMutationError<E>> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| MlsProviderMutationError::Unavailable("mls_provider_service_unavailable"))?;
        let mut provider = self
            .provider
            .lock()
            .map_err(|_| MlsProviderMutationError::Unavailable("mls_provider_service_unavailable"))?;
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

/// Result of a provider operation that may fail before durable replacement.
#[derive(Debug)]
pub enum MlsProviderMutationError<E> {
    Operation(E),
    Unavailable(&'static str),
}

fn restore_provider<E>(
    provider: &mut ProfileProvider,
    snapshot: &[u8],
) -> Result<(), MlsProviderMutationError<E>> {
    *provider = ProfileProvider::from_snapshot(snapshot).map_err(|_| {
        MlsProviderMutationError::Unavailable("mls_provider_snapshot_invalid")
    })?;
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

    use charp2p_core::DeviceIdentity;
    use charp2p_mls::{CIPHERSUITE, device_credential, prepare_profile_key_package};
    use openmls::prelude::{CredentialWithKey, OpenMlsProvider};
    use openmls_basic_credential::SignatureKeyPair;
    use tempfile::tempdir;
    use zeroize::Zeroizing;

    use super::{
        MlsProviderMutationError, MlsProviderService, WRAPPING_KEY_BYTES, WrappingKeyStore,
        decrypt_snapshot, encrypt_snapshot,
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
            *self
                .key
                .lock()
                .map_err(|_| "test_key_store_unavailable")? = Some(*key);
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
        let expected = service.read(|provider| provider.snapshot().unwrap()).unwrap();
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
        let before = service.read(|provider| provider.snapshot().unwrap()).unwrap();

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
        assert!(
            EventStore::open(&path)
                .unwrap()
                .encrypted_mls_provider_snapshot()
                .unwrap()
                .is_none()
        );
    }
}
