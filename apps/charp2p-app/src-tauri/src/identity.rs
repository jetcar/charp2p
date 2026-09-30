use std::sync::{Arc, Mutex};

use charp2p_core::{DeviceIdentity, DeviceIdentitySecret};
use keyring_core::{Entry, Error as KeyringError};
use serde::Serialize;
use zeroize::Zeroizing;

const CREDENTIAL_SERVICE: &str = "chat.charp2p.client";
const CREDENTIAL_USER: &str = "device-identity-v1";
const RECORD_VERSION: u8 = 1;
const MAX_DEVICE_NAME_CHARS: usize = 48;
const MAX_DEVICE_NAME_BYTES: usize = 80;
const MAX_LEGACY_DEVICE_NAME_BYTES: usize = 128;
const MAX_RECORD_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceProfile {
    pub device_name: String,
    pub peer_id: String,
}

pub struct IdentityService {
    operations: Arc<Mutex<()>>,
}

impl IdentityService {
    pub fn new(operations: Arc<Mutex<()>>) -> Self {
        Self { operations }
    }

    pub fn status(&self) -> Result<Option<DeviceProfile>, &'static str> {
        let _guard = self
            .operations
            .lock()
            .map_err(|_| "identity_service_unavailable")?;
        load_profile()
    }

    pub fn create(&self, requested_name: &str) -> Result<DeviceProfile, &'static str> {
        let _guard = self
            .operations
            .lock()
            .map_err(|_| "identity_service_unavailable")?;

        if load_profile()?.is_some() {
            return Err("identity_already_exists");
        }

        let device_name = normalize_device_name(requested_name)?;
        let (identity, secret) =
            DeviceIdentity::generate_persistable().map_err(|_| "identity_creation_failed")?;
        let record = encode_record(&device_name, &secret)?;
        protected_entry(CREDENTIAL_USER)?
            .set_secret(record.as_slice())
            .map_err(|_| "identity_store_unavailable")?;

        Ok(DeviceProfile {
            device_name,
            peer_id: identity.peer_id().to_string(),
        })
    }

    pub(crate) fn load_network_identity(&self) -> Result<DeviceIdentity, &'static str> {
        let _guard = self
            .operations
            .lock()
            .map_err(|_| "identity_service_unavailable")?;
        load_identity_record()?
            .map(|(_, identity)| identity)
            .ok_or("identity_missing")
    }
}

impl Default for IdentityService {
    fn default() -> Self {
        Self::new(Arc::new(Mutex::new(())))
    }
}

pub fn initialize_platform_store() -> Result<(), &'static str> {
    #[cfg(windows)]
    let store =
        windows_native_keyring_store::Store::new().map_err(|_| "identity_store_unavailable")?;

    #[cfg(target_os = "android")]
    let store =
        android_native_keyring_store::Store::new().map_err(|_| "identity_store_unavailable")?;

    #[cfg(not(any(windows, target_os = "android")))]
    return Err("identity_store_unsupported");

    #[cfg(any(windows, target_os = "android"))]
    {
        keyring_core::set_default_store(store);
        Ok(())
    }
}

fn load_profile() -> Result<Option<DeviceProfile>, &'static str> {
    Ok(
        load_identity_record()?.map(|(device_name, identity)| DeviceProfile {
            device_name,
            peer_id: identity.peer_id().to_string(),
        }),
    )
}

fn load_identity_record() -> Result<Option<(String, DeviceIdentity)>, &'static str> {
    let record = match protected_entry(CREDENTIAL_USER)?.get_secret() {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(KeyringError::NoEntry) => return Ok(None),
        Err(_) => return Err("identity_store_unavailable"),
    };
    let (device_name, secret) = decode_record(record.as_slice())?;
    let identity =
        DeviceIdentity::from_persisted_secret(&secret).map_err(|_| "identity_record_invalid")?;

    Ok(Some((device_name, identity)))
}

pub(crate) fn protected_entry(user: &str) -> Result<Entry, &'static str> {
    #[cfg(all(windows, not(test)))]
    let entry = Entry::new_with_modifiers(
        CREDENTIAL_SERVICE,
        user,
        &std::collections::HashMap::from([("persistence", "Local")]),
    );

    #[cfg(all(target_os = "android", not(test)))]
    let entry = Entry::new(CREDENTIAL_SERVICE, user);

    #[cfg(test)]
    let entry = Entry::new(CREDENTIAL_SERVICE, user);

    #[cfg(all(not(test), not(any(windows, target_os = "android"))))]
    return Err("identity_store_unsupported");

    #[cfg(any(test, windows, target_os = "android"))]
    entry.map_err(|_| "identity_store_unavailable")
}

fn normalize_device_name(requested: &str) -> Result<String, &'static str> {
    let name = requested.trim();
    let character_count = name.chars().count();
    if character_count == 0
        || character_count > MAX_DEVICE_NAME_CHARS
        || name.len() > MAX_DEVICE_NAME_BYTES
        || name.chars().any(char::is_control)
    {
        return Err("invalid_device_name");
    }

    Ok(name.to_owned())
}

pub(crate) fn invitation_device_name(device_name: &str) -> String {
    if device_name.len() <= MAX_DEVICE_NAME_BYTES {
        return device_name.to_owned();
    }
    let mut end = MAX_DEVICE_NAME_BYTES;
    while !device_name.is_char_boundary(end) {
        end -= 1;
    }
    device_name[..end].trim_end().to_owned()
}

fn encode_record(
    device_name: &str,
    secret: &DeviceIdentitySecret,
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let name_bytes = device_name.as_bytes();
    let name_len = u16::try_from(name_bytes.len()).map_err(|_| "identity_record_invalid")?;
    let secret_bytes = secret.expose_for_protected_storage();
    let total_len = 3usize
        .checked_add(name_bytes.len())
        .and_then(|size| size.checked_add(secret_bytes.len()))
        .ok_or("identity_record_invalid")?;
    if total_len > MAX_RECORD_BYTES {
        return Err("identity_record_invalid");
    }

    let mut record = Zeroizing::new(Vec::with_capacity(total_len));
    record.push(RECORD_VERSION);
    record.extend_from_slice(&name_len.to_be_bytes());
    record.extend_from_slice(name_bytes);
    record.extend_from_slice(secret_bytes);
    Ok(record)
}

fn decode_record(record: &[u8]) -> Result<(String, DeviceIdentitySecret), &'static str> {
    if record.len() < 4 || record.len() > MAX_RECORD_BYTES || record[0] != RECORD_VERSION {
        return Err("identity_record_invalid");
    }

    let name_len = usize::from(u16::from_be_bytes([record[1], record[2]]));
    if name_len == 0 || name_len > MAX_LEGACY_DEVICE_NAME_BYTES {
        return Err("identity_record_invalid");
    }
    let secret_start = 3usize
        .checked_add(name_len)
        .filter(|start| *start < record.len())
        .ok_or("identity_record_invalid")?;
    let device_name =
        std::str::from_utf8(&record[3..secret_start]).map_err(|_| "identity_record_invalid")?;
    if device_name.is_empty()
        || device_name.chars().count() > MAX_DEVICE_NAME_CHARS
        || device_name.len() > MAX_LEGACY_DEVICE_NAME_BYTES
        || device_name.trim() != device_name
        || device_name.chars().any(char::is_control)
    {
        return Err("identity_record_invalid");
    }
    let device_name = device_name.to_owned();
    let secret = DeviceIdentitySecret::from_protected_bytes(record[secret_start..].to_vec());
    Ok((device_name, secret))
}

#[cfg(test)]
mod tests {
    use super::{
        decode_record, encode_record, invitation_device_name, normalize_device_name,
        IdentityService,
    };
    use charp2p_core::{DeviceIdentity, DeviceIdentitySecret};

    #[test]
    fn identity_record_round_trips_without_changing_peer_id() {
        let (identity, secret) = DeviceIdentity::generate_persistable().expect("identity encodes");
        let record = encode_record("Alex's tablet", &secret).expect("record encodes");
        let (device_name, restored_secret) =
            decode_record(record.as_slice()).expect("record decodes");
        let restored =
            DeviceIdentity::from_persisted_secret(&restored_secret).expect("identity restores");

        assert_eq!(device_name, "Alex's tablet");
        assert_eq!(restored.peer_id(), identity.peer_id());
    }

    #[test]
    fn malformed_records_are_rejected_before_key_decoding() {
        assert!(decode_record(&[]).is_err());
        assert!(decode_record(&[2, 0, 1, b'a', 1]).is_err());
        assert!(decode_record(&[1, 0, 5, b'a', 1]).is_err());
        assert!(decode_record(&[1, 0, 0, 1]).is_err());
    }

    #[test]
    fn device_names_are_trimmed_and_bounded() {
        assert_eq!(normalize_device_name("  Alex's PC  ").unwrap(), "Alex's PC");
        assert!(normalize_device_name("").is_err());
        assert!(normalize_device_name("bad\nname").is_err());
        assert!(normalize_device_name(&"a".repeat(49)).is_err());
        assert!(normalize_device_name(&"é".repeat(40)).is_ok());
        assert!(normalize_device_name(&"é".repeat(41)).is_err());
    }

    #[test]
    fn record_size_is_bounded() {
        let secret = DeviceIdentitySecret::from_protected_bytes(vec![7; 400]);
        assert!(encode_record(&"a".repeat(128), &secret).is_err());
    }

    #[test]
    fn legacy_multibyte_name_loads_with_a_bounded_invitation_form() {
        let (_, secret) = DeviceIdentity::generate_persistable().unwrap();
        let legacy_name = "é".repeat(48);
        let mut record = zeroize::Zeroizing::new(Vec::new());
        record.push(super::RECORD_VERSION);
        record.extend_from_slice(&(legacy_name.len() as u16).to_be_bytes());
        record.extend_from_slice(legacy_name.as_bytes());
        record.extend_from_slice(secret.expose_for_protected_storage());

        let (loaded, _) = decode_record(&record).unwrap();
        assert_eq!(loaded, legacy_name);
        let invitation_name = invitation_device_name(&loaded);
        assert!(invitation_name.len() <= 80);
        assert!(loaded.starts_with(&invitation_name));
        assert_eq!(invitation_name.trim(), invitation_name);

        let trailing_space_boundary = format!("{} é", "é".repeat(39));
        let bounded = invitation_device_name(&trailing_space_boundary);
        assert_eq!(bounded, "é".repeat(39));
        assert!(bounded.len() <= 80);
    }

    #[test]
    fn identity_service_creates_once_and_restores_the_profile() {
        keyring_core::set_default_store(
            keyring_core::mock::Store::new().expect("mock store initializes"),
        );
        let service = IdentityService::default();

        assert!(service.status().unwrap().is_none());
        let created = service.create("Alex's PC").expect("identity is created");
        let restored = service.status().unwrap().expect("identity is restored");

        assert_eq!(restored, created);
        assert_eq!(
            service.create("Replacement").unwrap_err(),
            "identity_already_exists"
        );
        keyring_core::unset_default_store();
    }
}
