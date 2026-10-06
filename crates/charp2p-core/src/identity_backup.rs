use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

use crate::{DeviceIdentity, DeviceIdentitySecret};

const BACKUP_MAGIC: &[u8] = b"charp2p-identity-backup";
const BACKUP_VERSION: u8 = 1;
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;
const KEY_BYTES: usize = 32;
const HEADER_BYTES: usize = BACKUP_MAGIC.len() + 1 + SALT_BYTES + NONCE_BYTES;
/// Largest encoded identity backup accepted for restore.
pub const MAX_IDENTITY_BACKUP_BYTES: usize = 1024;
const MAX_BACKUP_PLAINTEXT_BYTES: usize = 512;
/// Shortest passphrase, in characters, accepted for an identity backup.
pub const MIN_BACKUP_PASSPHRASE_CHARS: usize = 12;
/// Longest passphrase, in bytes, accepted for an identity backup.
pub const MAX_BACKUP_PASSPHRASE_BYTES: usize = 1024;
const MAX_BACKUP_DEVICE_NAME_BYTES: usize = 128;

// Version-1 Argon2id parameters (ADR-028). Unit tests use reduced memory so
// the debug build stays fast; the format itself never reads them from input.
#[cfg(not(test))]
const KDF_MEMORY_KIB: u32 = 64 * 1024;
#[cfg(test)]
const KDF_MEMORY_KIB: u32 = 64;
const KDF_PASSES: u32 = 3;
const KDF_LANES: u32 = 1;

/// A failure to create or open an encrypted identity backup.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdentityBackupError {
    #[error("backup passphrase is too short or too long")]
    InvalidPassphrase,
    #[error("backup device name is invalid")]
    InvalidDeviceName,
    #[error("identity backup has an invalid size")]
    InvalidSize,
    #[error("identity backup is not a CharP2P identity backup")]
    UnrecognizedFormat,
    #[error("identity backup version {0} is unsupported")]
    UnsupportedVersion(u8),
    #[error("identity backup cannot be decrypted with this passphrase")]
    DecryptionFailed,
    #[error("identity backup contents are invalid")]
    InvalidContents,
    #[error("identity backup could not be created")]
    EncryptionFailed,
}

/// Device identity contents recovered from an encrypted backup.
pub struct RestoredIdentityBackup {
    pub device_name: String,
    pub secret: DeviceIdentitySecret,
}

#[derive(Serialize, Deserialize)]
struct BackupPlaintext {
    device_name: String,
    device_key: Vec<u8>,
}

impl Drop for BackupPlaintext {
    fn drop(&mut self) {
        self.device_name.zeroize();
        self.device_key.zeroize();
    }
}

/// Seals a device name and encoded device key with a passphrase-derived key.
///
/// The returned bytes may be stored outside platform-protected storage. They
/// reveal nothing about the key without the passphrase.
pub fn seal_identity_backup(
    device_name: &str,
    secret: &DeviceIdentitySecret,
    passphrase: &str,
) -> Result<Vec<u8>, IdentityBackupError> {
    validate_passphrase(passphrase)?;
    validate_device_name(device_name)?;
    DeviceIdentity::from_persisted_secret(secret)
        .map_err(|_| IdentityBackupError::InvalidContents)?;

    let plaintext = BackupPlaintext {
        device_name: device_name.to_owned(),
        device_key: secret.expose_for_protected_storage().to_vec(),
    };
    let encoded = Zeroizing::new(
        postcard::to_allocvec(&plaintext).map_err(|_| IdentityBackupError::EncryptionFailed)?,
    );
    if encoded.len() > MAX_BACKUP_PLAINTEXT_BYTES {
        return Err(IdentityBackupError::InvalidContents);
    }

    let mut salt = [0_u8; SALT_BYTES];
    let mut nonce = [0_u8; NONCE_BYTES];
    getrandom::fill(&mut salt)
        .and_then(|()| getrandom::fill(&mut nonce))
        .map_err(|_| IdentityBackupError::EncryptionFailed)?;

    let mut backup = Vec::with_capacity(HEADER_BYTES + encoded.len() + 16);
    backup.extend_from_slice(BACKUP_MAGIC);
    backup.push(BACKUP_VERSION);
    backup.extend_from_slice(&salt);
    backup.extend_from_slice(&nonce);

    let key = derive_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| IdentityBackupError::EncryptionFailed)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: encoded.as_slice(),
                aad: &backup,
            },
        )
        .map_err(|_| IdentityBackupError::EncryptionFailed)?;
    backup.extend_from_slice(&ciphertext);
    if backup.len() > MAX_IDENTITY_BACKUP_BYTES {
        return Err(IdentityBackupError::InvalidContents);
    }
    Ok(backup)
}

/// Opens an encrypted identity backup and validates the recovered device key.
pub fn open_identity_backup(
    backup: &[u8],
    passphrase: &str,
) -> Result<RestoredIdentityBackup, IdentityBackupError> {
    if backup.len() > MAX_IDENTITY_BACKUP_BYTES {
        return Err(IdentityBackupError::InvalidSize);
    }
    if !backup.starts_with(BACKUP_MAGIC) {
        return Err(IdentityBackupError::UnrecognizedFormat);
    }
    let version = *backup
        .get(BACKUP_MAGIC.len())
        .ok_or(IdentityBackupError::InvalidSize)?;
    if version != BACKUP_VERSION {
        return Err(IdentityBackupError::UnsupportedVersion(version));
    }
    if backup.len() <= HEADER_BYTES {
        return Err(IdentityBackupError::InvalidSize);
    }
    validate_passphrase(passphrase)?;

    let (header, ciphertext) = backup.split_at(HEADER_BYTES);
    let salt_start = BACKUP_MAGIC.len() + 1;
    let salt = &header[salt_start..salt_start + SALT_BYTES];
    let nonce = &header[salt_start + SALT_BYTES..];

    let key = derive_key(passphrase, salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| IdentityBackupError::DecryptionFailed)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: header,
                },
            )
            .map_err(|_| IdentityBackupError::DecryptionFailed)?,
    );

    let (decoded, remaining): (BackupPlaintext, _) =
        postcard::take_from_bytes(&plaintext).map_err(|_| IdentityBackupError::InvalidContents)?;
    if !remaining.is_empty() {
        return Err(IdentityBackupError::InvalidContents);
    }
    validate_device_name(&decoded.device_name).map_err(|_| IdentityBackupError::InvalidContents)?;
    let secret = DeviceIdentitySecret::from_protected_bytes(decoded.device_key.clone());
    DeviceIdentity::from_persisted_secret(&secret)
        .map_err(|_| IdentityBackupError::InvalidContents)?;

    Ok(RestoredIdentityBackup {
        device_name: decoded.device_name.clone(),
        secret,
    })
}

fn validate_passphrase(passphrase: &str) -> Result<(), IdentityBackupError> {
    if passphrase.chars().count() < MIN_BACKUP_PASSPHRASE_CHARS
        || passphrase.len() > MAX_BACKUP_PASSPHRASE_BYTES
    {
        return Err(IdentityBackupError::InvalidPassphrase);
    }
    Ok(())
}

fn validate_device_name(device_name: &str) -> Result<(), IdentityBackupError> {
    if device_name.trim().is_empty() || device_name.len() > MAX_BACKUP_DEVICE_NAME_BYTES {
        return Err(IdentityBackupError::InvalidDeviceName);
    }
    Ok(())
}

fn derive_key(
    passphrase: &str,
    salt: &[u8],
) -> Result<Zeroizing<[u8; KEY_BYTES]>, IdentityBackupError> {
    let params = Params::new(KDF_MEMORY_KIB, KDF_PASSES, KDF_LANES, Some(KEY_BYTES))
        .map_err(|_| IdentityBackupError::EncryptionFailed)?;
    let mut key = Zeroizing::new([0_u8; KEY_BYTES]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, key.as_mut_slice())
        .map_err(|_| IdentityBackupError::EncryptionFailed)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::{
        BACKUP_MAGIC, IdentityBackupError, MAX_IDENTITY_BACKUP_BYTES, open_identity_backup,
        seal_identity_backup,
    };
    use crate::{DeviceIdentity, DeviceIdentitySecret};

    const PASSPHRASE: &str = "correct horse battery staple";

    fn sealed() -> (DeviceIdentity, Vec<u8>) {
        let (identity, secret) =
            DeviceIdentity::generate_persistable().expect("Ed25519 identity can be encoded");
        let backup = seal_identity_backup("Laptop", &secret, PASSPHRASE)
            .expect("identity backup can be sealed");
        (identity, backup)
    }

    #[test]
    fn backup_restores_the_same_device_identity_and_name() {
        let (identity, backup) = sealed();

        let restored = open_identity_backup(&backup, PASSPHRASE).expect("backup opens");
        let restored_identity =
            DeviceIdentity::from_persisted_secret(&restored.secret).expect("restored key decodes");

        assert_eq!(restored.device_name, "Laptop");
        assert_eq!(restored_identity.peer_id(), identity.peer_id());
        assert!(backup.len() <= MAX_IDENTITY_BACKUP_BYTES);
    }

    #[test]
    fn backups_of_the_same_identity_use_fresh_salt_and_nonce() {
        let (_, secret) =
            DeviceIdentity::generate_persistable().expect("Ed25519 identity can be encoded");
        let first = seal_identity_backup("Laptop", &secret, PASSPHRASE).expect("sealed");
        let second = seal_identity_backup("Laptop", &secret, PASSPHRASE).expect("sealed");

        assert_ne!(first, second);
    }

    #[test]
    fn wrong_passphrase_is_rejected() {
        let (_, backup) = sealed();

        assert_eq!(
            open_identity_backup(&backup, "incorrect horse battery").err(),
            Some(IdentityBackupError::DecryptionFailed)
        );
    }

    #[test]
    fn tampered_header_or_ciphertext_is_rejected() {
        let (_, backup) = sealed();
        for index in [BACKUP_MAGIC.len() + 1, backup.len() - 1] {
            let mut tampered = backup.clone();
            tampered[index] ^= 1;

            assert_eq!(
                open_identity_backup(&tampered, PASSPHRASE).err(),
                Some(IdentityBackupError::DecryptionFailed)
            );
        }
    }

    #[test]
    fn short_passphrase_is_refused_when_sealing() {
        let (_, secret) =
            DeviceIdentity::generate_persistable().expect("Ed25519 identity can be encoded");

        assert_eq!(
            seal_identity_backup("Laptop", &secret, "short").err(),
            Some(IdentityBackupError::InvalidPassphrase)
        );
    }

    #[test]
    fn invalid_device_key_is_not_sealed() {
        let secret = DeviceIdentitySecret::from_protected_bytes(vec![0, 1, 2, 3]);

        assert_eq!(
            seal_identity_backup("Laptop", &secret, PASSPHRASE).err(),
            Some(IdentityBackupError::InvalidContents)
        );
    }

    #[test]
    fn foreign_oversized_and_future_backups_are_rejected() {
        let (_, backup) = sealed();
        let mut future = backup.clone();
        future[BACKUP_MAGIC.len()] = 2;

        assert_eq!(
            open_identity_backup(b"not a backup", PASSPHRASE).err(),
            Some(IdentityBackupError::UnrecognizedFormat)
        );
        assert_eq!(
            open_identity_backup(&vec![0; MAX_IDENTITY_BACKUP_BYTES + 1], PASSPHRASE).err(),
            Some(IdentityBackupError::InvalidSize)
        );
        assert_eq!(
            open_identity_backup(&future, PASSPHRASE).err(),
            Some(IdentityBackupError::UnsupportedVersion(2))
        );
        assert_eq!(
            open_identity_backup(&backup[..BACKUP_MAGIC.len() + 1], PASSPHRASE).err(),
            Some(IdentityBackupError::InvalidSize)
        );
    }
}
