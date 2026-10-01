#![forbid(unsafe_code)]

//! The fixed MLS profile used for CharP2P group-message protection.

use std::{collections::HashMap, fmt, sync::RwLock};

pub use charp2p_core::MAX_JOIN_MLS_MESSAGE_BYTES as MAX_MLS_WIRE_BYTES;
use charp2p_core::{Invitation, JoinError, JoinRequest, PeerId};
use openmls::{
    group::GroupContext,
    prelude::{
        Capabilities, Ciphersuite, CredentialType, CredentialWithKey, Extension, ExtensionType,
        Extensions, KeyPackage, KeyPackageIn, MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig,
        MlsMessageBodyIn, MlsMessageIn, OpenMlsProvider, ProtocolVersion,
        RequiredCapabilitiesExtension, StagedCommit, StagedWelcome, UnknownExtension, WelcomeError,
        tls_codec::{Deserialize, Serialize},
    },
};
use openmls_memory_storage::MemoryStorage;
use openmls_rust_crypto::RustCrypto;
use openmls_traits::signatures::Signer;
use thiserror::Error;
use zeroize::Zeroizing;

const PROFILE_EXTENSION_TYPE_ID: u16 = 0xF000;
const PROFILE_EXTENSION_TYPE: ExtensionType = ExtensionType::Unknown(PROFILE_EXTENSION_TYPE_ID);
const DEVICE_CREDENTIAL_DOMAIN: &[u8] = b"charp2p-device-credential\0";
const DEVICE_CREDENTIAL_VERSION: u16 = 1;
const MAX_DEVICE_PEER_ID_BYTES: usize = 128;
const PROVIDER_SNAPSHOT_VERSION: u16 = 1;
const MAX_PROVIDER_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;
const MAX_PROVIDER_SNAPSHOT_RECORDS: usize = 4_096;
const MAX_PROVIDER_SNAPSHOT_KEY_BYTES: usize = 64 * 1024;
const MAX_PROVIDER_SNAPSHOT_VALUE_BYTES: usize = 2 * 1024 * 1024;
/// Version of the CharP2P MLS profile carried by an authenticated private-use
/// group-context extension.
pub const PROFILE_VERSION: u16 = 1;

/// The only ciphersuite accepted by profile version 1.
///
/// Pinning one suite prevents silent negotiation to a weaker or incompatible
/// construction. A future profile version can add another suite explicitly.
pub const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

/// Profile provider whose secret-bearing storage can be snapshotted for
/// application-managed encrypted persistence.
#[derive(Default)]
pub struct ProfileProvider {
    crypto: RustCrypto,
    storage: MemoryStorage,
}

impl ProfileProvider {
    /// Restores one bounded, versioned provider snapshot.
    pub fn from_snapshot(encoded: &[u8]) -> Result<Self, ProfileProviderSnapshotError> {
        if encoded.len() < 6 || encoded.len() > MAX_PROVIDER_SNAPSHOT_BYTES {
            return Err(ProfileProviderSnapshotError::InvalidSize);
        }
        let mut decoder = SnapshotDecoder::new(encoded);
        let version = decoder.u16()?;
        if version != PROVIDER_SNAPSHOT_VERSION {
            return Err(ProfileProviderSnapshotError::UnsupportedVersion(version));
        }
        let record_count = usize::try_from(decoder.u32()?)
            .map_err(|_| ProfileProviderSnapshotError::InvalidSize)?;
        if record_count > MAX_PROVIDER_SNAPSHOT_RECORDS {
            return Err(ProfileProviderSnapshotError::InvalidSize);
        }
        let mut values = HashMap::with_capacity(record_count);
        for _ in 0..record_count {
            let key_length = usize::try_from(decoder.u32()?)
                .map_err(|_| ProfileProviderSnapshotError::InvalidSize)?;
            let value_length = usize::try_from(decoder.u32()?)
                .map_err(|_| ProfileProviderSnapshotError::InvalidSize)?;
            if key_length == 0
                || key_length > MAX_PROVIDER_SNAPSHOT_KEY_BYTES
                || value_length > MAX_PROVIDER_SNAPSHOT_VALUE_BYTES
            {
                return Err(ProfileProviderSnapshotError::InvalidSize);
            }
            let key = decoder.bytes(key_length)?.to_vec();
            let value = decoder.bytes(value_length)?.to_vec();
            if values.insert(key, value).is_some() {
                return Err(ProfileProviderSnapshotError::DuplicateKey);
            }
        }
        decoder.finish()?;
        Ok(Self {
            crypto: RustCrypto::default(),
            storage: MemoryStorage {
                values: RwLock::new(values),
            },
        })
    }

    /// Serializes all provider records into a bounded zeroizing snapshot.
    /// The snapshot contains MLS secrets and must be encrypted before storage.
    pub fn snapshot(&self) -> Result<Zeroizing<Vec<u8>>, ProfileProviderSnapshotError> {
        let values = self
            .storage
            .values
            .read()
            .map_err(|_| ProfileProviderSnapshotError::StorageUnavailable)?;
        if values.len() > MAX_PROVIDER_SNAPSHOT_RECORDS {
            return Err(ProfileProviderSnapshotError::InvalidSize);
        }
        let mut records: Vec<_> = values.iter().collect();
        records.sort_unstable_by_key(|(key, _)| *key);
        let mut encoded_length = 6usize;
        for (key, value) in &records {
            if key.is_empty()
                || key.len() > MAX_PROVIDER_SNAPSHOT_KEY_BYTES
                || value.len() > MAX_PROVIDER_SNAPSHOT_VALUE_BYTES
            {
                return Err(ProfileProviderSnapshotError::InvalidSize);
            }
            encoded_length = encoded_length
                .checked_add(8)
                .and_then(|length| length.checked_add(key.len()))
                .and_then(|length| length.checked_add(value.len()))
                .ok_or(ProfileProviderSnapshotError::InvalidSize)?;
            if encoded_length > MAX_PROVIDER_SNAPSHOT_BYTES {
                return Err(ProfileProviderSnapshotError::InvalidSize);
            }
        }
        let mut encoded = Zeroizing::new(Vec::with_capacity(encoded_length));
        encoded.extend_from_slice(&PROVIDER_SNAPSHOT_VERSION.to_be_bytes());
        encoded.extend_from_slice(
            &u32::try_from(records.len())
                .map_err(|_| ProfileProviderSnapshotError::InvalidSize)?
                .to_be_bytes(),
        );
        for (key, value) in records {
            encoded.extend_from_slice(
                &u32::try_from(key.len())
                    .map_err(|_| ProfileProviderSnapshotError::InvalidSize)?
                    .to_be_bytes(),
            );
            encoded.extend_from_slice(
                &u32::try_from(value.len())
                    .map_err(|_| ProfileProviderSnapshotError::InvalidSize)?
                    .to_be_bytes(),
            );
            encoded.extend_from_slice(key);
            encoded.extend_from_slice(value);
        }
        debug_assert_eq!(encoded.len(), encoded_length);
        Ok(encoded)
    }
}

impl OpenMlsProvider for ProfileProvider {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

/// Failure while encoding or restoring a profile-provider snapshot.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProfileProviderSnapshotError {
    #[error("MLS provider snapshot has an invalid size")]
    InvalidSize,
    #[error("MLS provider snapshot version {0} is unsupported")]
    UnsupportedVersion(u16),
    #[error("MLS provider snapshot is malformed")]
    Malformed,
    #[error("MLS provider snapshot contains a duplicate key")]
    DuplicateKey,
    #[error("MLS provider storage is unavailable")]
    StorageUnavailable,
}

struct SnapshotDecoder<'a> {
    remaining: &'a [u8],
}

impl<'a> SnapshotDecoder<'a> {
    fn new(encoded: &'a [u8]) -> Self {
        Self { remaining: encoded }
    }

    fn u16(&mut self) -> Result<u16, ProfileProviderSnapshotError> {
        let bytes: [u8; 2] = self
            .bytes(2)?
            .try_into()
            .map_err(|_| ProfileProviderSnapshotError::Malformed)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, ProfileProviderSnapshotError> {
        let bytes: [u8; 4] = self
            .bytes(4)?
            .try_into()
            .map_err(|_| ProfileProviderSnapshotError::Malformed)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], ProfileProviderSnapshotError> {
        if self.remaining.len() < length {
            return Err(ProfileProviderSnapshotError::Malformed);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn finish(self) -> Result<(), ProfileProviderSnapshotError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(ProfileProviderSnapshotError::Malformed)
        }
    }
}

/// A mismatch between received MLS state and the CharP2P profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProfileError {
    /// The group uses a ciphersuite that profile version 1 does not permit.
    UnsupportedCiphersuite,
    /// The authenticated profile extension is missing or has another version.
    UnsupportedProfileVersion,
    /// Local runtime configuration differs from the fixed profile.
    UnsupportedJoinConfiguration,
    /// A group leaf does not carry a valid CharP2P device credential.
    InvalidDeviceCredential,
}

/// Failure while checking and decrypting a profile Welcome.
#[derive(Debug)]
pub enum StageWelcomeError<StorageError> {
    /// The encoded Welcome exceeds the wire bound or is malformed.
    Wire(MlsWireError),
    /// The encoded MLS message is valid but is not a Welcome.
    UnexpectedMessage,
    /// The Welcome does not conform to the CharP2P profile.
    Profile(ProfileError),
    /// OpenMLS rejected the Welcome or its stored key material.
    OpenMls(WelcomeError<StorageError>),
}

/// Failure to decode a CharP2P device identity from an MLS credential.
#[derive(Debug, Error)]
pub enum DeviceCredentialError {
    /// Profile version 1 accepts only MLS Basic Credentials.
    #[error("MLS credential type is not supported")]
    UnsupportedCredentialType,
    /// The credential does not contain a canonical CharP2P device identity.
    #[error("MLS device credential is malformed")]
    InvalidIdentity,
    /// The encoded CharP2P device-credential version is not supported.
    #[error("MLS device credential version {0} is not supported")]
    UnsupportedVersion(u16),
}

/// Failure to parse an encoded MLS message inside the profile wire bound.
#[derive(Debug, Error)]
pub enum MlsWireError {
    /// The encoded message is empty or above the profile limit.
    #[error("MLS message has an invalid encoded size")]
    InvalidSize,
    /// OpenMLS rejected the bounded wire encoding.
    #[error("MLS message encoding is malformed")]
    Malformed(#[source] openmls::prelude::tls_codec::Error),
    /// Bytes remain after the one canonical MLS message.
    #[error("MLS message has trailing data")]
    TrailingData,
}

/// Failure while authenticating an inbound profile KeyPackage.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ProfileKeyPackageError {
    /// The encoded KeyPackage is empty or above the profile wire bound.
    #[error("MLS KeyPackage has an invalid encoded size")]
    InvalidSize,
    /// The bounded bytes are not exactly one canonical KeyPackage.
    #[error("MLS KeyPackage encoding is malformed")]
    Malformed,
    /// OpenMLS rejected the KeyPackage signature, lifetime, or structure.
    #[error("MLS KeyPackage verification failed")]
    VerificationFailed,
    /// The KeyPackage uses a ciphersuite outside profile version 1.
    #[error("MLS KeyPackage ciphersuite is unsupported")]
    UnsupportedCiphersuite,
    /// The leaf does not advertise the exact profile version 1 capabilities.
    #[error("MLS KeyPackage capabilities are unsupported")]
    UnsupportedCapabilities,
    /// The leaf does not carry a valid CharP2P device credential.
    #[error("MLS KeyPackage device credential is invalid")]
    InvalidDeviceCredential,
    /// The signed device credential is not the authenticated transport peer.
    #[error("MLS KeyPackage device does not match the transport peer")]
    TransportPeerMismatch,
}

/// A one-time profile KeyPackage whose private keys are stored by the provider.
pub struct PreparedKeyPackage {
    device_id: PeerId,
    encoded: Zeroizing<Vec<u8>>,
}

impl PreparedKeyPackage {
    /// Device identity signed into the KeyPackage leaf credential.
    pub fn device_id(&self) -> PeerId {
        self.device_id
    }

    /// Bounded encoded KeyPackage sent in one join request.
    pub fn encoded(&self) -> &[u8] {
        self.encoded.as_slice()
    }

    /// Transfers the one-time public package into a bounded join request.
    pub fn into_join_request(mut self, invitation: &Invitation) -> Result<JoinRequest, JoinError> {
        let encoded = std::mem::take(&mut *self.encoded);
        JoinRequest::from_invitation(invitation, encoded)
    }
}

impl fmt::Debug for PreparedKeyPackage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedKeyPackage")
            .field("device_id", &self.device_id)
            .field("encoded_bytes", &self.encoded.len())
            .finish()
    }
}

/// Failure while creating a one-time profile KeyPackage.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PrepareKeyPackageError {
    /// The supplied credential is malformed or names another device.
    #[error("MLS credential does not match the local device")]
    InvalidDeviceCredential,
    /// OpenMLS could not generate and store the one-time private key material.
    #[error("MLS KeyPackage generation failed")]
    GenerationFailed,
    /// OpenMLS could not canonically encode the KeyPackage.
    #[error("MLS KeyPackage encoding failed")]
    WireEncodingFailed,
    /// The generated KeyPackage exceeds the profile wire bound.
    #[error("MLS KeyPackage exceeds the profile wire bound")]
    WireSizeExceeded,
    /// The generated KeyPackage did not pass the inbound profile validator.
    #[error("generated MLS KeyPackage failed profile validation")]
    SelfValidationFailed,
}

/// Bounded MLS messages produced while staging one authenticated member.
pub struct PreparedMemberAdmission {
    peer_id: PeerId,
    commit: Zeroizing<Vec<u8>>,
    welcome: Zeroizing<Vec<u8>>,
}

impl PreparedMemberAdmission {
    /// Device authenticated by both the transport and KeyPackage credential.
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// Commit that existing members must authenticate and merge.
    pub fn commit(&self) -> &[u8] {
        self.commit.as_slice()
    }

    /// Welcome returned only to the joining device.
    pub fn welcome(&self) -> &[u8] {
        self.welcome.as_slice()
    }
}

impl fmt::Debug for PreparedMemberAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedMemberAdmission")
            .field("peer_id", &self.peer_id)
            .field("commit_bytes", &self.commit.len())
            .field("welcome_bytes", &self.welcome.len())
            .finish()
    }
}

/// Failure while staging an authenticated device addition.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PrepareMemberAdmissionError {
    /// The owner's existing group state is outside the fixed profile.
    #[error("owner MLS group does not match the CharP2P profile")]
    InvalidGroupProfile,
    /// The KeyPackage is invalid or is not bound to the transport peer.
    #[error("joining MLS KeyPackage is invalid")]
    InvalidKeyPackage(ProfileKeyPackageError),
    /// OpenMLS could not stage the member addition.
    #[error("MLS member addition could not be staged")]
    MemberAdditionFailed,
    /// The locally generated pending commit violates the profile.
    #[error("generated MLS member commit violates the profile")]
    InvalidPendingCommit,
    /// OpenMLS could not canonically encode the generated messages.
    #[error("generated MLS member messages could not be encoded")]
    WireEncodingFailed,
    /// The generated commit or Welcome exceeds the profile wire bound.
    #[error("generated MLS member messages exceed the profile wire bound")]
    WireSizeExceeded,
    /// A failed preparation could not clear its pending commit.
    #[error("failed MLS member preparation could not be rolled back")]
    RollbackFailed,
}

/// Failure while merging a previously persisted member admission commit.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MergeMemberAdmissionError {
    /// There is no locally prepared commit to merge.
    #[error("no MLS member admission is pending")]
    MissingPendingCommit,
    /// The pending commit violates the fixed profile.
    #[error("pending MLS member admission violates the profile")]
    InvalidPendingCommit,
    /// OpenMLS could not durably advance the group epoch.
    #[error("pending MLS member admission could not be merged")]
    MergeFailed,
}

/// Failure while discarding an unpublished member admission.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AbortMemberAdmissionError {
    /// OpenMLS could not durably clear its pending commit.
    #[error("pending MLS member admission could not be cleared")]
    StorageFailed,
}

/// Returns the group configuration required by profile version 1.
///
/// The ratchet tree travels in the MLS Welcome so a joining peer does not
/// depend on a central delivery service to retrieve it.
pub fn group_create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(CIPHERSUITE)
        .capabilities(profile_capabilities())
        .use_ratchet_tree_extension(true)
        .with_group_context_extensions(profile_extensions())
        .build()
}

/// Returns the required join behavior for every profile version 1 member.
fn group_join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .use_ratchet_tree_extension(true)
        .build()
}

/// Returns the capabilities that every profile key package must advertise.
pub fn profile_capabilities() -> Capabilities {
    Capabilities::new(
        None,
        Some(&[CIPHERSUITE]),
        Some(&[PROFILE_EXTENSION_TYPE]),
        None,
        Some(&[CredentialType::Basic]),
    )
}

/// Creates the MLS Basic Credential bound to one CharP2P device peer ID.
pub fn device_credential(device_id: PeerId) -> openmls::prelude::BasicCredential {
    let peer_id = device_id.to_bytes();
    debug_assert!(peer_id.len() <= MAX_DEVICE_PEER_ID_BYTES);
    let mut identity = Vec::with_capacity(DEVICE_CREDENTIAL_DOMAIN.len() + 2 + peer_id.len());
    identity.extend_from_slice(DEVICE_CREDENTIAL_DOMAIN);
    identity.extend_from_slice(&DEVICE_CREDENTIAL_VERSION.to_be_bytes());
    identity.extend_from_slice(&peer_id);
    openmls::prelude::BasicCredential::new(identity)
}

/// Extracts and validates the CharP2P device peer ID bound to an MLS
/// credential.
pub fn device_id_from_credential(
    credential: &openmls::prelude::Credential,
) -> Result<PeerId, DeviceCredentialError> {
    if credential.credential_type() != CredentialType::Basic {
        return Err(DeviceCredentialError::UnsupportedCredentialType);
    }
    let identity = credential.serialized_content();
    let version_offset = DEVICE_CREDENTIAL_DOMAIN.len();
    if identity.len() < version_offset + 3
        || !identity.starts_with(DEVICE_CREDENTIAL_DOMAIN)
        || identity.len() > version_offset + 2 + MAX_DEVICE_PEER_ID_BYTES
    {
        return Err(DeviceCredentialError::InvalidIdentity);
    }
    let version = u16::from_be_bytes([identity[version_offset], identity[version_offset + 1]]);
    if version != DEVICE_CREDENTIAL_VERSION {
        return Err(DeviceCredentialError::UnsupportedVersion(version));
    }
    PeerId::from_bytes(&identity[version_offset + 2..])
        .map_err(|_| DeviceCredentialError::InvalidIdentity)
}

/// Generates and stores one-time profile KeyPackage private material.
///
/// `credential_with_key` must contain the public key of `signer` and a
/// CharP2P Basic Credential for `device_id`. The returned public encoding is
/// ready for one [`charp2p_core::JoinRequest`].
pub fn prepare_profile_key_package<Provider: OpenMlsProvider>(
    provider: &Provider,
    signer: &impl Signer,
    credential_with_key: CredentialWithKey,
    device_id: PeerId,
) -> Result<PreparedKeyPackage, PrepareKeyPackageError> {
    let credential_device = device_id_from_credential(&credential_with_key.credential)
        .map_err(|_| PrepareKeyPackageError::InvalidDeviceCredential)?;
    if credential_device != device_id {
        return Err(PrepareKeyPackageError::InvalidDeviceCredential);
    }
    let key_package = KeyPackage::builder()
        .leaf_node_capabilities(profile_capabilities())
        .build(CIPHERSUITE, provider, signer, credential_with_key)
        .map_err(|_| PrepareKeyPackageError::GenerationFailed)?;
    let encoded = Zeroizing::new(
        key_package
            .key_package()
            .tls_serialize_detached()
            .map_err(|_| PrepareKeyPackageError::WireEncodingFailed)?,
    );
    if encoded.is_empty() || encoded.len() > MAX_MLS_WIRE_BYTES {
        return Err(PrepareKeyPackageError::WireSizeExceeded);
    }
    validate_profile_key_package(provider, encoded.as_slice(), device_id)
        .map_err(|_| PrepareKeyPackageError::SelfValidationFailed)?;
    Ok(PreparedKeyPackage { device_id, encoded })
}

/// Bounds and parses exactly one MLS wire message before any attacker-sized
/// field is allocated by OpenMLS.
pub fn decode_profile_message(encoded: &[u8]) -> Result<MlsMessageIn, MlsWireError> {
    if encoded.is_empty() || encoded.len() > MAX_MLS_WIRE_BYTES {
        return Err(MlsWireError::InvalidSize);
    }
    let mut remaining = encoded;
    let message = MlsMessageIn::tls_deserialize(&mut remaining).map_err(MlsWireError::Malformed)?;
    if !remaining.is_empty() {
        return Err(MlsWireError::TrailingData);
    }
    Ok(message)
}

/// Bounds and verifies one profile KeyPackage for an authenticated transport
/// peer.
///
/// The returned package is safe to pass to `MlsGroup::add_members`. This does
/// not authorize the peer to join a group; the caller must separately validate
/// its invitation and membership policy.
pub fn validate_profile_key_package<Provider: OpenMlsProvider>(
    provider: &Provider,
    encoded: &[u8],
    authenticated_peer: PeerId,
) -> Result<KeyPackage, ProfileKeyPackageError> {
    if encoded.is_empty() || encoded.len() > MAX_MLS_WIRE_BYTES {
        return Err(ProfileKeyPackageError::InvalidSize);
    }
    let mut remaining = encoded;
    let key_package = KeyPackageIn::tls_deserialize(&mut remaining)
        .map_err(|_| ProfileKeyPackageError::Malformed)?;
    if !remaining.is_empty() {
        return Err(ProfileKeyPackageError::Malformed);
    }
    let key_package = key_package
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|_| ProfileKeyPackageError::VerificationFailed)?;
    if key_package.ciphersuite() != CIPHERSUITE {
        return Err(ProfileKeyPackageError::UnsupportedCiphersuite);
    }
    if key_package.leaf_node().capabilities() != &profile_capabilities() {
        return Err(ProfileKeyPackageError::UnsupportedCapabilities);
    }
    let credential_peer = device_id_from_credential(key_package.leaf_node().credential())
        .map_err(|_| ProfileKeyPackageError::InvalidDeviceCredential)?;
    if credential_peer != authenticated_peer {
        return Err(ProfileKeyPackageError::TransportPeerMismatch);
    }
    Ok(key_package)
}

/// Stages one authenticated device addition without advancing the local epoch.
///
/// The caller must durably publish `commit()` to the signed group event graph
/// before calling [`merge_prepared_member_admission`]. The `welcome()` is then
/// returned only to the authenticated joining peer. Any validation or encoding
/// failure after OpenMLS creates the pending commit clears that commit first.
pub fn prepare_profile_member_admission<Provider: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &Provider,
    signer: &impl Signer,
    encoded_key_package: &[u8],
    authenticated_peer: PeerId,
) -> Result<PreparedMemberAdmission, PrepareMemberAdmissionError> {
    validate_group_profile(group).map_err(|_| PrepareMemberAdmissionError::InvalidGroupProfile)?;
    let key_package =
        validate_profile_key_package(provider, encoded_key_package, authenticated_peer)
            .map_err(PrepareMemberAdmissionError::InvalidKeyPackage)?;
    let (commit, welcome, _) = group
        .add_members(provider, signer, &[key_package])
        .map_err(|_| PrepareMemberAdmissionError::MemberAdditionFailed)?;

    let pending_is_valid = group
        .pending_commit()
        .is_some_and(|pending| validate_staged_commit_profile(pending).is_ok());
    if !pending_is_valid {
        return Err(rollback_prepared_admission(
            group,
            provider,
            PrepareMemberAdmissionError::InvalidPendingCommit,
        ));
    }

    let commit = match commit.tls_serialize_detached() {
        Ok(commit) => Zeroizing::new(commit),
        Err(_) => {
            return Err(rollback_prepared_admission(
                group,
                provider,
                PrepareMemberAdmissionError::WireEncodingFailed,
            ));
        }
    };
    let welcome = match welcome.tls_serialize_detached() {
        Ok(welcome) => Zeroizing::new(welcome),
        Err(_) => {
            return Err(rollback_prepared_admission(
                group,
                provider,
                PrepareMemberAdmissionError::WireEncodingFailed,
            ));
        }
    };
    if commit.is_empty()
        || commit.len() > MAX_MLS_WIRE_BYTES
        || welcome.is_empty()
        || welcome.len() > MAX_MLS_WIRE_BYTES
    {
        return Err(rollback_prepared_admission(
            group,
            provider,
            PrepareMemberAdmissionError::WireSizeExceeded,
        ));
    }

    Ok(PreparedMemberAdmission {
        peer_id: authenticated_peer,
        commit,
        welcome,
    })
}

/// Merges a prepared admission after its Commit is durably published.
pub fn merge_prepared_member_admission<Provider: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &Provider,
) -> Result<(), MergeMemberAdmissionError> {
    let pending = group
        .pending_commit()
        .ok_or(MergeMemberAdmissionError::MissingPendingCommit)?;
    validate_staged_commit_profile(pending)
        .map_err(|_| MergeMemberAdmissionError::InvalidPendingCommit)?;
    group
        .merge_pending_commit(provider)
        .map_err(|_| MergeMemberAdmissionError::MergeFailed)
}

/// Clears a prepared admission when its Commit cannot be durably published.
pub fn abort_prepared_member_admission<Provider: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &Provider,
) -> Result<(), AbortMemberAdmissionError> {
    group
        .clear_pending_commit(provider.storage())
        .map_err(|_| AbortMemberAdmissionError::StorageFailed)
}

fn rollback_prepared_admission<Provider: OpenMlsProvider>(
    group: &mut MlsGroup,
    provider: &Provider,
    error: PrepareMemberAdmissionError,
) -> PrepareMemberAdmissionError {
    match group.clear_pending_commit(provider.storage()) {
        Ok(()) => error,
        Err(_) => PrepareMemberAdmissionError::RollbackFailed,
    }
}

/// Checks and decrypts a profile Welcome without persisting the resulting
/// group.
///
/// The public ciphersuite is rejected before OpenMLS consumes the matching
/// one-time key package. The encrypted profile marker is checked after
/// decryption and before group persistence. OpenMLS consumes the key package
/// during decryption even when that second check rejects the Welcome, so the
/// application must publish a fresh key package after such a rejection.
pub fn stage_profile_welcome<Provider: openmls::storage::OpenMlsProvider>(
    provider: &Provider,
    encoded: &[u8],
) -> Result<
    StagedWelcome,
    StageWelcomeError<<Provider as openmls::storage::OpenMlsProvider>::StorageError>,
> {
    let message = decode_profile_message(encoded).map_err(StageWelcomeError::Wire)?;
    let MlsMessageBodyIn::Welcome(welcome) = message.extract() else {
        return Err(StageWelcomeError::UnexpectedMessage);
    };
    validate_ciphersuite(welcome.ciphersuite()).map_err(StageWelcomeError::Profile)?;
    let staged = StagedWelcome::new_from_welcome(provider, &group_join_config(), welcome, None)
        .map_err(StageWelcomeError::OpenMls)?;
    validate_group_context(staged.group_context()).map_err(StageWelcomeError::Profile)?;
    validate_credentials(staged.members().map(|member| member.credential))
        .map_err(StageWelcomeError::Profile)?;
    Ok(staged)
}

/// Rejects an authenticated commit that would move the group outside profile
/// version 1. Call this before `MlsGroup::merge_staged_commit`.
pub fn validate_staged_commit_profile(commit: &StagedCommit) -> Result<(), ProfileError> {
    validate_group_context(commit.group_context())?;
    validate_credentials(commit.credentials_to_verify().cloned())
}

/// Rejects restored state that is outside profile version 1.
pub fn validate_group_profile(group: &MlsGroup) -> Result<(), ProfileError> {
    validate_ciphersuite(group.ciphersuite())?;
    if group.configuration() != &group_join_config() {
        return Err(ProfileError::UnsupportedJoinConfiguration);
    }
    validate_extensions(group.extensions())?;
    validate_credentials(group.members().map(|member| member.credential))
}

fn validate_ciphersuite(ciphersuite: Ciphersuite) -> Result<(), ProfileError> {
    if ciphersuite != CIPHERSUITE {
        return Err(ProfileError::UnsupportedCiphersuite);
    }
    Ok(())
}

fn validate_group_context(context: &GroupContext) -> Result<(), ProfileError> {
    validate_ciphersuite(context.ciphersuite())?;
    validate_extensions(context.extensions())
}

fn validate_extensions(extensions: &Extensions<GroupContext>) -> Result<(), ProfileError> {
    let expected_version = PROFILE_VERSION.to_be_bytes();
    match extensions.unknown(PROFILE_EXTENSION_TYPE_ID) {
        Some(extension) if extension.0.as_slice() == expected_version => Ok(()),
        _ => Err(ProfileError::UnsupportedProfileVersion),
    }
}

fn validate_credentials(
    credentials: impl IntoIterator<Item = openmls::prelude::Credential>,
) -> Result<(), ProfileError> {
    for credential in credentials {
        device_id_from_credential(&credential)
            .map_err(|_| ProfileError::InvalidDeviceCredential)?;
    }
    Ok(())
}

fn profile_extensions() -> Extensions<GroupContext> {
    Extensions::try_from(vec![
        Extension::RequiredCapabilities(RequiredCapabilitiesExtension::new(
            &[PROFILE_EXTENSION_TYPE],
            &[],
            &[CredentialType::Basic],
        )),
        Extension::Unknown(
            PROFILE_EXTENSION_TYPE_ID,
            UnknownExtension(PROFILE_VERSION.to_be_bytes().to_vec()),
        ),
    ])
    .expect("the static CharP2P MLS profile extensions are valid")
}

#[cfg(test)]
mod tests {
    use charp2p_core::{
        DeviceIdentity, GroupIdentity, HistoryPolicy, Invitation, InvitationSpec, PeerId,
    };
    use openmls::prelude::{
        BasicCredential, Ciphersuite, CredentialWithKey, Extensions, KeyPackage, MlsGroup,
        MlsGroupCreateConfig, OpenMlsProvider, ProcessedMessageContent, ProtocolMessage,
        WireFormat, tls_codec::Serialize,
    };
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_rust_crypto::OpenMlsRustCrypto;

    use super::{
        CIPHERSUITE, DeviceCredentialError, MAX_MLS_WIRE_BYTES, MergeMemberAdmissionError,
        MlsWireError, PrepareKeyPackageError, PrepareMemberAdmissionError, ProfileError,
        ProfileKeyPackageError, ProfileProvider, ProfileProviderSnapshotError, StageWelcomeError,
        abort_prepared_member_admission, decode_profile_message, device_credential,
        device_id_from_credential, group_create_config, merge_prepared_member_admission,
        prepare_profile_key_package, prepare_profile_member_admission, profile_capabilities,
        profile_extensions, stage_profile_welcome, validate_group_profile,
        validate_profile_key_package, validate_staged_commit_profile,
    };

    fn credential(
        device_id: PeerId,
        provider: &impl OpenMlsProvider,
    ) -> (CredentialWithKey, SignatureKeyPair) {
        credential_with_basic(device_credential(device_id), provider)
    }

    fn credential_with_basic(
        credential: BasicCredential,
        provider: &impl OpenMlsProvider,
    ) -> (CredentialWithKey, SignatureKeyPair) {
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .expect("profile signature algorithm is supported");
        signer
            .store(provider.storage())
            .expect("test signer can be stored");
        (
            CredentialWithKey {
                credential: credential.into(),
                signature_key: signer.public().into(),
            },
            signer,
        )
    }

    #[test]
    fn provider_snapshot_restores_key_package_and_group_state() {
        let owner_provider = ProfileProvider::default();
        let member_provider = ProfileProvider::default();
        let owner_id = DeviceIdentity::generate().peer_id();
        let member_id = DeviceIdentity::generate().peer_id();
        let (owner_credential, owner_signer) = credential(owner_id, &owner_provider);
        let (member_credential, member_signer) = credential(member_id, &member_provider);
        let member_key_package = prepare_profile_key_package(
            &member_provider,
            &member_signer,
            member_credential,
            member_id,
        )
        .unwrap();
        let pending_snapshot = member_provider.snapshot().unwrap();
        assert_eq!(
            pending_snapshot.as_slice(),
            member_provider.snapshot().unwrap().as_slice()
        );
        let restored_member = ProfileProvider::from_snapshot(&pending_snapshot).unwrap();

        let mut owner_group = MlsGroup::new(
            &owner_provider,
            &owner_signer,
            &group_create_config(),
            owner_credential,
        )
        .unwrap();
        let admission = prepare_profile_member_admission(
            &mut owner_group,
            &owner_provider,
            &owner_signer,
            member_key_package.encoded(),
            member_id,
        )
        .unwrap();
        merge_prepared_member_admission(&mut owner_group, &owner_provider).unwrap();

        let staged = stage_profile_welcome(&restored_member, admission.welcome()).unwrap();
        let member_group = staged.into_group(&restored_member).unwrap();
        validate_group_profile(&member_group).unwrap();
        let group_id = member_group.group_id().clone();
        drop(member_group);

        let joined_snapshot = restored_member.snapshot().unwrap();
        let restored_joined = ProfileProvider::from_snapshot(&joined_snapshot).unwrap();
        let loaded = MlsGroup::load(restored_joined.storage(), &group_id)
            .unwrap()
            .expect("joined group is present in the restored snapshot");
        validate_group_profile(&loaded).unwrap();
        let member_ids: Vec<_> = loaded
            .members()
            .map(|member| device_id_from_credential(&member.credential).unwrap())
            .collect();
        assert!(member_ids.contains(&owner_id));
        assert!(member_ids.contains(&member_id));
    }

    #[test]
    fn provider_snapshot_rejects_unbounded_or_malformed_data() {
        assert!(matches!(
            ProfileProvider::from_snapshot(&[]),
            Err(ProfileProviderSnapshotError::InvalidSize)
        ));
        assert!(matches!(
            ProfileProvider::from_snapshot(&[0, 2, 0, 0, 0, 0]),
            Err(ProfileProviderSnapshotError::UnsupportedVersion(2))
        ));
        assert!(matches!(
            ProfileProvider::from_snapshot(&[0, 1, 0, 0, 0, 1]),
            Err(ProfileProviderSnapshotError::Malformed)
        ));
    }

    #[test]
    fn invited_member_decrypts_profile_application_message() {
        let owner_provider = OpenMlsRustCrypto::default();
        let member_provider = OpenMlsRustCrypto::default();
        let third_provider = OpenMlsRustCrypto::default();
        let owner_id = DeviceIdentity::generate().peer_id();
        let member_id = DeviceIdentity::generate().peer_id();
        let third_id = DeviceIdentity::generate().peer_id();
        let (owner_credential, owner_signer) = credential(owner_id, &owner_provider);
        let (member_credential, member_signer) = credential(member_id, &member_provider);
        let (third_credential, third_signer) = credential(third_id, &third_provider);
        let member_key_package = KeyPackage::builder()
            .leaf_node_capabilities(profile_capabilities())
            .build(
                CIPHERSUITE,
                &member_provider,
                &member_signer,
                member_credential,
            )
            .expect("profile key package can be built");
        let third_key_package = KeyPackage::builder()
            .leaf_node_capabilities(profile_capabilities())
            .build(
                CIPHERSUITE,
                &third_provider,
                &third_signer,
                third_credential,
            )
            .expect("third profile key package can be built");

        let mut owner_group = MlsGroup::new(
            &owner_provider,
            &owner_signer,
            &group_create_config(),
            owner_credential,
        )
        .expect("profile group can be created");
        let (_commit, welcome, _) = owner_group
            .add_members(
                &owner_provider,
                &owner_signer,
                &[member_key_package.key_package().clone()],
            )
            .expect("member can be added");
        validate_staged_commit_profile(
            owner_group
                .pending_commit()
                .expect("member addition creates a pending commit"),
        )
        .expect("locally created member addition matches the profile");
        owner_group
            .merge_pending_commit(&owner_provider)
            .expect("owner can advance the epoch");

        let welcome_bytes = welcome
            .tls_serialize_detached()
            .expect("welcome can be serialized");
        let staged = stage_profile_welcome(&member_provider, &welcome_bytes)
            .expect("invited member can stage the profile Welcome");
        let mut member_group = staged
            .into_group(&member_provider)
            .expect("invited member can join");
        validate_group_profile(&owner_group).expect("owner group matches the profile");
        validate_group_profile(&member_group).expect("joined group matches the profile");
        let member_ids: Vec<_> = member_group
            .members()
            .map(|member| device_id_from_credential(&member.credential).unwrap())
            .collect();
        assert_eq!(member_ids.len(), 2);
        assert!(member_ids.contains(&owner_id));
        assert!(member_ids.contains(&member_id));

        let message = owner_group
            .create_message(&owner_provider, &owner_signer, b"protected hello")
            .expect("owner can protect an application message");
        let message_bytes = message.to_bytes().expect("message can be serialized");
        let message_in = decode_profile_message(&message_bytes).expect("message can be parsed");
        assert_eq!(message_in.wire_format(), WireFormat::PrivateMessage);
        let protocol_message: ProtocolMessage = message_in
            .try_into_protocol_message()
            .expect("application output is a protocol message");
        let processed = member_group
            .process_message(&member_provider, protocol_message)
            .expect("member can authenticate and decrypt the message");
        let ProcessedMessageContent::ApplicationMessage(application) = processed.into_content()
        else {
            panic!("expected decrypted application data");
        };

        assert_eq!(application.into_bytes(), b"protected hello");

        let (_, third_welcome, _) = member_group
            .add_members(
                &member_provider,
                &member_signer,
                &[third_key_package.key_package().clone()],
            )
            .expect("a joined member can add another member");
        validate_staged_commit_profile(
            member_group
                .pending_commit()
                .expect("member addition creates a pending commit"),
        )
        .expect("joined member's local commit matches the profile");
        member_group
            .merge_pending_commit(&member_provider)
            .expect("joined member can advance the epoch");
        let third_welcome_bytes = third_welcome
            .tls_serialize_detached()
            .expect("third Welcome can be serialized");
        let third_staged = stage_profile_welcome(&third_provider, &third_welcome_bytes)
            .expect("joined member's Welcome carries the ratchet tree");
        let mut third_group = third_staged
            .into_group(&third_provider)
            .expect("third member can join");
        validate_group_profile(&third_group).expect("third group matches the profile");

        let profile_removal = member_group
            .commit_builder()
            .propose_group_context_extensions(Extensions::default())
            .expect("profile removal can be represented as an MLS proposal")
            .load_psks(member_provider.storage())
            .expect("proposal has no missing PSKs")
            .build(
                member_provider.rand(),
                member_provider.crypto(),
                &member_signer,
                |_| true,
            )
            .expect("profile removal commit can be built")
            .stage_commit(&member_provider)
            .expect("profile removal commit can be staged");
        let processed_removal = third_group
            .process_message(
                &third_provider,
                decode_profile_message(
                    &profile_removal
                        .commit()
                        .to_bytes()
                        .expect("commit can be serialized"),
                )
                .expect("commit can be parsed")
                .try_into_protocol_message()
                .expect("commit output is a protocol message"),
            )
            .expect("authenticated profile removal commit can be processed");
        let ProcessedMessageContent::StagedCommitMessage(staged_removal) =
            processed_removal.into_content()
        else {
            panic!("expected a staged commit");
        };
        assert_eq!(
            validate_staged_commit_profile(&staged_removal),
            Err(ProfileError::UnsupportedProfileVersion)
        );
    }

    #[test]
    fn profile_key_package_is_bound_to_the_authenticated_transport_peer() {
        let provider = OpenMlsRustCrypto::default();
        let member_id = DeviceIdentity::generate().peer_id();
        let other_id = DeviceIdentity::generate().peer_id();
        let (member_credential, member_signer) = credential(member_id, &provider);
        let member_key_package = KeyPackage::builder()
            .leaf_node_capabilities(profile_capabilities())
            .build(CIPHERSUITE, &provider, &member_signer, member_credential)
            .unwrap();
        let encoded = member_key_package
            .key_package()
            .tls_serialize_detached()
            .unwrap();

        let validated = validate_profile_key_package(&provider, &encoded, member_id).unwrap();
        assert_eq!(
            device_id_from_credential(validated.leaf_node().credential()).unwrap(),
            member_id
        );
        assert_eq!(
            validate_profile_key_package(&provider, &encoded, other_id).unwrap_err(),
            ProfileKeyPackageError::TransportPeerMismatch
        );

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            validate_profile_key_package(&provider, &trailing, member_id).unwrap_err(),
            ProfileKeyPackageError::Malformed
        );
        let mut forged = encoded;
        *forged.last_mut().unwrap() ^= 1;
        assert_eq!(
            validate_profile_key_package(&provider, &forged, member_id).unwrap_err(),
            ProfileKeyPackageError::VerificationFailed
        );
    }

    #[test]
    fn local_profile_key_package_is_bounded_and_self_validated() {
        let provider = OpenMlsRustCrypto::default();
        let device_id = DeviceIdentity::generate().peer_id();
        let other_id = DeviceIdentity::generate().peer_id();
        let (device_credential, signer) = credential(device_id, &provider);

        let prepared =
            prepare_profile_key_package(&provider, &signer, device_credential, device_id)
                .expect("profile KeyPackage can be prepared");

        assert_eq!(prepared.device_id(), device_id);
        assert!(!prepared.encoded().is_empty());
        assert!(prepared.encoded().len() <= MAX_MLS_WIRE_BYTES);
        validate_profile_key_package(&provider, prepared.encoded(), device_id).unwrap();
        let invitation = Invitation::issue(
            &GroupIdentity::generate(),
            InvitationSpec {
                group_name: "Design Crew",
                inviter_name: "Maya",
                expires_at_unix: 1_800_003_600,
                history_policy: HistoryPolicy::None,
                reusable: false,
            },
            1_800_000_000,
        )
        .unwrap();
        let request = prepared.into_join_request(&invitation).unwrap();
        assert_eq!(request.group_id(), invitation.group_id());
        assert!(!request.key_package().is_empty());

        let (device_credential, signer) = credential(device_id, &provider);
        assert_eq!(
            prepare_profile_key_package(&provider, &signer, device_credential, other_id)
                .unwrap_err(),
            PrepareKeyPackageError::InvalidDeviceCredential
        );
    }

    #[test]
    fn profile_key_package_rejects_unsupported_capabilities_and_credentials() {
        let provider = OpenMlsRustCrypto::default();
        let member_id = DeviceIdentity::generate().peer_id();
        let (member_credential, member_signer) = credential(member_id, &provider);
        let default_capabilities = KeyPackage::builder()
            .build(CIPHERSUITE, &provider, &member_signer, member_credential)
            .unwrap()
            .key_package()
            .tls_serialize_detached()
            .unwrap();
        assert_eq!(
            validate_profile_key_package(&provider, &default_capabilities, member_id).unwrap_err(),
            ProfileKeyPackageError::UnsupportedCapabilities
        );

        let malformed = BasicCredential::new(b"unscoped identity".to_vec());
        let (malformed_credential, malformed_signer) = credential_with_basic(malformed, &provider);
        let malformed_credential_package = KeyPackage::builder()
            .leaf_node_capabilities(profile_capabilities())
            .build(
                CIPHERSUITE,
                &provider,
                &malformed_signer,
                malformed_credential,
            )
            .unwrap()
            .key_package()
            .tls_serialize_detached()
            .unwrap();
        assert_eq!(
            validate_profile_key_package(&provider, &malformed_credential_package, member_id)
                .unwrap_err(),
            ProfileKeyPackageError::InvalidDeviceCredential
        );

        let (other_suite_credential, other_suite_signer) = credential(member_id, &provider);
        let other_suite_package = KeyPackage::builder()
            .leaf_node_capabilities(profile_capabilities())
            .build(
                Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                &provider,
                &other_suite_signer,
                other_suite_credential,
            )
            .unwrap()
            .key_package()
            .tls_serialize_detached()
            .unwrap();
        assert_eq!(
            validate_profile_key_package(&provider, &other_suite_package, member_id).unwrap_err(),
            ProfileKeyPackageError::UnsupportedCiphersuite
        );
        assert_eq!(
            validate_profile_key_package(&provider, &[], member_id).unwrap_err(),
            ProfileKeyPackageError::InvalidSize
        );
        assert_eq!(
            validate_profile_key_package(&provider, &vec![0; MAX_MLS_WIRE_BYTES + 1], member_id)
                .unwrap_err(),
            ProfileKeyPackageError::InvalidSize
        );
    }

    #[test]
    fn authenticated_member_admission_is_prepared_then_explicitly_merged() {
        let owner_provider = OpenMlsRustCrypto::default();
        let member_provider = OpenMlsRustCrypto::default();
        let owner_id = DeviceIdentity::generate().peer_id();
        let member_id = DeviceIdentity::generate().peer_id();
        let (owner_credential, owner_signer) = credential(owner_id, &owner_provider);
        let (member_credential, member_signer) = credential(member_id, &member_provider);
        let member_key_package = KeyPackage::builder()
            .leaf_node_capabilities(profile_capabilities())
            .build(
                CIPHERSUITE,
                &member_provider,
                &member_signer,
                member_credential,
            )
            .unwrap()
            .key_package()
            .tls_serialize_detached()
            .unwrap();
        let mut owner_group = MlsGroup::new(
            &owner_provider,
            &owner_signer,
            &group_create_config(),
            owner_credential,
        )
        .unwrap();

        let admission = prepare_profile_member_admission(
            &mut owner_group,
            &owner_provider,
            &owner_signer,
            &member_key_package,
            member_id,
        )
        .unwrap();
        assert_eq!(admission.peer_id(), member_id);
        assert!(!admission.commit().is_empty());
        assert!(!admission.welcome().is_empty());
        assert!(admission.commit().len() <= MAX_MLS_WIRE_BYTES);
        assert!(admission.welcome().len() <= MAX_MLS_WIRE_BYTES);
        assert!(owner_group.pending_commit().is_some());
        assert_eq!(owner_group.members().count(), 1);

        let staged_member = stage_profile_welcome(&member_provider, admission.welcome()).unwrap();
        let member_group = staged_member.into_group(&member_provider).unwrap();
        merge_prepared_member_admission(&mut owner_group, &owner_provider).unwrap();
        assert!(owner_group.pending_commit().is_none());
        assert_eq!(owner_group.members().count(), 2);
        assert_eq!(member_group.members().count(), 2);
        assert_eq!(
            merge_prepared_member_admission(&mut owner_group, &owner_provider).unwrap_err(),
            MergeMemberAdmissionError::MissingPendingCommit
        );
    }

    #[test]
    fn rejected_member_admission_does_not_leave_a_pending_commit() {
        let owner_provider = OpenMlsRustCrypto::default();
        let member_provider = OpenMlsRustCrypto::default();
        let owner_id = DeviceIdentity::generate().peer_id();
        let member_id = DeviceIdentity::generate().peer_id();
        let other_id = DeviceIdentity::generate().peer_id();
        let (owner_credential, owner_signer) = credential(owner_id, &owner_provider);
        let (member_credential, member_signer) = credential(member_id, &member_provider);
        let member_key_package = KeyPackage::builder()
            .leaf_node_capabilities(profile_capabilities())
            .build(
                CIPHERSUITE,
                &member_provider,
                &member_signer,
                member_credential,
            )
            .unwrap()
            .key_package()
            .tls_serialize_detached()
            .unwrap();
        let mut owner_group = MlsGroup::new(
            &owner_provider,
            &owner_signer,
            &group_create_config(),
            owner_credential,
        )
        .unwrap();

        assert_eq!(
            prepare_profile_member_admission(
                &mut owner_group,
                &owner_provider,
                &owner_signer,
                &member_key_package,
                other_id,
            )
            .unwrap_err(),
            PrepareMemberAdmissionError::InvalidKeyPackage(
                ProfileKeyPackageError::TransportPeerMismatch
            )
        );
        assert!(owner_group.pending_commit().is_none());
        assert_eq!(owner_group.members().count(), 1);

        let admission = prepare_profile_member_admission(
            &mut owner_group,
            &owner_provider,
            &owner_signer,
            &member_key_package,
            member_id,
        )
        .unwrap();
        assert!(!admission.commit().is_empty());
        assert!(owner_group.pending_commit().is_some());
        abort_prepared_member_admission(&mut owner_group, &owner_provider).unwrap();
        assert!(owner_group.pending_commit().is_none());
        assert_eq!(owner_group.members().count(), 1);
    }

    #[test]
    fn mismatched_welcome_and_restored_group_are_rejected() {
        let owner_provider = OpenMlsRustCrypto::default();
        let member_provider = OpenMlsRustCrypto::default();
        let (owner_credential, owner_signer) =
            credential(DeviceIdentity::generate().peer_id(), &owner_provider);
        let (member_credential, member_signer) =
            credential(DeviceIdentity::generate().peer_id(), &member_provider);
        let member_key_package = KeyPackage::builder()
            .leaf_node_capabilities(profile_capabilities())
            .build(
                CIPHERSUITE,
                &member_provider,
                &member_signer,
                member_credential,
            )
            .expect("profile key package can be built");
        let mut group_without_profile = MlsGroup::new(
            &owner_provider,
            &owner_signer,
            &MlsGroupCreateConfig::builder()
                .ciphersuite(CIPHERSUITE)
                .use_ratchet_tree_extension(true)
                .build(),
            owner_credential,
        )
        .expect("control group can be created");
        let (_, welcome, _) = group_without_profile
            .add_members(
                &owner_provider,
                &owner_signer,
                &[member_key_package.key_package().clone()],
            )
            .expect("control group can add the profile-capable member");
        let welcome_bytes = welcome
            .tls_serialize_detached()
            .expect("control Welcome can be serialized");
        assert!(matches!(
            stage_profile_welcome(&member_provider, &welcome_bytes),
            Err(StageWelcomeError::Profile(
                ProfileError::UnsupportedProfileVersion
            ))
        ));
        assert_eq!(
            validate_group_profile(&group_without_profile),
            Err(ProfileError::UnsupportedProfileVersion)
        );

        let second_provider = OpenMlsRustCrypto::default();
        let (second_credential, second_signer) =
            credential(DeviceIdentity::generate().peer_id(), &second_provider);
        let group_with_other_suite = MlsGroup::new(
            &second_provider,
            &second_signer,
            &MlsGroupCreateConfig::builder()
                .ciphersuite(Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519)
                .build(),
            second_credential,
        )
        .expect("control group with another supported suite can be created");
        assert_eq!(
            validate_group_profile(&group_with_other_suite),
            Err(ProfileError::UnsupportedCiphersuite)
        );

        let third_provider = OpenMlsRustCrypto::default();
        let (third_credential, third_signer) =
            credential(DeviceIdentity::generate().peer_id(), &third_provider);
        let group_without_tree_config = MlsGroup::new(
            &third_provider,
            &third_signer,
            &MlsGroupCreateConfig::builder()
                .ciphersuite(CIPHERSUITE)
                .capabilities(profile_capabilities())
                .with_group_context_extensions(profile_extensions())
                .build(),
            third_credential,
        )
        .expect("control group without tree configuration can be created");
        assert_eq!(
            validate_group_profile(&group_without_tree_config),
            Err(ProfileError::UnsupportedJoinConfiguration)
        );
    }

    #[test]
    fn device_credentials_round_trip_and_reject_malformed_identity() {
        let device_id = DeviceIdentity::generate().peer_id();
        let credential: openmls::prelude::Credential = device_credential(device_id).into();
        assert_eq!(device_id_from_credential(&credential).unwrap(), device_id);

        let malformed: openmls::prelude::Credential =
            BasicCredential::new(b"unscoped identity".to_vec()).into();
        assert!(matches!(
            device_id_from_credential(&malformed),
            Err(DeviceCredentialError::InvalidIdentity)
        ));

        let mut future_identity = super::DEVICE_CREDENTIAL_DOMAIN.to_vec();
        future_identity.extend_from_slice(&2_u16.to_be_bytes());
        future_identity.extend_from_slice(&device_id.to_bytes());
        let future: openmls::prelude::Credential = BasicCredential::new(future_identity).into();
        assert!(matches!(
            device_id_from_credential(&future),
            Err(DeviceCredentialError::UnsupportedVersion(2))
        ));

        let wrong_type =
            openmls::prelude::Credential::new(openmls::prelude::CredentialType::X509, Vec::new());
        assert!(matches!(
            device_id_from_credential(&wrong_type),
            Err(DeviceCredentialError::UnsupportedCredentialType)
        ));

        let mut oversized_identity = super::DEVICE_CREDENTIAL_DOMAIN.to_vec();
        oversized_identity.extend_from_slice(&super::DEVICE_CREDENTIAL_VERSION.to_be_bytes());
        oversized_identity.extend_from_slice(&[0; super::MAX_DEVICE_PEER_ID_BYTES + 1]);
        let oversized: openmls::prelude::Credential =
            BasicCredential::new(oversized_identity).into();
        assert!(matches!(
            device_id_from_credential(&oversized),
            Err(DeviceCredentialError::InvalidIdentity)
        ));

        let truncated: openmls::prelude::Credential =
            BasicCredential::new(super::DEVICE_CREDENTIAL_DOMAIN.to_vec()).into();
        assert!(matches!(
            device_id_from_credential(&truncated),
            Err(DeviceCredentialError::InvalidIdentity)
        ));

        let mut invalid_peer_id = super::DEVICE_CREDENTIAL_DOMAIN.to_vec();
        invalid_peer_id.extend_from_slice(&super::DEVICE_CREDENTIAL_VERSION.to_be_bytes());
        invalid_peer_id.push(0);
        let invalid: openmls::prelude::Credential = BasicCredential::new(invalid_peer_id).into();
        assert!(matches!(
            device_id_from_credential(&invalid),
            Err(DeviceCredentialError::InvalidIdentity)
        ));

        let mut trailing_identity = super::DEVICE_CREDENTIAL_DOMAIN.to_vec();
        trailing_identity.extend_from_slice(&super::DEVICE_CREDENTIAL_VERSION.to_be_bytes());
        trailing_identity.extend_from_slice(&device_id.to_bytes());
        trailing_identity.push(0);
        let trailing: openmls::prelude::Credential = BasicCredential::new(trailing_identity).into();
        assert!(matches!(
            device_id_from_credential(&trailing),
            Err(DeviceCredentialError::InvalidIdentity)
        ));
    }

    #[test]
    fn profile_paths_reject_malformed_device_credentials() {
        let malformed = || BasicCredential::new(b"unscoped identity".to_vec());

        let restored_provider = OpenMlsRustCrypto::default();
        let (restored_credential, restored_signer) =
            credential_with_basic(malformed(), &restored_provider);
        let restored_group = MlsGroup::new(
            &restored_provider,
            &restored_signer,
            &group_create_config(),
            restored_credential,
        )
        .expect("OpenMLS accepts the malformed profile credential");
        assert_eq!(
            validate_group_profile(&restored_group),
            Err(ProfileError::InvalidDeviceCredential)
        );

        let owner_provider = OpenMlsRustCrypto::default();
        let malformed_member_provider = OpenMlsRustCrypto::default();
        let (owner_credential, owner_signer) =
            credential(DeviceIdentity::generate().peer_id(), &owner_provider);
        let (malformed_member_credential, malformed_member_signer) =
            credential_with_basic(malformed(), &malformed_member_provider);
        let malformed_member_key_package = KeyPackage::builder()
            .leaf_node_capabilities(profile_capabilities())
            .build(
                CIPHERSUITE,
                &malformed_member_provider,
                &malformed_member_signer,
                malformed_member_credential,
            )
            .expect("OpenMLS accepts the malformed member credential");
        let mut owner_group = MlsGroup::new(
            &owner_provider,
            &owner_signer,
            &group_create_config(),
            owner_credential,
        )
        .expect("profile group can be created");
        let (_, malformed_welcome, _) = owner_group
            .add_members(
                &owner_provider,
                &owner_signer,
                &[malformed_member_key_package.key_package().clone()],
            )
            .expect("OpenMLS can stage the malformed member addition");
        assert_eq!(
            validate_staged_commit_profile(
                owner_group
                    .pending_commit()
                    .expect("member addition creates a pending commit"),
            ),
            Err(ProfileError::InvalidDeviceCredential)
        );
        let malformed_welcome_bytes = malformed_welcome
            .tls_serialize_detached()
            .expect("Welcome can be serialized");
        assert!(matches!(
            stage_profile_welcome(&malformed_member_provider, &malformed_welcome_bytes),
            Err(StageWelcomeError::Profile(
                ProfileError::InvalidDeviceCredential
            ))
        ));
    }

    #[test]
    fn profile_message_decoder_rejects_unbounded_and_trailing_input() {
        assert!(matches!(
            decode_profile_message(&[]),
            Err(MlsWireError::InvalidSize)
        ));
        let provider = OpenMlsRustCrypto::default();
        assert!(matches!(
            stage_profile_welcome(&provider, &[]),
            Err(StageWelcomeError::Wire(MlsWireError::InvalidSize))
        ));
        assert!(matches!(
            decode_profile_message(&vec![0; MAX_MLS_WIRE_BYTES + 1]),
            Err(MlsWireError::InvalidSize)
        ));

        let (credential, signer) = credential(DeviceIdentity::generate().peer_id(), &provider);
        let mut group = MlsGroup::new(&provider, &signer, &group_create_config(), credential)
            .expect("profile group can be created");
        let encoded_message = group
            .create_message(&provider, &signer, b"bounded")
            .expect("message can be created")
            .to_bytes()
            .expect("message can be serialized");
        assert!(matches!(
            stage_profile_welcome(&provider, &encoded_message),
            Err(StageWelcomeError::UnexpectedMessage)
        ));
        let mut encoded = encoded_message;
        encoded.push(0);
        assert!(matches!(
            decode_profile_message(&encoded),
            Err(MlsWireError::TrailingData)
        ));
    }
}
