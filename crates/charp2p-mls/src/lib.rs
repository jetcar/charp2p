#![forbid(unsafe_code)]

//! The fixed MLS profile used for CharP2P group-message protection.

pub use charp2p_core::MAX_JOIN_MLS_MESSAGE_BYTES as MAX_MLS_WIRE_BYTES;
use charp2p_core::PeerId;
use openmls::{
    group::GroupContext,
    prelude::{
        Capabilities, Ciphersuite, CredentialType, Extension, ExtensionType, Extensions,
        KeyPackage, KeyPackageIn, MlsGroup, MlsGroupCreateConfig, MlsGroupJoinConfig,
        MlsMessageBodyIn, MlsMessageIn, OpenMlsProvider, ProtocolVersion,
        RequiredCapabilitiesExtension, StagedCommit, StagedWelcome, UnknownExtension, WelcomeError,
        tls_codec::Deserialize,
    },
};
use thiserror::Error;

const PROFILE_EXTENSION_TYPE_ID: u16 = 0xF000;
const PROFILE_EXTENSION_TYPE: ExtensionType = ExtensionType::Unknown(PROFILE_EXTENSION_TYPE_ID);
const DEVICE_CREDENTIAL_DOMAIN: &[u8] = b"charp2p-device-credential\0";
const DEVICE_CREDENTIAL_VERSION: u16 = 1;
const MAX_DEVICE_PEER_ID_BYTES: usize = 128;
/// Version of the CharP2P MLS profile carried by an authenticated private-use
/// group-context extension.
pub const PROFILE_VERSION: u16 = 1;

/// The only ciphersuite accepted by profile version 1.
///
/// Pinning one suite prevents silent negotiation to a weaker or incompatible
/// construction. A future profile version can add another suite explicitly.
pub const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

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
    use charp2p_core::{DeviceIdentity, PeerId};
    use openmls::prelude::{
        BasicCredential, Ciphersuite, CredentialWithKey, Extensions, KeyPackage, MlsGroup,
        MlsGroupCreateConfig, OpenMlsProvider, ProcessedMessageContent, ProtocolMessage,
        WireFormat, tls_codec::Serialize,
    };
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_rust_crypto::OpenMlsRustCrypto;

    use super::{
        CIPHERSUITE, DeviceCredentialError, MAX_MLS_WIRE_BYTES, MlsWireError, ProfileError,
        ProfileKeyPackageError, StageWelcomeError, decode_profile_message, device_credential,
        device_id_from_credential, group_create_config, profile_capabilities, profile_extensions,
        stage_profile_welcome, validate_group_profile, validate_profile_key_package,
        validate_staged_commit_profile,
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
