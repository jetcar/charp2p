#![forbid(unsafe_code)]

//! The fixed MLS profile used for CharP2P group-message protection.

use openmls::{
    group::GroupContext,
    prelude::{
        Capabilities, Ciphersuite, CredentialType, Extension, ExtensionType, Extensions, MlsGroup,
        MlsGroupCreateConfig, MlsGroupJoinConfig, RequiredCapabilitiesExtension, StagedCommit,
        StagedWelcome, UnknownExtension, Welcome, WelcomeError,
    },
};

const PROFILE_EXTENSION_TYPE_ID: u16 = 0xF000;
const PROFILE_EXTENSION_TYPE: ExtensionType = ExtensionType::Unknown(PROFILE_EXTENSION_TYPE_ID);

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
}

/// Failure while checking and decrypting a profile Welcome.
#[derive(Debug)]
pub enum StageWelcomeError<StorageError> {
    /// The Welcome does not conform to the CharP2P profile.
    Profile(ProfileError),
    /// OpenMLS rejected the Welcome or its stored key material.
    OpenMls(WelcomeError<StorageError>),
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
    welcome: Welcome,
) -> Result<
    StagedWelcome,
    StageWelcomeError<<Provider as openmls::storage::OpenMlsProvider>::StorageError>,
> {
    validate_ciphersuite(welcome.ciphersuite()).map_err(StageWelcomeError::Profile)?;
    let staged = StagedWelcome::new_from_welcome(provider, &group_join_config(), welcome, None)
        .map_err(StageWelcomeError::OpenMls)?;
    validate_group_context(staged.group_context()).map_err(StageWelcomeError::Profile)?;
    Ok(staged)
}

/// Rejects an authenticated commit that would move the group outside profile
/// version 1. Call this before `MlsGroup::merge_staged_commit`.
pub fn validate_staged_commit_profile(commit: &StagedCommit) -> Result<(), ProfileError> {
    validate_group_context(commit.group_context())
}

/// Rejects restored state that is outside profile version 1.
pub fn validate_group_profile(group: &MlsGroup) -> Result<(), ProfileError> {
    validate_ciphersuite(group.ciphersuite())?;
    if group.configuration() != &group_join_config() {
        return Err(ProfileError::UnsupportedJoinConfiguration);
    }
    validate_extensions(group.extensions())
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
    use openmls::prelude::{
        BasicCredential, Ciphersuite, CredentialWithKey, Extensions, KeyPackage, MlsGroup,
        MlsGroupCreateConfig, MlsMessageBodyIn, MlsMessageIn, OpenMlsProvider,
        ProcessedMessageContent, ProtocolMessage, WireFormat,
        tls_codec::{Deserialize, Serialize},
    };
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_rust_crypto::OpenMlsRustCrypto;

    use super::{
        CIPHERSUITE, ProfileError, StageWelcomeError, group_create_config, profile_capabilities,
        profile_extensions, stage_profile_welcome, validate_group_profile,
        validate_staged_commit_profile,
    };

    fn credential(
        identity: &[u8],
        provider: &impl OpenMlsProvider,
    ) -> (CredentialWithKey, SignatureKeyPair) {
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .expect("profile signature algorithm is supported");
        signer
            .store(provider.storage())
            .expect("test signer can be stored");
        let credential = BasicCredential::new(identity.to_vec());
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
        let (owner_credential, owner_signer) = credential(b"owner-device", &owner_provider);
        let (member_credential, member_signer) = credential(b"member-device", &member_provider);
        let (third_credential, third_signer) = credential(b"third-device", &third_provider);
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
        owner_group
            .merge_pending_commit(&owner_provider)
            .expect("owner can advance the epoch");

        let welcome_bytes = welcome
            .tls_serialize_detached()
            .expect("welcome can be serialized");
        let welcome_in = MlsMessageIn::tls_deserialize(&mut welcome_bytes.as_slice())
            .expect("welcome can be parsed");
        let MlsMessageBodyIn::Welcome(welcome) = welcome_in.extract() else {
            panic!("expected an MLS Welcome");
        };
        let staged = stage_profile_welcome(&member_provider, welcome)
            .expect("invited member can stage the profile Welcome");
        let mut member_group = staged
            .into_group(&member_provider)
            .expect("invited member can join");
        validate_group_profile(&owner_group).expect("owner group matches the profile");
        validate_group_profile(&member_group).expect("joined group matches the profile");

        let message = owner_group
            .create_message(&owner_provider, &owner_signer, b"protected hello")
            .expect("owner can protect an application message");
        let message_bytes = message.to_bytes().expect("message can be serialized");
        let message_in =
            MlsMessageIn::tls_deserialize_exact(message_bytes).expect("message can be parsed");
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
        member_group
            .merge_pending_commit(&member_provider)
            .expect("joined member can advance the epoch");
        let third_welcome_bytes = third_welcome
            .tls_serialize_detached()
            .expect("third Welcome can be serialized");
        let third_welcome_in = MlsMessageIn::tls_deserialize_exact(third_welcome_bytes)
            .expect("third Welcome can be parsed");
        let MlsMessageBodyIn::Welcome(third_welcome) = third_welcome_in.extract() else {
            panic!("expected an MLS Welcome");
        };
        let third_staged = stage_profile_welcome(&third_provider, third_welcome)
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
                MlsMessageIn::tls_deserialize_exact(
                    profile_removal
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
    fn mismatched_welcome_and_restored_group_are_rejected() {
        let owner_provider = OpenMlsRustCrypto::default();
        let member_provider = OpenMlsRustCrypto::default();
        let (owner_credential, owner_signer) = credential(b"owner-device", &owner_provider);
        let (member_credential, member_signer) = credential(b"member-device", &member_provider);
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
        let welcome_in = MlsMessageIn::tls_deserialize_exact(welcome_bytes)
            .expect("control Welcome can be parsed");
        let MlsMessageBodyIn::Welcome(welcome) = welcome_in.extract() else {
            panic!("expected an MLS Welcome");
        };
        assert!(matches!(
            stage_profile_welcome(&member_provider, welcome),
            Err(StageWelcomeError::Profile(
                ProfileError::UnsupportedProfileVersion
            ))
        ));
        assert_eq!(
            validate_group_profile(&group_without_profile),
            Err(ProfileError::UnsupportedProfileVersion)
        );

        let second_provider = OpenMlsRustCrypto::default();
        let (second_credential, second_signer) = credential(b"second-device", &second_provider);
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
        let (third_credential, third_signer) = credential(b"third-device", &third_provider);
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
}
