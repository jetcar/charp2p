use std::borrow::Cow;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use libp2p_identity::{DecodingError, PeerId, PublicKey, SigningError};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::GroupIdentity;

const INVITATION_VERSION: u16 = 1;
const DISCOVERY_SECRET_BYTES: usize = 32;
const INVITATION_ID_BYTES: usize = 16;
const MAX_NAME_BYTES: usize = 80;
const MAX_ENCODED_BYTES: usize = 8 * 1024;
const MAX_INPUT_BYTES: usize = MAX_ENCODED_BYTES + 256;
const SIGNING_DOMAIN: &[u8] = b"charp2p-invitation-v1\0";

/// Controls which retained messages a newly joined member may request.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum HistoryPolicy {
    /// No messages created before the join event.
    None,
    /// Messages created after the invitation was issued.
    FromInvitation,
    /// All history retained by an online member.
    AllRetained,
}

/// User-selected fields used to issue an invitation.
pub struct InvitationSpec<'a> {
    /// Human-readable group name authenticated by the owner signature.
    pub group_name: &'a str,
    /// Human-readable inviter name authenticated by the owner signature.
    pub inviter_name: &'a str,
    /// Unix timestamp after which conforming clients reject the invitation.
    pub expires_at_unix: u64,
    /// History the joining member may request.
    pub history_policy: HistoryPolicy,
    /// Whether more than one membership may be created from this capability.
    pub reusable: bool,
}

/// A verified bearer capability for joining one group.
pub struct Invitation {
    claims: InvitationClaims,
    owner_public_key: PublicKey,
    signature: Vec<u8>,
}

impl Invitation {
    /// Issues a signed invitation from a group owner identity.
    pub fn issue(
        owner: &GroupIdentity,
        spec: InvitationSpec<'_>,
        now_unix: u64,
    ) -> Result<Self, InvitationError> {
        validate_name("group name", spec.group_name)?;
        validate_name("inviter name", spec.inviter_name)?;
        if spec.expires_at_unix <= now_unix {
            return Err(InvitationError::Expired);
        }

        let mut discovery_secret = [0; DISCOVERY_SECRET_BYTES];
        let mut invitation_id = [0; INVITATION_ID_BYTES];
        getrandom::fill(&mut discovery_secret)
            .and_then(|()| getrandom::fill(&mut invitation_id))
            .map_err(|_| InvitationError::RandomnessUnavailable)?;

        let owner_public_key = owner.public_key();
        let claims = InvitationClaims {
            version: INVITATION_VERSION,
            owner_public_key: owner_public_key.encode_protobuf(),
            discovery_secret,
            invitation_id,
            group_name: spec.group_name.to_owned(),
            inviter_name: spec.inviter_name.to_owned(),
            expires_at_unix: spec.expires_at_unix,
            history_policy: spec.history_policy,
            reusable: spec.reusable,
        };
        let signature = owner.sign(&signing_payload(&claims)?)?;

        Ok(Self {
            claims,
            owner_public_key,
            signature,
        })
    }

    /// Encodes the invitation as an unpadded URL-safe Base64 payload.
    pub fn encode(&self) -> Result<String, InvitationError> {
        let wire = SignedInvitation {
            claims: self.claims.clone(),
            signature: self.signature.clone(),
        };
        Ok(URL_SAFE_NO_PAD.encode(postcard::to_allocvec(&wire)?))
    }

    /// Decodes and verifies an invitation payload.
    pub fn decode(encoded: &str, now_unix: u64) -> Result<Self, InvitationError> {
        if encoded.is_empty() || encoded.len() > MAX_ENCODED_BYTES {
            return Err(InvitationError::InvalidSize);
        }

        let bytes = URL_SAFE_NO_PAD.decode(encoded)?;
        let wire: SignedInvitation = postcard::from_bytes(&bytes)?;
        validate_claims(&wire.claims, now_unix)?;

        let owner_public_key = PublicKey::try_decode_protobuf(&wire.claims.owner_public_key)?;
        if !owner_public_key.verify(&signing_payload(&wire.claims)?, &wire.signature) {
            return Err(InvitationError::InvalidSignature);
        }

        Ok(Self {
            claims: wire.claims,
            owner_public_key,
            signature: wire.signature,
        })
    }

    /// Extracts, decodes, and verifies an invitation from a pasted payload,
    /// custom URI, or the canonical HTTPS app link.
    pub fn decode_input(input: &str, now_unix: u64) -> Result<Self, InvitationError> {
        let input = input.trim();
        if input.is_empty() || input.len() > MAX_INPUT_BYTES {
            return Err(InvitationError::InvalidSize);
        }

        let encoded = if input.starts_with("charp2p:") {
            Cow::Owned(payload_from_custom_uri(input)?)
        } else if input.starts_with("https:") {
            Cow::Owned(payload_from_https_link(input)?)
        } else {
            Cow::Borrowed(input)
        };

        Self::decode(encoded.as_ref(), now_unix)
    }

    /// Returns the group identifier derived from the group owner public key.
    pub fn group_id(&self) -> PeerId {
        self.owner_public_key.to_peer_id()
    }

    /// Returns the opaque DHT rendezvous secret.
    pub fn discovery_secret(&self) -> &[u8; DISCOVERY_SECRET_BYTES] {
        &self.claims.discovery_secret
    }

    /// Returns the random identifier used for revocation and replay tracking.
    pub fn invitation_id(&self) -> &[u8; INVITATION_ID_BYTES] {
        &self.claims.invitation_id
    }

    /// Returns the authenticated display name of the group.
    pub fn group_name(&self) -> &str {
        &self.claims.group_name
    }

    /// Returns the authenticated display name of the inviter.
    pub fn inviter_name(&self) -> &str {
        &self.claims.inviter_name
    }

    /// Returns the invitation expiry as a Unix timestamp.
    pub fn expires_at_unix(&self) -> u64 {
        self.claims.expires_at_unix
    }

    /// Returns the history access granted by the invitation.
    pub fn history_policy(&self) -> HistoryPolicy {
        self.claims.history_policy
    }

    /// Returns whether the capability may authorize more than one membership.
    pub fn is_reusable(&self) -> bool {
        self.claims.reusable
    }
}

/// Failures produced while issuing, encoding, or validating invitations.
#[derive(Debug, Error)]
pub enum InvitationError {
    /// The payload is empty or exceeds the protocol limit.
    #[error("invitation payload has an invalid size")]
    InvalidSize,
    /// A link does not use the supported scheme, host, path, or fragment form.
    #[error("invitation link is invalid")]
    InvalidLink,
    /// Base64 decoding failed.
    #[error("invitation is not valid URL-safe Base64")]
    Base64(#[from] base64::DecodeError),
    /// Binary serialization or deserialization failed.
    #[error("invitation binary payload is malformed")]
    Serialization(#[from] postcard::Error),
    /// The embedded owner public key is malformed.
    #[error("invitation owner public key is invalid")]
    PublicKey(#[from] DecodingError),
    /// Signing failed.
    #[error("invitation could not be signed")]
    Signing(#[from] SigningError),
    /// The invitation version is unsupported.
    #[error("unsupported invitation version {0}")]
    UnsupportedVersion(u16),
    /// An authenticated display field violates protocol limits.
    #[error("invalid invitation field: {0}")]
    InvalidField(&'static str),
    /// The invitation is expired.
    #[error("invitation has expired")]
    Expired,
    /// The owner signature does not validate the claims.
    #[error("invitation signature is invalid")]
    InvalidSignature,
    /// The operating system random source failed.
    #[error("secure random source is unavailable")]
    RandomnessUnavailable,
}

fn payload_from_custom_uri(input: &str) -> Result<String, InvitationError> {
    let url = Url::parse(input).map_err(|_| InvitationError::InvalidLink)?;
    if url.scheme() != "charp2p"
        || url.host_str() != Some("join")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(InvitationError::InvalidLink);
    }

    url.path()
        .strip_prefix('/')
        .filter(|payload| !payload.is_empty() && !payload.contains('/'))
        .map(str::to_owned)
        .ok_or(InvitationError::InvalidLink)
}

fn payload_from_https_link(input: &str) -> Result<String, InvitationError> {
    let url = Url::parse(input).map_err(|_| InvitationError::InvalidLink)?;
    if url.scheme() != "https"
        || url.host_str() != Some("join.charp2p.example")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.path() != "/i"
        || url.query().is_some()
    {
        return Err(InvitationError::InvalidLink);
    }

    url.fragment()
        .filter(|payload| !payload.is_empty())
        .map(str::to_owned)
        .ok_or(InvitationError::InvalidLink)
}

#[derive(Clone, Deserialize, Serialize)]
struct InvitationClaims {
    version: u16,
    owner_public_key: Vec<u8>,
    discovery_secret: [u8; DISCOVERY_SECRET_BYTES],
    invitation_id: [u8; INVITATION_ID_BYTES],
    group_name: String,
    inviter_name: String,
    expires_at_unix: u64,
    history_policy: HistoryPolicy,
    reusable: bool,
}

#[derive(Deserialize, Serialize)]
struct SignedInvitation {
    claims: InvitationClaims,
    signature: Vec<u8>,
}

fn signing_payload(claims: &InvitationClaims) -> Result<Vec<u8>, postcard::Error> {
    let encoded = postcard::to_allocvec(claims)?;
    let mut payload = Vec::with_capacity(SIGNING_DOMAIN.len() + encoded.len());
    payload.extend_from_slice(SIGNING_DOMAIN);
    payload.extend_from_slice(&encoded);
    Ok(payload)
}

fn validate_claims(claims: &InvitationClaims, now_unix: u64) -> Result<(), InvitationError> {
    if claims.version != INVITATION_VERSION {
        return Err(InvitationError::UnsupportedVersion(claims.version));
    }
    validate_name("group name", &claims.group_name)?;
    validate_name("inviter name", &claims.inviter_name)?;
    if claims.expires_at_unix <= now_unix {
        return Err(InvitationError::Expired);
    }
    Ok(())
}

fn validate_name(field: &'static str, value: &str) -> Result<(), InvitationError> {
    if value.is_empty()
        || value.len() > MAX_NAME_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(InvitationError::InvalidField(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    use super::{HistoryPolicy, Invitation, InvitationError, InvitationSpec, SignedInvitation};
    use crate::GroupIdentity;

    const NOW: u64 = 1_800_000_000;

    fn spec(expires_at_unix: u64) -> InvitationSpec<'static> {
        InvitationSpec {
            group_name: "Design Crew",
            inviter_name: "Maya",
            expires_at_unix,
            history_policy: HistoryPolicy::FromInvitation,
            reusable: false,
        }
    }

    #[test]
    fn issued_invitation_round_trips_and_preserves_authenticated_fields() {
        let owner = GroupIdentity::generate();
        let invitation = Invitation::issue(&owner, spec(NOW + 3_600), NOW).unwrap();
        let encoded = invitation.encode().unwrap();
        let decoded = Invitation::decode(&encoded, NOW + 60).unwrap();

        assert_eq!(decoded.group_id(), owner.group_id());
        assert_eq!(decoded.group_name(), "Design Crew");
        assert_eq!(decoded.inviter_name(), "Maya");
        assert_eq!(decoded.expires_at_unix(), NOW + 3_600);
        assert_eq!(decoded.history_policy(), HistoryPolicy::FromInvitation);
        assert!(!decoded.is_reusable());
        assert_eq!(decoded.discovery_secret(), invitation.discovery_secret());
        assert_eq!(decoded.invitation_id(), invitation.invitation_id());
    }

    #[test]
    fn changing_an_authenticated_field_invalidates_the_signature() {
        let owner = GroupIdentity::generate();
        let invitation = Invitation::issue(&owner, spec(NOW + 3_600), NOW).unwrap();
        let bytes = URL_SAFE_NO_PAD
            .decode(invitation.encode().unwrap())
            .unwrap();
        let mut wire: SignedInvitation = postcard::from_bytes(&bytes).unwrap();
        wire.claims.group_name = "Impostor Group".to_owned();
        let tampered = URL_SAFE_NO_PAD.encode(postcard::to_allocvec(&wire).unwrap());

        assert!(matches!(
            Invitation::decode(&tampered, NOW),
            Err(InvitationError::InvalidSignature)
        ));
    }

    #[test]
    fn expired_invitation_is_rejected_on_issue_and_decode() {
        let owner = GroupIdentity::generate();

        assert!(matches!(
            Invitation::issue(&owner, spec(NOW), NOW),
            Err(InvitationError::Expired)
        ));

        let invitation = Invitation::issue(&owner, spec(NOW + 1), NOW).unwrap();
        assert!(matches!(
            Invitation::decode(&invitation.encode().unwrap(), NOW + 1),
            Err(InvitationError::Expired)
        ));
    }

    #[test]
    fn invalid_display_names_are_rejected_before_signing() {
        let owner = GroupIdentity::generate();
        let mut invalid = spec(NOW + 3_600);
        invalid.group_name = " Design Crew";

        assert!(matches!(
            Invitation::issue(&owner, invalid, NOW),
            Err(InvitationError::InvalidField("group name"))
        ));
    }

    #[test]
    fn invitations_get_distinct_secrets_and_identifiers() {
        let owner = GroupIdentity::generate();
        let first = Invitation::issue(&owner, spec(NOW + 3_600), NOW).unwrap();
        let second = Invitation::issue(&owner, spec(NOW + 3_600), NOW).unwrap();

        assert_ne!(first.discovery_secret(), second.discovery_secret());
        assert_ne!(first.invitation_id(), second.invitation_id());
    }

    #[test]
    fn oversized_encoded_payload_is_rejected_before_decoding() {
        let oversized = "A".repeat(8 * 1024 + 1);

        assert!(matches!(
            Invitation::decode(&oversized, NOW),
            Err(InvitationError::InvalidSize)
        ));
    }

    #[test]
    fn supported_link_forms_decode_the_same_invitation() {
        let owner = GroupIdentity::generate();
        let encoded = Invitation::issue(&owner, spec(NOW + 3_600), NOW)
            .unwrap()
            .encode()
            .unwrap();
        let inputs = [
            encoded.clone(),
            format!("charp2p://join/{encoded}"),
            format!("https://join.charp2p.example/i#{encoded}"),
        ];

        for input in inputs {
            let decoded = Invitation::decode_input(&input, NOW).unwrap();
            assert_eq!(decoded.group_id(), owner.group_id());
        }
    }

    #[test]
    fn links_reject_secrets_in_queries_or_on_untrusted_hosts() {
        let owner = GroupIdentity::generate();
        let encoded = Invitation::issue(&owner, spec(NOW + 3_600), NOW)
            .unwrap()
            .encode()
            .unwrap();

        assert!(matches!(
            Invitation::decode_input(&format!("charp2p://join/{encoded}?secret=1"), NOW),
            Err(InvitationError::InvalidLink)
        ));
        assert!(matches!(
            Invitation::decode_input(&format!("https://example.com/i#{encoded}"), NOW),
            Err(InvitationError::InvalidLink)
        ));
        assert!(matches!(
            Invitation::decode_input(
                &format!("https://attacker@join.charp2p.example/i#{encoded}"),
                NOW
            ),
            Err(InvitationError::InvalidLink)
        ));
        assert!(matches!(
            Invitation::decode_input(
                &format!("https://join.charp2p.example:444/i#{encoded}"),
                NOW
            ),
            Err(InvitationError::InvalidLink)
        ));
        assert!(matches!(
            Invitation::decode_input(
                &format!("https://join.charp2p.example/i?invite={encoded}"),
                NOW
            ),
            Err(InvitationError::InvalidLink)
        ));
    }
}
