use std::borrow::Cow;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use libp2p_identity::{DecodingError, PeerId, PublicKey, SigningError};
use multiaddr::{Multiaddr, Protocol};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

use crate::GroupIdentity;

const INVITATION_VERSION: u16 = 2;
const HINTED_INVITATION_VERSION: u16 = 3;
/// Most inviter address hints carried by one invitation.
pub const MAX_ADDRESS_HINTS: usize = 4;
const MAX_ADDRESS_HINT_BYTES: usize = 256;
const DISCOVERY_SECRET_BYTES: usize = 32;
const INVITATION_ID_BYTES: usize = 16;
const MAX_INVITER_DEVICE_ID_BYTES: usize = 128;
const MAX_NAME_BYTES: usize = 80;
/// Largest canonical encoded invitation payload accepted by the protocol.
pub const MAX_INVITATION_ENCODED_BYTES: usize = 8 * 1024;
const MAX_INPUT_BYTES: usize = MAX_INVITATION_ENCODED_BYTES + 256;
const SIGNING_DOMAIN: &[u8] = b"charp2p-invitation-v2\0";
const HINTED_SIGNING_DOMAIN: &[u8] = b"charp2p-invitation-v3\0";

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
#[derive(Clone, Copy)]
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
    address_hints: Vec<Multiaddr>,
    owner_public_key: PublicKey,
    signature: Vec<u8>,
}

/// Opaque identifier used to revoke or account for one issued invitation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct InvitationId([u8; INVITATION_ID_BYTES]);

impl InvitationId {
    /// Reconstructs an identifier loaded from trusted local metadata.
    pub fn from_bytes(bytes: [u8; INVITATION_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the fixed-width identifier bytes.
    pub fn as_bytes(&self) -> &[u8; INVITATION_ID_BYTES] {
        &self.0
    }
}

impl Invitation {
    /// Issues a signed invitation from a group owner identity.
    pub fn issue(
        owner: &GroupIdentity,
        inviter_device_id: PeerId,
        spec: InvitationSpec<'_>,
        now_unix: u64,
    ) -> Result<Self, InvitationError> {
        Self::issue_with_address_hints(owner, inviter_device_id, spec, &[], now_unix)
    }

    /// Issues a signed invitation that also authenticates inviter device
    /// addresses, direct or relayed, for joiners to dial before a DHT lookup.
    /// Hints produce a version 3 invitation; an empty list issues version 2.
    pub fn issue_with_address_hints(
        owner: &GroupIdentity,
        inviter_device_id: PeerId,
        spec: InvitationSpec<'_>,
        address_hints: &[Multiaddr],
        now_unix: u64,
    ) -> Result<Self, InvitationError> {
        validate_name("group name", spec.group_name)?;
        validate_name("inviter name", spec.inviter_name)?;
        let inviter_device_id = inviter_device_id.to_bytes();
        validate_inviter_device_id(&inviter_device_id)?;
        if spec.expires_at_unix <= now_unix {
            return Err(InvitationError::Expired);
        }
        let encoded_hints = address_hints
            .iter()
            .map(Multiaddr::to_vec)
            .collect::<Vec<_>>();
        if !encoded_hints.is_empty() {
            validate_address_hints(&encoded_hints)?;
        }

        let mut discovery_secret = [0; DISCOVERY_SECRET_BYTES];
        let mut invitation_id = [0; INVITATION_ID_BYTES];
        getrandom::fill(&mut discovery_secret)
            .and_then(|()| getrandom::fill(&mut invitation_id))
            .map_err(|_| InvitationError::RandomnessUnavailable)?;

        let owner_public_key = owner.public_key();
        let claims = InvitationClaims {
            version: if encoded_hints.is_empty() {
                INVITATION_VERSION
            } else {
                HINTED_INVITATION_VERSION
            },
            owner_public_key: owner_public_key.encode_protobuf(),
            inviter_device_id,
            discovery_secret,
            invitation_id,
            group_name: spec.group_name.to_owned(),
            inviter_name: spec.inviter_name.to_owned(),
            expires_at_unix: spec.expires_at_unix,
            history_policy: spec.history_policy,
            reusable: spec.reusable,
        };
        let signature = owner.sign(&signing_payload(&claims, &encoded_hints)?)?;
        let invitation = Self {
            claims,
            address_hints: address_hints.to_vec(),
            owner_public_key,
            signature,
        };
        if invitation.encode()?.len() > MAX_INVITATION_ENCODED_BYTES {
            return Err(InvitationError::InvalidSize);
        }
        Ok(invitation)
    }

    /// Encodes the invitation as an unpadded URL-safe Base64 payload.
    pub fn encode(&self) -> Result<String, InvitationError> {
        let bytes = if self.address_hints.is_empty() {
            postcard::to_allocvec(&SignedInvitation {
                claims: self.claims.clone(),
                signature: self.signature.clone(),
            })?
        } else {
            postcard::to_allocvec(&SignedHintedInvitation {
                claims: self.claims.clone(),
                address_hints: self.address_hints.iter().map(Multiaddr::to_vec).collect(),
                signature: self.signature.clone(),
            })?
        };
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }

    /// Encodes the invitation as the application custom URI registered by the
    /// Windows and Android clients.
    pub fn custom_uri(&self) -> Result<String, InvitationError> {
        Ok(format!("charp2p://join/{}", self.encode()?))
    }

    /// Encodes the invitation as the canonical HTTPS App Link.
    pub fn https_link(&self) -> Result<String, InvitationError> {
        Ok(format!("https://join.charp2p.example/i#{}", self.encode()?))
    }

    /// Decodes and verifies an invitation payload.
    pub fn decode(encoded: &str, now_unix: u64) -> Result<Self, InvitationError> {
        if encoded.is_empty() || encoded.len() > MAX_INVITATION_ENCODED_BYTES {
            return Err(InvitationError::InvalidSize);
        }

        let bytes = URL_SAFE_NO_PAD.decode(encoded)?;
        // The version is the first claim field, so it selects the wire layout.
        let (version, _) = postcard::take_from_bytes::<u16>(&bytes)?;
        let (claims, encoded_hints, signature) = if version == HINTED_INVITATION_VERSION {
            let wire: SignedHintedInvitation = postcard::from_bytes(&bytes)?;
            if postcard::to_allocvec(&wire)? != bytes {
                return Err(InvitationError::NonCanonical);
            }
            (wire.claims, wire.address_hints, wire.signature)
        } else {
            let wire: SignedInvitation = postcard::from_bytes(&bytes)?;
            if postcard::to_allocvec(&wire)? != bytes {
                return Err(InvitationError::NonCanonical);
            }
            (wire.claims, Vec::new(), wire.signature)
        };
        validate_claims(&claims, now_unix)?;
        let address_hints = if claims.version == HINTED_INVITATION_VERSION {
            validate_address_hints(&encoded_hints)?
        } else {
            Vec::new()
        };

        let owner_public_key = PublicKey::try_decode_protobuf(&claims.owner_public_key)?;
        if !owner_public_key.verify(&signing_payload(&claims, &encoded_hints)?, &signature) {
            return Err(InvitationError::InvalidSignature);
        }

        Ok(Self {
            claims,
            address_hints,
            owner_public_key,
            signature,
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
    pub fn invitation_id(&self) -> InvitationId {
        InvitationId(self.claims.invitation_id)
    }

    /// Returns the authenticated display name of the group.
    pub fn group_name(&self) -> &str {
        &self.claims.group_name
    }

    /// Returns the authenticated display name of the inviter.
    pub fn inviter_name(&self) -> &str {
        &self.claims.inviter_name
    }

    /// Returns the root-authorized device expected to answer this invitation.
    pub fn inviter_device_id(&self) -> PeerId {
        PeerId::from_bytes(&self.claims.inviter_device_id)
            .expect("validated during invitation construction")
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

    /// Returns the authenticated inviter address hints, without the trailing
    /// inviter peer ID. Version 2 invitations carry none.
    pub fn address_hints(&self) -> &[Multiaddr] {
        &self.address_hints
    }
}

/// Failures produced while issuing, encoding, or validating invitations.
#[derive(Debug, Error)]
pub enum InvitationError {
    /// The payload is empty or exceeds the protocol limit.
    #[error("invitation payload has an invalid size")]
    InvalidSize,
    /// The payload is not in its canonical binary encoding.
    #[error("invitation payload is not canonically encoded")]
    NonCanonical,
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
    /// The root-authorized inviter device identifier is malformed.
    #[error("invitation device identifier is invalid")]
    InvalidInviterDevice,
    /// An inviter address hint is malformed, duplicated, or over the limits.
    #[error("invitation address hint is invalid")]
    InvalidAddressHint,
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
    inviter_device_id: Vec<u8>,
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

/// Version 3 wire layout: version 2 claims followed by binary multiaddress
/// hints, all covered by the root signature.
#[derive(Deserialize, Serialize)]
struct SignedHintedInvitation {
    claims: InvitationClaims,
    address_hints: Vec<Vec<u8>>,
    signature: Vec<u8>,
}

fn signing_payload(
    claims: &InvitationClaims,
    address_hints: &[Vec<u8>],
) -> Result<Vec<u8>, postcard::Error> {
    let (domain, encoded) = if claims.version == HINTED_INVITATION_VERSION {
        (
            HINTED_SIGNING_DOMAIN,
            postcard::to_allocvec(&(claims, address_hints))?,
        )
    } else {
        (SIGNING_DOMAIN, postcard::to_allocvec(claims)?)
    };
    let mut payload = Vec::with_capacity(domain.len() + encoded.len());
    payload.extend_from_slice(domain);
    payload.extend_from_slice(&encoded);
    Ok(payload)
}

fn validate_claims(claims: &InvitationClaims, now_unix: u64) -> Result<(), InvitationError> {
    if claims.version != INVITATION_VERSION && claims.version != HINTED_INVITATION_VERSION {
        return Err(InvitationError::UnsupportedVersion(claims.version));
    }
    validate_name("group name", &claims.group_name)?;
    validate_name("inviter name", &claims.inviter_name)?;
    validate_inviter_device_id(&claims.inviter_device_id)?;
    if claims.expires_at_unix <= now_unix {
        return Err(InvitationError::Expired);
    }
    Ok(())
}

fn validate_inviter_device_id(encoded: &[u8]) -> Result<(), InvitationError> {
    if encoded.is_empty()
        || encoded.len() > MAX_INVITER_DEVICE_ID_BYTES
        || PeerId::from_bytes(encoded).is_err()
    {
        return Err(InvitationError::InvalidInviterDevice);
    }
    Ok(())
}

/// Parses version 3 hints: one to four distinct multiaddresses, each without a
/// trailing `/p2p` component because the dialer appends the pinned inviter.
fn validate_address_hints(encoded: &[Vec<u8>]) -> Result<Vec<Multiaddr>, InvitationError> {
    if encoded.is_empty() || encoded.len() > MAX_ADDRESS_HINTS {
        return Err(InvitationError::InvalidAddressHint);
    }
    let mut hints: Vec<Multiaddr> = Vec::with_capacity(encoded.len());
    for bytes in encoded {
        if bytes.is_empty() || bytes.len() > MAX_ADDRESS_HINT_BYTES {
            return Err(InvitationError::InvalidAddressHint);
        }
        let hint =
            Multiaddr::try_from(bytes.clone()).map_err(|_| InvitationError::InvalidAddressHint)?;
        if hint.to_vec() != *bytes
            || matches!(hint.iter().last(), Some(Protocol::P2p(_)))
            || hints.contains(&hint)
        {
            return Err(InvitationError::InvalidAddressHint);
        }
        hints.push(hint);
    }
    Ok(hints)
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

    use multiaddr::Multiaddr;

    use super::{
        HistoryPolicy, Invitation, InvitationError, InvitationSpec, SignedHintedInvitation,
        SignedInvitation, signing_payload,
    };
    use crate::{DeviceIdentity, GroupIdentity};

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
        let inviter_device_id = DeviceIdentity::generate().peer_id();
        let invitation =
            Invitation::issue(&owner, inviter_device_id, spec(NOW + 3_600), NOW).unwrap();
        let encoded = invitation.encode().unwrap();
        let decoded = Invitation::decode(&encoded, NOW + 60).unwrap();

        assert_eq!(decoded.group_id(), owner.group_id());
        assert_eq!(decoded.group_name(), "Design Crew");
        assert_eq!(decoded.inviter_name(), "Maya");
        assert_eq!(decoded.inviter_device_id(), inviter_device_id);
        assert_eq!(decoded.expires_at_unix(), NOW + 3_600);
        assert_eq!(decoded.history_policy(), HistoryPolicy::FromInvitation);
        assert!(!decoded.is_reusable());
        assert_eq!(decoded.discovery_secret(), invitation.discovery_secret());
        assert_eq!(decoded.invitation_id(), invitation.invitation_id());
    }

    #[test]
    fn decoder_accepts_only_the_canonical_encoding() {
        let owner = GroupIdentity::generate();
        let invitation = Invitation::issue(
            &owner,
            DeviceIdentity::generate().peer_id(),
            spec(NOW + 3_600),
            NOW,
        )
        .unwrap();
        let mut bytes = URL_SAFE_NO_PAD
            .decode(invitation.encode().unwrap())
            .unwrap();
        bytes.push(0);

        assert!(matches!(
            Invitation::decode(&URL_SAFE_NO_PAD.encode(bytes), NOW),
            Err(InvitationError::NonCanonical)
        ));
    }

    #[test]
    fn changing_an_authenticated_field_invalidates_the_signature() {
        let owner = GroupIdentity::generate();
        let invitation = Invitation::issue(
            &owner,
            DeviceIdentity::generate().peer_id(),
            spec(NOW + 3_600),
            NOW,
        )
        .unwrap();
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
    fn changing_the_inviter_device_invalidates_the_root_signature() {
        let owner = GroupIdentity::generate();
        let invitation = Invitation::issue(
            &owner,
            DeviceIdentity::generate().peer_id(),
            spec(NOW + 3_600),
            NOW,
        )
        .unwrap();
        let bytes = URL_SAFE_NO_PAD
            .decode(invitation.encode().unwrap())
            .unwrap();
        let mut wire: SignedInvitation = postcard::from_bytes(&bytes).unwrap();
        wire.claims.inviter_device_id = DeviceIdentity::generate().peer_id().to_bytes();
        let tampered = URL_SAFE_NO_PAD.encode(postcard::to_allocvec(&wire).unwrap());

        assert!(matches!(
            Invitation::decode(&tampered, NOW),
            Err(InvitationError::InvalidSignature)
        ));
    }

    #[test]
    fn malformed_inviter_device_is_rejected_before_signature_verification() {
        let owner = GroupIdentity::generate();
        let invitation = Invitation::issue(
            &owner,
            DeviceIdentity::generate().peer_id(),
            spec(NOW + 3_600),
            NOW,
        )
        .unwrap();
        let bytes = URL_SAFE_NO_PAD
            .decode(invitation.encode().unwrap())
            .unwrap();
        let mut wire: SignedInvitation = postcard::from_bytes(&bytes).unwrap();
        wire.claims.inviter_device_id = vec![0; 129];
        wire.signature = owner
            .sign(&signing_payload(&wire.claims, &[]).unwrap())
            .unwrap();
        let malformed = URL_SAFE_NO_PAD.encode(postcard::to_allocvec(&wire).unwrap());

        assert!(matches!(
            Invitation::decode(&malformed, NOW),
            Err(InvitationError::InvalidInviterDevice)
        ));
    }

    #[test]
    fn expired_invitation_is_rejected_on_issue_and_decode() {
        let owner = GroupIdentity::generate();

        assert!(matches!(
            Invitation::issue(&owner, DeviceIdentity::generate().peer_id(), spec(NOW), NOW),
            Err(InvitationError::Expired)
        ));

        let invitation = Invitation::issue(
            &owner,
            DeviceIdentity::generate().peer_id(),
            spec(NOW + 1),
            NOW,
        )
        .unwrap();
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
            Invitation::issue(&owner, DeviceIdentity::generate().peer_id(), invalid, NOW),
            Err(InvitationError::InvalidField("group name"))
        ));
    }

    #[test]
    fn invitations_get_distinct_secrets_and_identifiers() {
        let owner = GroupIdentity::generate();
        let first = Invitation::issue(
            &owner,
            DeviceIdentity::generate().peer_id(),
            spec(NOW + 3_600),
            NOW,
        )
        .unwrap();
        let second = Invitation::issue(
            &owner,
            DeviceIdentity::generate().peer_id(),
            spec(NOW + 3_600),
            NOW,
        )
        .unwrap();

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
        let invitation = Invitation::issue(
            &owner,
            DeviceIdentity::generate().peer_id(),
            spec(NOW + 3_600),
            NOW,
        )
        .unwrap();
        let inputs = [
            invitation.encode().unwrap(),
            invitation.custom_uri().unwrap(),
            invitation.https_link().unwrap(),
        ];

        for input in inputs {
            let decoded = Invitation::decode_input(&input, NOW).unwrap();
            assert_eq!(decoded.group_id(), owner.group_id());
        }
    }

    #[test]
    fn links_reject_secrets_in_queries_or_on_untrusted_hosts() {
        let owner = GroupIdentity::generate();
        let encoded = Invitation::issue(
            &owner,
            DeviceIdentity::generate().peer_id(),
            spec(NOW + 3_600),
            NOW,
        )
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

    fn hints() -> Vec<Multiaddr> {
        vec![
            "/ip4/192.0.2.10/udp/4001/quic-v1".parse().unwrap(),
            format!(
                "/ip4/198.51.100.7/udp/4001/quic-v1/p2p/{}/p2p-circuit",
                DeviceIdentity::generate().peer_id()
            )
            .parse()
            .unwrap(),
        ]
    }

    fn hinted_wire(invitation: &Invitation) -> SignedHintedInvitation {
        let bytes = URL_SAFE_NO_PAD
            .decode(invitation.encode().unwrap())
            .unwrap();
        postcard::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn hinted_invitation_round_trips_as_version_3() {
        let owner = GroupIdentity::generate();
        let inviter_device_id = DeviceIdentity::generate().peer_id();
        let hints = hints();
        let invitation = Invitation::issue_with_address_hints(
            &owner,
            inviter_device_id,
            spec(NOW + 3_600),
            &hints,
            NOW,
        )
        .unwrap();
        let decoded = Invitation::decode_input(&invitation.custom_uri().unwrap(), NOW).unwrap();

        assert_eq!(hinted_wire(&invitation).claims.version, 3);
        assert_eq!(decoded.address_hints(), hints.as_slice());
        assert_eq!(decoded.inviter_device_id(), inviter_device_id);
        assert_eq!(decoded.group_id(), owner.group_id());
        assert_eq!(decoded.discovery_secret(), invitation.discovery_secret());
    }

    #[test]
    fn invitation_without_hints_keeps_the_version_2_encoding() {
        let owner = GroupIdentity::generate();
        let invitation = Invitation::issue_with_address_hints(
            &owner,
            DeviceIdentity::generate().peer_id(),
            spec(NOW + 3_600),
            &[],
            NOW,
        )
        .unwrap();
        let bytes = URL_SAFE_NO_PAD
            .decode(invitation.encode().unwrap())
            .unwrap();
        let wire: SignedInvitation = postcard::from_bytes(&bytes).unwrap();

        assert_eq!(wire.claims.version, 2);
        assert_eq!(postcard::to_allocvec(&wire).unwrap(), bytes);
        assert!(
            Invitation::decode(&invitation.encode().unwrap(), NOW)
                .unwrap()
                .address_hints()
                .is_empty()
        );
    }

    #[test]
    fn changing_an_address_hint_invalidates_the_root_signature() {
        let owner = GroupIdentity::generate();
        let invitation = Invitation::issue_with_address_hints(
            &owner,
            DeviceIdentity::generate().peer_id(),
            spec(NOW + 3_600),
            &hints(),
            NOW,
        )
        .unwrap();
        let mut wire = hinted_wire(&invitation);
        wire.address_hints[0] = "/ip4/203.0.113.66/udp/4001/quic-v1"
            .parse::<Multiaddr>()
            .unwrap()
            .to_vec();
        let tampered = URL_SAFE_NO_PAD.encode(postcard::to_allocvec(&wire).unwrap());

        assert!(matches!(
            Invitation::decode(&tampered, NOW),
            Err(InvitationError::InvalidSignature)
        ));
    }

    #[test]
    fn hints_cannot_be_stripped_into_a_version_2_invitation() {
        let owner = GroupIdentity::generate();
        let invitation = Invitation::issue_with_address_hints(
            &owner,
            DeviceIdentity::generate().peer_id(),
            spec(NOW + 3_600),
            &hints(),
            NOW,
        )
        .unwrap();
        let hinted = hinted_wire(&invitation);
        let mut claims = hinted.claims;
        claims.version = 2;
        let stripped = URL_SAFE_NO_PAD.encode(
            postcard::to_allocvec(&SignedInvitation {
                claims,
                signature: hinted.signature,
            })
            .unwrap(),
        );

        assert!(matches!(
            Invitation::decode(&stripped, NOW),
            Err(InvitationError::InvalidSignature)
        ));
    }

    #[test]
    fn invalid_address_hints_are_rejected_on_issue_and_decode() {
        let owner = GroupIdentity::generate();
        let inviter_device_id = DeviceIdentity::generate().peer_id();
        let base: Multiaddr = "/ip4/192.0.2.10/udp/4001/quic-v1".parse().unwrap();
        let with_peer = base
            .clone()
            .with(multiaddr::Protocol::P2p(inviter_device_id));
        let too_many = (0..5)
            .map(|port| {
                format!("/ip4/192.0.2.10/udp/{}/quic-v1", 4001 + port)
                    .parse()
                    .unwrap()
            })
            .collect::<Vec<Multiaddr>>();

        for invalid in [vec![with_peer], vec![base.clone(), base.clone()], too_many] {
            assert!(matches!(
                Invitation::issue_with_address_hints(
                    &owner,
                    inviter_device_id,
                    spec(NOW + 3_600),
                    &invalid,
                    NOW
                ),
                Err(InvitationError::InvalidAddressHint)
            ));
        }

        let invitation = Invitation::issue_with_address_hints(
            &owner,
            inviter_device_id,
            spec(NOW + 3_600),
            &[base],
            NOW,
        )
        .unwrap();
        for invalid in [Vec::new(), vec![vec![0xff, 0xff]]] {
            let mut wire = hinted_wire(&invitation);
            wire.address_hints = invalid;
            wire.signature = owner
                .sign(&signing_payload(&wire.claims, &wire.address_hints).unwrap())
                .unwrap();
            let malformed = URL_SAFE_NO_PAD.encode(postcard::to_allocvec(&wire).unwrap());

            assert!(matches!(
                Invitation::decode(&malformed, NOW),
                Err(InvitationError::InvalidAddressHint)
            ));
        }
    }
}
