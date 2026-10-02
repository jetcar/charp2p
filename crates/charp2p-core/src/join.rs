use std::fmt;

use libp2p_identity::PeerId;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{Invitation, MAX_INVITATION_ENCODED_BYTES};

const JOIN_WIRE_VERSION: u16 = 1;
const MAX_GROUP_ID_BYTES: usize = 128;
const ACCEPTED_RESPONSE_TAG: u8 = 1;
const REJECTED_RESPONSE_TAG: u8 = 2;

/// Largest encoded MLS KeyPackage or Welcome accepted by the join protocol.
pub const MAX_JOIN_MLS_MESSAGE_BYTES: usize = 128 * 1024;
/// Largest encoded join request accepted before any variable-size allocation.
pub const MAX_JOIN_REQUEST_WIRE_BYTES: usize =
    2 + 2 + MAX_GROUP_ID_BYTES + 2 + MAX_INVITATION_ENCODED_BYTES + 4 + MAX_JOIN_MLS_MESSAGE_BYTES;
/// Largest encoded join response accepted before any variable-size allocation.
pub const MAX_JOIN_RESPONSE_WIRE_BYTES: usize = 2 + 1 + 4 + MAX_JOIN_MLS_MESSAGE_BYTES;

/// A bounded request to turn one invitation capability into group membership.
pub struct JoinRequest {
    group_id: PeerId,
    invitation: Zeroizing<String>,
    key_package: Zeroizing<Vec<u8>>,
}

impl JoinRequest {
    /// Creates a canonical request from an already verified invitation.
    pub fn from_invitation(
        invitation: &Invitation,
        key_package: Vec<u8>,
    ) -> Result<Self, JoinError> {
        let key_package = Zeroizing::new(key_package);
        let encoded = Zeroizing::new(invitation.encode()?);
        Self::from_zeroizing_parts(invitation.group_id(), encoded, key_package)
    }

    /// Encodes the versioned join request without copying its secret fields.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, JoinError> {
        let group_id = self.group_id.to_bytes();
        let group_len = u16::try_from(group_id.len()).map_err(|_| JoinError::InvalidGroupId)?;
        let invitation_len =
            u16::try_from(self.invitation.len()).map_err(|_| JoinError::InvalidInvitation)?;
        let key_package_len =
            u32::try_from(self.key_package.len()).map_err(|_| JoinError::InvalidKeyPackageSize)?;
        let capacity =
            2 + 2 + group_id.len() + 2 + self.invitation.len() + 4 + self.key_package.len();
        if capacity > MAX_JOIN_REQUEST_WIRE_BYTES {
            return Err(JoinError::InvalidWireSize);
        }

        let mut encoded = Zeroizing::new(Vec::with_capacity(capacity));
        encoded.extend_from_slice(&JOIN_WIRE_VERSION.to_be_bytes());
        encoded.extend_from_slice(&group_len.to_be_bytes());
        encoded.extend_from_slice(&group_id);
        encoded.extend_from_slice(&invitation_len.to_be_bytes());
        encoded.extend_from_slice(self.invitation.as_bytes());
        encoded.extend_from_slice(&key_package_len.to_be_bytes());
        encoded.extend_from_slice(self.key_package.as_slice());
        Ok(encoded)
    }

    /// Bounds and decodes one request before allocating its variable fields.
    pub fn decode(encoded: &[u8]) -> Result<Self, JoinError> {
        if encoded.is_empty() || encoded.len() > MAX_JOIN_REQUEST_WIRE_BYTES {
            return Err(JoinError::InvalidWireSize);
        }
        let mut decoder = Decoder::new(encoded);
        decoder.version()?;
        let group_len = decoder.u16()? as usize;
        if group_len == 0 || group_len > MAX_GROUP_ID_BYTES {
            return Err(JoinError::InvalidGroupId);
        }
        let group_id =
            PeerId::from_bytes(decoder.bytes(group_len)?).map_err(|_| JoinError::InvalidGroupId)?;
        let invitation_len = decoder.u16()? as usize;
        if invitation_len == 0 || invitation_len > MAX_INVITATION_ENCODED_BYTES {
            return Err(JoinError::InvalidInvitation);
        }
        let invitation = Zeroizing::new(
            std::str::from_utf8(decoder.bytes(invitation_len)?)
                .map_err(|_| JoinError::InvalidInvitation)?
                .to_owned(),
        );
        let key_package_len =
            usize::try_from(decoder.u32()?).map_err(|_| JoinError::InvalidKeyPackageSize)?;
        if key_package_len == 0 || key_package_len > MAX_JOIN_MLS_MESSAGE_BYTES {
            return Err(JoinError::InvalidKeyPackageSize);
        }
        let key_package = Zeroizing::new(decoder.bytes(key_package_len)?.to_vec());
        decoder.finish()?;
        Self::from_zeroizing_parts(group_id, invitation, key_package)
    }

    /// Group selected before the invitation is cryptographically verified.
    pub fn group_id(&self) -> PeerId {
        self.group_id
    }

    /// Canonical encoded bearer invitation. Never include this value in logs.
    pub fn invitation(&self) -> &str {
        self.invitation.as_str()
    }

    /// Encoded MLS KeyPackage for the authenticated transport device.
    pub fn key_package(&self) -> &[u8] {
        self.key_package.as_slice()
    }

    fn from_zeroizing_parts(
        group_id: PeerId,
        invitation: Zeroizing<String>,
        key_package: Zeroizing<Vec<u8>>,
    ) -> Result<Self, JoinError> {
        if !is_canonical_invitation_text(invitation.as_str()) {
            return Err(JoinError::InvalidInvitation);
        }
        if key_package.is_empty() || key_package.len() > MAX_JOIN_MLS_MESSAGE_BYTES {
            return Err(JoinError::InvalidKeyPackageSize);
        }
        Ok(Self {
            group_id,
            invitation,
            key_package,
        })
    }
}

impl fmt::Debug for JoinRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JoinRequest")
            .field("group_id", &self.group_id)
            .field("invitation", &"[REDACTED]")
            .field("key_package_bytes", &self.key_package.len())
            .finish()
    }
}

/// Bounded owner response to a membership request.
pub struct JoinResponse {
    content: JoinResponseContent,
}

enum JoinResponseContent {
    Accepted { welcome: Zeroizing<Vec<u8>> },
    Rejected { reason: JoinRejectReason },
}

impl JoinResponse {
    /// Creates an accepted response containing one bounded MLS Welcome.
    pub fn accepted(welcome: Vec<u8>) -> Result<Self, JoinError> {
        let welcome = Zeroizing::new(welcome);
        if welcome.is_empty() || welcome.len() > MAX_JOIN_MLS_MESSAGE_BYTES {
            return Err(JoinError::InvalidWelcomeSize);
        }
        Ok(Self {
            content: JoinResponseContent::Accepted { welcome },
        })
    }

    /// Creates a rejection that discloses no group-state detail.
    pub fn rejected(reason: JoinRejectReason) -> Self {
        Self {
            content: JoinResponseContent::Rejected { reason },
        }
    }

    /// Encodes the versioned response into a zeroizing wire buffer.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, JoinError> {
        let mut encoded = Zeroizing::new(Vec::new());
        encoded.extend_from_slice(&JOIN_WIRE_VERSION.to_be_bytes());
        match &self.content {
            JoinResponseContent::Accepted { welcome } => {
                let length =
                    u32::try_from(welcome.len()).map_err(|_| JoinError::InvalidWelcomeSize)?;
                encoded.push(ACCEPTED_RESPONSE_TAG);
                encoded.extend_from_slice(&length.to_be_bytes());
                encoded.extend_from_slice(welcome.as_slice());
            }
            JoinResponseContent::Rejected { reason } => {
                encoded.push(REJECTED_RESPONSE_TAG);
                encoded.push(reason.code());
            }
        }
        if encoded.len() > MAX_JOIN_RESPONSE_WIRE_BYTES {
            return Err(JoinError::InvalidWireSize);
        }
        Ok(encoded)
    }

    /// Bounds and decodes one response before allocating its Welcome.
    pub fn decode(encoded: &[u8]) -> Result<Self, JoinError> {
        if encoded.is_empty() || encoded.len() > MAX_JOIN_RESPONSE_WIRE_BYTES {
            return Err(JoinError::InvalidWireSize);
        }
        let mut decoder = Decoder::new(encoded);
        decoder.version()?;
        let response = match decoder.u8()? {
            ACCEPTED_RESPONSE_TAG => {
                let welcome_len =
                    usize::try_from(decoder.u32()?).map_err(|_| JoinError::InvalidWelcomeSize)?;
                if welcome_len == 0 || welcome_len > MAX_JOIN_MLS_MESSAGE_BYTES {
                    return Err(JoinError::InvalidWelcomeSize);
                }
                Self::accepted(decoder.bytes(welcome_len)?.to_vec())?
            }
            REJECTED_RESPONSE_TAG => Self::rejected(JoinRejectReason::from_code(decoder.u8()?)?),
            _ => return Err(JoinError::Malformed),
        };
        decoder.finish()?;
        Ok(response)
    }

    /// Returns the accepted MLS Welcome, if membership was granted.
    pub fn welcome(&self) -> Option<&[u8]> {
        match &self.content {
            JoinResponseContent::Accepted { welcome } => Some(welcome.as_slice()),
            JoinResponseContent::Rejected { .. } => None,
        }
    }

    /// Returns the stable rejection reason, if membership was refused.
    pub fn rejection(&self) -> Option<JoinRejectReason> {
        match self.content {
            JoinResponseContent::Accepted { .. } => None,
            JoinResponseContent::Rejected { reason } => Some(reason),
        }
    }
}

impl fmt::Debug for JoinResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.content {
            JoinResponseContent::Accepted { welcome } => formatter
                .debug_struct("Accepted")
                .field("welcome_bytes", &welcome.len())
                .finish(),
            JoinResponseContent::Rejected { reason } => formatter
                .debug_struct("Rejected")
                .field("reason", reason)
                .finish(),
        }
    }
}

/// Stable join rejection categories with no group-state details.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JoinRejectReason {
    /// The request did not authorize membership.
    Unauthorized,
    /// The owner cannot process a join at this time.
    Busy,
    /// The supplied MLS profile is unsupported.
    UnsupportedProfile,
}

impl JoinRejectReason {
    const fn code(self) -> u8 {
        match self {
            Self::Unauthorized => 1,
            Self::Busy => 2,
            Self::UnsupportedProfile => 3,
        }
    }

    fn from_code(code: u8) -> Result<Self, JoinError> {
        match code {
            1 => Ok(Self::Unauthorized),
            2 => Ok(Self::Busy),
            3 => Ok(Self::UnsupportedProfile),
            _ => Err(JoinError::Malformed),
        }
    }
}

/// Invalid or unsafe join payload.
#[derive(Debug, Error)]
pub enum JoinError {
    /// The outer encoded request or response violates its pre-decode bound.
    #[error("join message has an invalid encoded size")]
    InvalidWireSize,
    /// The claimed group identifier is absent, oversized, or malformed.
    #[error("join group identifier is invalid")]
    InvalidGroupId,
    /// The invitation is absent or is not canonical unpadded Base64url text.
    #[error("join invitation is not canonical")]
    InvalidInvitation,
    /// The MLS KeyPackage is absent or exceeds the profile wire bound.
    #[error("join key package has an invalid encoded size")]
    InvalidKeyPackageSize,
    /// The MLS Welcome is absent or exceeds the profile wire bound.
    #[error("join welcome has an invalid encoded size")]
    InvalidWelcomeSize,
    /// The versioned binary framing is malformed or has trailing bytes.
    #[error("join message encoding is malformed")]
    Malformed,
    /// The binary framing version is unsupported.
    #[error("unsupported join message version {0}")]
    UnsupportedVersion(u16),
    /// A verified invitation could not be canonically encoded.
    #[error("join invitation could not be encoded")]
    Invitation(#[from] crate::InvitationError),
}

struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    fn new(encoded: &'a [u8]) -> Self {
        Self { remaining: encoded }
    }

    fn version(&mut self) -> Result<(), JoinError> {
        let version = self.u16()?;
        if version != JOIN_WIRE_VERSION {
            return Err(JoinError::UnsupportedVersion(version));
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8, JoinError> {
        Ok(*self.bytes(1)?.first().ok_or(JoinError::Malformed)?)
    }

    fn u16(&mut self) -> Result<u16, JoinError> {
        let bytes: [u8; 2] = self
            .bytes(2)?
            .try_into()
            .map_err(|_| JoinError::Malformed)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, JoinError> {
        let bytes: [u8; 4] = self
            .bytes(4)?
            .try_into()
            .map_err(|_| JoinError::Malformed)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], JoinError> {
        if self.remaining.len() < length {
            return Err(JoinError::Malformed);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn finish(self) -> Result<(), JoinError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(JoinError::Malformed)
        }
    }
}

fn is_canonical_invitation_text(invitation: &str) -> bool {
    if invitation.is_empty()
        || invitation.len() > MAX_INVITATION_ENCODED_BYTES
        || !invitation
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return false;
    }
    match invitation.len() % 4 {
        0 => true,
        1 => false,
        2 => base64url_value(invitation.as_bytes()[invitation.len() - 1]) & 0x0f == 0,
        3 => base64url_value(invitation.as_bytes()[invitation.len() - 1]) & 0x03 == 0,
        _ => unreachable!("modulo four is always within zero through three"),
    }
}

fn base64url_value(byte: u8) -> u8 {
    match byte {
        b'A'..=b'Z' => byte - b'A',
        b'a'..=b'z' => byte - b'a' + 26,
        b'0'..=b'9' => byte - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        _ => unreachable!("the caller validates the Base64url alphabet"),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        JoinError, JoinRejectReason, JoinRequest, JoinResponse, MAX_JOIN_MLS_MESSAGE_BYTES,
        MAX_JOIN_REQUEST_WIRE_BYTES,
    };
    use crate::{DeviceIdentity, GroupIdentity, HistoryPolicy, Invitation, InvitationSpec};

    const NOW: u64 = 1_800_000_000;

    fn invitation() -> Invitation {
        Invitation::issue(
            &GroupIdentity::generate(),
            DeviceIdentity::generate().peer_id(),
            InvitationSpec {
                group_name: "Design Crew",
                inviter_name: "Maya",
                expires_at_unix: NOW + 3_600,
                history_policy: HistoryPolicy::None,
                reusable: false,
            },
            NOW,
        )
        .unwrap()
    }

    #[test]
    fn join_request_round_trips_through_the_bounded_codec() {
        let invitation = invitation();
        let request = JoinRequest::from_invitation(&invitation, vec![1, 2, 3]).unwrap();
        let encoded = request.encode().unwrap();
        let decoded = JoinRequest::decode(&encoded).unwrap();

        assert_eq!(decoded.group_id(), invitation.group_id());
        assert_eq!(decoded.invitation(), invitation.encode().unwrap());
        assert_eq!(decoded.key_package(), &[1, 2, 3]);
        assert!(matches!(
            JoinRequest::decode(&vec![0; MAX_JOIN_REQUEST_WIRE_BYTES + 1]),
            Err(JoinError::InvalidWireSize)
        ));
    }

    #[test]
    fn decoder_rejects_declared_lengths_before_allocating_fields() {
        let invitation = invitation();
        let mut encoded = JoinRequest::from_invitation(&invitation, vec![1])
            .unwrap()
            .encode()
            .unwrap();
        let group_len = u16::from_be_bytes([encoded[2], encoded[3]]) as usize;
        let invitation_length_offset = 4 + group_len;
        encoded[invitation_length_offset..invitation_length_offset + 2]
            .copy_from_slice(&u16::MAX.to_be_bytes());

        assert!(matches!(
            JoinRequest::decode(&encoded),
            Err(JoinError::InvalidInvitation)
        ));
    }

    #[test]
    fn codec_rejects_unknown_versions_trailing_bytes_and_oversized_welcome_claims() {
        let invitation = invitation();
        let mut request = JoinRequest::from_invitation(&invitation, vec![1])
            .unwrap()
            .encode()
            .unwrap();
        request[0..2].copy_from_slice(&2_u16.to_be_bytes());
        assert!(matches!(
            JoinRequest::decode(&request),
            Err(JoinError::UnsupportedVersion(2))
        ));

        let mut request = JoinRequest::from_invitation(&invitation, vec![1])
            .unwrap()
            .encode()
            .unwrap();
        request.push(0);
        assert!(matches!(
            JoinRequest::decode(&request),
            Err(JoinError::Malformed)
        ));

        let oversized_welcome = [0, 1, super::ACCEPTED_RESPONSE_TAG, 0xff, 0xff, 0xff, 0xff];
        assert!(matches!(
            JoinResponse::decode(&oversized_welcome),
            Err(JoinError::InvalidWelcomeSize)
        ));
    }

    #[test]
    fn join_request_rejects_noncanonical_invitation_and_key_package_bounds() {
        let invitation = invitation();
        let mut encoded = JoinRequest::from_invitation(&invitation, vec![1])
            .unwrap()
            .encode()
            .unwrap();
        let group_len = u16::from_be_bytes([encoded[2], encoded[3]]) as usize;
        let invitation_offset = 4 + group_len + 2;
        encoded[invitation_offset] = b'=';
        assert!(matches!(
            JoinRequest::decode(&encoded),
            Err(JoinError::InvalidInvitation)
        ));
        assert!(!super::is_canonical_invitation_text("A"));
        assert!(!super::is_canonical_invitation_text("AB"));
        assert!(matches!(
            JoinRequest::from_invitation(&invitation, Vec::new()),
            Err(JoinError::InvalidKeyPackageSize)
        ));
        assert!(matches!(
            JoinRequest::from_invitation(&invitation, vec![0; MAX_JOIN_MLS_MESSAGE_BYTES + 1],),
            Err(JoinError::InvalidKeyPackageSize)
        ));
    }

    #[test]
    fn join_response_can_only_be_created_with_a_bounded_welcome() {
        let accepted = JoinResponse::accepted(vec![1, 2, 3]).unwrap();
        let decoded = JoinResponse::decode(&accepted.encode().unwrap()).unwrap();
        assert_eq!(decoded.welcome(), Some([1, 2, 3].as_slice()));
        assert_eq!(decoded.rejection(), None);
        assert!(matches!(
            JoinResponse::accepted(vec![0; MAX_JOIN_MLS_MESSAGE_BYTES + 1]),
            Err(JoinError::InvalidWelcomeSize)
        ));

        let rejected = JoinResponse::rejected(JoinRejectReason::Unauthorized);
        let decoded = JoinResponse::decode(&rejected.encode().unwrap()).unwrap();
        assert_eq!(decoded.welcome(), None);
        assert_eq!(decoded.rejection(), Some(JoinRejectReason::Unauthorized));
    }

    #[test]
    fn debug_output_redacts_join_secrets() {
        let request =
            JoinRequest::from_invitation(&invitation(), b"key-package-secret".to_vec()).unwrap();
        let accepted = JoinResponse::accepted(b"welcome-secret".to_vec()).unwrap();

        let request_debug = format!("{request:?}");
        let response_debug = format!("{accepted:?}");
        assert!(!request_debug.contains(request.invitation()));
        assert!(!request_debug.contains("key-package-secret"));
        assert!(!response_debug.contains("welcome-secret"));
    }
}
