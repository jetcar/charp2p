use std::fmt;

use libp2p_identity::PeerId;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::{Invitation, MAX_INVITATION_ENCODED_BYTES, join::is_canonical_invitation_text};

const INVITE_WIRE_VERSION: u16 = 1;
const MAX_GROUP_ID_BYTES: usize = 128;
const ISSUED_RESPONSE_TAG: u8 = 1;
const REJECTED_RESPONSE_TAG: u8 = 2;

/// Longest invitation lifetime a permitted member may request; the owner
/// still caps it by the group's own maximum.
pub const MAX_INVITE_REQUEST_LIFETIME_SECONDS: u32 = 30 * 24 * 60 * 60;
/// Largest encoded invite request accepted before any variable-size allocation.
pub const MAX_INVITE_REQUEST_WIRE_BYTES: usize = 2 + 2 + MAX_GROUP_ID_BYTES + 4;
/// Largest encoded invite response accepted before any variable-size allocation.
pub const MAX_INVITE_RESPONSE_WIRE_BYTES: usize = 2 + 1 + 2 + MAX_INVITATION_ENCODED_BYTES;

/// A permitted member's bounded request for an owner-issued invitation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InviteRequest {
    group_id: PeerId,
    lifetime_seconds: u32,
}

impl InviteRequest {
    /// Creates a request for one group with a bounded, non-zero lifetime.
    pub fn new(group_id: PeerId, lifetime_seconds: u32) -> Result<Self, InviteRequestError> {
        if lifetime_seconds == 0 || lifetime_seconds > MAX_INVITE_REQUEST_LIFETIME_SECONDS {
            return Err(InviteRequestError::InvalidLifetime);
        }
        if group_id.to_bytes().len() > MAX_GROUP_ID_BYTES {
            return Err(InviteRequestError::InvalidGroupId);
        }
        Ok(Self {
            group_id,
            lifetime_seconds,
        })
    }

    /// Encodes the versioned request.
    pub fn encode(&self) -> Vec<u8> {
        let group_id = self.group_id.to_bytes();
        let mut encoded = Vec::with_capacity(2 + 2 + group_id.len() + 4);
        encoded.extend_from_slice(&INVITE_WIRE_VERSION.to_be_bytes());
        // `new` and `decode` bound the group identifier to `MAX_GROUP_ID_BYTES`.
        encoded.extend_from_slice(&(group_id.len() as u16).to_be_bytes());
        encoded.extend_from_slice(&group_id);
        encoded.extend_from_slice(&self.lifetime_seconds.to_be_bytes());
        encoded
    }

    /// Bounds and decodes one request.
    pub fn decode(encoded: &[u8]) -> Result<Self, InviteRequestError> {
        if encoded.is_empty() || encoded.len() > MAX_INVITE_REQUEST_WIRE_BYTES {
            return Err(InviteRequestError::InvalidWireSize);
        }
        let mut decoder = Decoder::new(encoded);
        decoder.version()?;
        let group_len = decoder.u16()? as usize;
        if group_len == 0 || group_len > MAX_GROUP_ID_BYTES {
            return Err(InviteRequestError::InvalidGroupId);
        }
        let group_id = PeerId::from_bytes(decoder.bytes(group_len)?)
            .map_err(|_| InviteRequestError::InvalidGroupId)?;
        let lifetime_seconds = decoder.u32()?;
        decoder.finish()?;
        Self::new(group_id, lifetime_seconds)
    }

    /// Group the member asks to invite into.
    pub fn group_id(&self) -> PeerId {
        self.group_id
    }

    /// Requested invitation lifetime before the owner applies its own maximum.
    pub fn lifetime_seconds(&self) -> u32 {
        self.lifetime_seconds
    }
}

/// Bounded owner response to an invite request.
pub struct InviteResponse {
    content: InviteResponseContent,
}

enum InviteResponseContent {
    Issued { invitation: Zeroizing<String> },
    Rejected { reason: InviteRejectReason },
}

impl InviteResponse {
    /// Creates a response carrying one owner-issued bearer invitation.
    pub fn issued(invitation: &Invitation) -> Result<Self, InviteRequestError> {
        let encoded = Zeroizing::new(invitation.encode()?);
        Self::from_encoded_invitation(encoded)
    }

    /// Creates a rejection that does not reveal which check failed.
    pub fn rejected(reason: InviteRejectReason) -> Self {
        Self {
            content: InviteResponseContent::Rejected { reason },
        }
    }

    /// Encodes the versioned response into a zeroizing wire buffer.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut encoded = Zeroizing::new(Vec::new());
        encoded.extend_from_slice(&INVITE_WIRE_VERSION.to_be_bytes());
        match &self.content {
            InviteResponseContent::Issued { invitation } => {
                encoded.push(ISSUED_RESPONSE_TAG);
                // Construction bounds the invitation to `MAX_INVITATION_ENCODED_BYTES`.
                encoded.extend_from_slice(&(invitation.len() as u16).to_be_bytes());
                encoded.extend_from_slice(invitation.as_bytes());
            }
            InviteResponseContent::Rejected { reason } => {
                encoded.push(REJECTED_RESPONSE_TAG);
                encoded.push(reason.code());
            }
        }
        encoded
    }

    /// Bounds and decodes one response before allocating its invitation.
    pub fn decode(encoded: &[u8]) -> Result<Self, InviteRequestError> {
        if encoded.is_empty() || encoded.len() > MAX_INVITE_RESPONSE_WIRE_BYTES {
            return Err(InviteRequestError::InvalidWireSize);
        }
        let mut decoder = Decoder::new(encoded);
        decoder.version()?;
        let response = match decoder.u8()? {
            ISSUED_RESPONSE_TAG => {
                let length = decoder.u16()? as usize;
                if length == 0 || length > MAX_INVITATION_ENCODED_BYTES {
                    return Err(InviteRequestError::InvalidInvitation);
                }
                let invitation = Zeroizing::new(
                    std::str::from_utf8(decoder.bytes(length)?)
                        .map_err(|_| InviteRequestError::InvalidInvitation)?
                        .to_owned(),
                );
                Self::from_encoded_invitation(invitation)?
            }
            REJECTED_RESPONSE_TAG => Self::rejected(InviteRejectReason::from_code(decoder.u8()?)?),
            _ => return Err(InviteRequestError::Malformed),
        };
        decoder.finish()?;
        Ok(response)
    }

    /// Canonical encoded bearer invitation, if one was issued. It is not yet
    /// verified; decode it with the invitation parser before use and never
    /// include it in logs.
    pub fn invitation(&self) -> Option<&str> {
        match &self.content {
            InviteResponseContent::Issued { invitation } => Some(invitation.as_str()),
            InviteResponseContent::Rejected { .. } => None,
        }
    }

    /// Returns the stable rejection reason, if no invitation was issued.
    pub fn rejection(&self) -> Option<InviteRejectReason> {
        match self.content {
            InviteResponseContent::Issued { .. } => None,
            InviteResponseContent::Rejected { reason } => Some(reason),
        }
    }

    fn from_encoded_invitation(invitation: Zeroizing<String>) -> Result<Self, InviteRequestError> {
        if !is_canonical_invitation_text(invitation.as_str()) {
            return Err(InviteRequestError::InvalidInvitation);
        }
        Ok(Self {
            content: InviteResponseContent::Issued { invitation },
        })
    }
}

impl fmt::Debug for InviteResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.content {
            InviteResponseContent::Issued { invitation } => formatter
                .debug_struct("Issued")
                .field("invitation", &"[REDACTED]")
                .field("invitation_bytes", &invitation.len())
                .finish(),
            InviteResponseContent::Rejected { reason } => formatter
                .debug_struct("Rejected")
                .field("reason", reason)
                .finish(),
        }
    }
}

/// Invite request rejection categories. ADR-036 keeps them to two so a
/// rejection does not reveal which check failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InviteRejectReason {
    /// The requester may not invite into this group.
    Unauthorized,
    /// The owner cannot issue an invitation at this time.
    Busy,
}

impl InviteRejectReason {
    const fn code(self) -> u8 {
        match self {
            Self::Unauthorized => 1,
            Self::Busy => 2,
        }
    }

    fn from_code(code: u8) -> Result<Self, InviteRequestError> {
        match code {
            1 => Ok(Self::Unauthorized),
            2 => Ok(Self::Busy),
            _ => Err(InviteRequestError::Malformed),
        }
    }
}

/// Invalid or unsafe invite request payload.
#[derive(Debug, Error)]
pub enum InviteRequestError {
    /// The outer encoded request or response violates its pre-decode bound.
    #[error("invite message has an invalid encoded size")]
    InvalidWireSize,
    /// The claimed group identifier is absent, oversized, or malformed.
    #[error("invite group identifier is invalid")]
    InvalidGroupId,
    /// The requested lifetime is zero or above the protocol maximum.
    #[error("invite request lifetime is outside the supported range")]
    InvalidLifetime,
    /// The invitation is absent or is not canonical unpadded Base64url text.
    #[error("issued invitation is not canonical")]
    InvalidInvitation,
    /// The versioned binary framing is malformed or has trailing bytes.
    #[error("invite message encoding is malformed")]
    Malformed,
    /// The binary framing version is unsupported.
    #[error("unsupported invite message version {0}")]
    UnsupportedVersion(u16),
    /// An issued invitation could not be canonically encoded.
    #[error("issued invitation could not be encoded")]
    Invitation(#[from] crate::InvitationError),
}

struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    fn new(encoded: &'a [u8]) -> Self {
        Self { remaining: encoded }
    }

    fn version(&mut self) -> Result<(), InviteRequestError> {
        let version = self.u16()?;
        if version != INVITE_WIRE_VERSION {
            return Err(InviteRequestError::UnsupportedVersion(version));
        }
        Ok(())
    }

    fn u8(&mut self) -> Result<u8, InviteRequestError> {
        Ok(self.bytes(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, InviteRequestError> {
        let bytes: [u8; 2] = self
            .bytes(2)?
            .try_into()
            .map_err(|_| InviteRequestError::Malformed)?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn u32(&mut self) -> Result<u32, InviteRequestError> {
        let bytes: [u8; 4] = self
            .bytes(4)?
            .try_into()
            .map_err(|_| InviteRequestError::Malformed)?;
        Ok(u32::from_be_bytes(bytes))
    }

    fn bytes(&mut self, length: usize) -> Result<&'a [u8], InviteRequestError> {
        if self.remaining.len() < length {
            return Err(InviteRequestError::Malformed);
        }
        let (value, remaining) = self.remaining.split_at(length);
        self.remaining = remaining;
        Ok(value)
    }

    fn finish(self) -> Result<(), InviteRequestError> {
        if self.remaining.is_empty() {
            Ok(())
        } else {
            Err(InviteRequestError::Malformed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        InviteRejectReason, InviteRequest, InviteRequestError, InviteResponse,
        MAX_INVITE_REQUEST_LIFETIME_SECONDS, MAX_INVITE_REQUEST_WIRE_BYTES,
        MAX_INVITE_RESPONSE_WIRE_BYTES,
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
    fn invite_request_round_trips_and_bounds_its_lifetime() {
        let group_id = GroupIdentity::generate().group_id();
        let request = InviteRequest::new(group_id, 86_400).unwrap();
        let encoded = request.encode();
        assert!(encoded.len() <= MAX_INVITE_REQUEST_WIRE_BYTES);
        assert_eq!(InviteRequest::decode(&encoded).unwrap(), request);

        assert!(matches!(
            InviteRequest::new(group_id, 0),
            Err(InviteRequestError::InvalidLifetime)
        ));
        assert!(matches!(
            InviteRequest::new(group_id, MAX_INVITE_REQUEST_LIFETIME_SECONDS + 1),
            Err(InviteRequestError::InvalidLifetime)
        ));
        let mut oversized = encoded.clone();
        let lifetime_offset = oversized.len() - 4;
        oversized[lifetime_offset..]
            .copy_from_slice(&(MAX_INVITE_REQUEST_LIFETIME_SECONDS + 1).to_be_bytes());
        assert!(matches!(
            InviteRequest::decode(&oversized),
            Err(InviteRequestError::InvalidLifetime)
        ));
    }

    #[test]
    fn invite_request_rejects_versions_trailing_bytes_and_group_bounds() {
        let request = InviteRequest::new(GroupIdentity::generate().group_id(), 60).unwrap();
        let mut encoded = request.encode();
        encoded[0..2].copy_from_slice(&2_u16.to_be_bytes());
        assert!(matches!(
            InviteRequest::decode(&encoded),
            Err(InviteRequestError::UnsupportedVersion(2))
        ));

        let mut encoded = request.encode();
        encoded.push(0);
        assert!(matches!(
            InviteRequest::decode(&encoded),
            Err(InviteRequestError::Malformed)
        ));

        let mut encoded = request.encode();
        encoded[2..4].copy_from_slice(&0_u16.to_be_bytes());
        assert!(matches!(
            InviteRequest::decode(&encoded),
            Err(InviteRequestError::InvalidGroupId)
        ));
        assert!(matches!(
            InviteRequest::decode(&[0; MAX_INVITE_REQUEST_WIRE_BYTES + 1]),
            Err(InviteRequestError::InvalidWireSize)
        ));
    }

    #[test]
    fn invite_response_round_trips_an_issued_invitation_or_rejection() {
        let invitation = invitation();
        let issued = InviteResponse::issued(&invitation).unwrap();
        let decoded = InviteResponse::decode(&issued.encode()).unwrap();
        assert_eq!(
            decoded.invitation(),
            Some(invitation.encode().unwrap().as_str())
        );
        assert_eq!(decoded.rejection(), None);

        for reason in [InviteRejectReason::Unauthorized, InviteRejectReason::Busy] {
            let decoded =
                InviteResponse::decode(&InviteResponse::rejected(reason).encode()).unwrap();
            assert_eq!(decoded.invitation(), None);
            assert_eq!(decoded.rejection(), Some(reason));
        }
        assert!(matches!(
            InviteResponse::decode(&[0, 1, 2, 3]),
            Err(InviteRequestError::Malformed)
        ));
    }

    #[test]
    fn invite_response_rejects_noncanonical_and_oversized_invitations() {
        let mut encoded = InviteResponse::issued(&invitation()).unwrap().encode();
        encoded[5] = b'=';
        assert!(matches!(
            InviteResponse::decode(&encoded),
            Err(InviteRequestError::InvalidInvitation)
        ));
        assert!(matches!(
            InviteResponse::decode(&[0, 1, 1, 0xff, 0xff]),
            Err(InviteRequestError::InvalidInvitation)
        ));
        assert!(matches!(
            InviteResponse::decode(&vec![0; MAX_INVITE_RESPONSE_WIRE_BYTES + 1]),
            Err(InviteRequestError::InvalidWireSize)
        ));
    }

    #[test]
    fn debug_output_redacts_the_issued_invitation() {
        let issued = InviteResponse::issued(&invitation()).unwrap();
        let debug = format!("{issued:?}");
        assert!(!debug.contains(issued.invitation().unwrap()));
        assert!(debug.contains("[REDACTED]"));
    }
}
