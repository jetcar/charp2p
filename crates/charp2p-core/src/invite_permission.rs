use libp2p_identity::PeerId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const INVITE_PERMISSION_VERSION: u16 = 1;
const MAX_INVITE_PERMISSION_BYTES: usize = 128;

/// Owner-authored grant or withdrawal of one member device's permission to
/// request invitations, carried inside the end-to-end protected payload of an
/// `InvitePermissionChanged` event (ADR-036).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvitePermission {
    device_id: PeerId,
    granted: bool,
}

impl InvitePermission {
    /// Creates a permission change for the target device.
    pub fn new(device_id: PeerId, granted: bool) -> Self {
        Self { device_id, granted }
    }

    /// Returns the target member device.
    pub fn device_id(&self) -> PeerId {
        self.device_id
    }

    /// Returns whether the permission is granted rather than withdrawn.
    pub fn granted(&self) -> bool {
        self.granted
    }

    /// Encodes the change as versioned plaintext for MLS protection.
    pub fn encode(&self) -> Result<Vec<u8>, InvitePermissionError> {
        Ok(postcard::to_allocvec(&InvitePermissionWire {
            version: INVITE_PERMISSION_VERSION,
            device_id: self.device_id.to_bytes(),
            granted: self.granted,
        })?)
    }

    /// Decodes and validates decrypted permission plaintext.
    pub fn decode(encoded: &[u8]) -> Result<Self, InvitePermissionError> {
        if encoded.is_empty() || encoded.len() > MAX_INVITE_PERMISSION_BYTES {
            return Err(InvitePermissionError::InvalidSize);
        }
        let (wire, remaining): (InvitePermissionWire, _) = postcard::take_from_bytes(encoded)?;
        if !remaining.is_empty() {
            return Err(InvitePermissionError::InvalidSize);
        }
        if wire.version != INVITE_PERMISSION_VERSION {
            return Err(InvitePermissionError::UnsupportedVersion(wire.version));
        }
        let device_id = PeerId::from_bytes(&wire.device_id)
            .map_err(|_| InvitePermissionError::InvalidDeviceId)?;
        if device_id.to_bytes() != wire.device_id {
            return Err(InvitePermissionError::InvalidDeviceId);
        }
        Ok(Self::new(device_id, wire.granted))
    }
}

/// Errors returned for invalid invite permission changes.
#[derive(Debug, Error)]
pub enum InvitePermissionError {
    /// The payload is empty, too large, or has trailing bytes.
    #[error("invite permission has an invalid size")]
    InvalidSize,
    /// Binary serialization or deserialization failed.
    #[error("invite permission binary payload is malformed")]
    Serialization(#[from] postcard::Error),
    /// The permission version is unsupported.
    #[error("unsupported invite permission version {0}")]
    UnsupportedVersion(u16),
    /// The target device identifier is invalid.
    #[error("invite permission device identifier is invalid")]
    InvalidDeviceId,
}

#[derive(Deserialize, Serialize)]
struct InvitePermissionWire {
    version: u16,
    device_id: Vec<u8>,
    granted: bool,
}

#[cfg(test)]
mod tests {
    use super::{InvitePermission, InvitePermissionError, InvitePermissionWire};
    use libp2p_identity::{Keypair, PeerId};

    fn device() -> PeerId {
        Keypair::generate_ed25519().public().to_peer_id()
    }

    #[test]
    fn permission_round_trips() {
        let device_id = device();
        for granted in [true, false] {
            let permission = InvitePermission::new(device_id, granted);
            let decoded = InvitePermission::decode(&permission.encode().expect("encode"))
                .expect("decode permission");
            assert_eq!(decoded, permission);
            assert_eq!(decoded.device_id(), device_id);
            assert_eq!(decoded.granted(), granted);
        }
    }

    #[test]
    fn malformed_payloads_are_rejected() {
        let mut encoded = InvitePermission::new(device(), true)
            .encode()
            .expect("encode");
        encoded.push(0);
        assert!(matches!(
            InvitePermission::decode(&encoded),
            Err(InvitePermissionError::InvalidSize)
        ));
        let future = postcard::to_allocvec(&InvitePermissionWire {
            version: 2,
            device_id: device().to_bytes(),
            granted: true,
        })
        .expect("encode");
        assert!(matches!(
            InvitePermission::decode(&future),
            Err(InvitePermissionError::UnsupportedVersion(2))
        ));
        let invalid = postcard::to_allocvec(&InvitePermissionWire {
            version: 1,
            device_id: vec![1, 2, 3],
            granted: true,
        })
        .expect("encode");
        assert!(matches!(
            InvitePermission::decode(&invalid),
            Err(InvitePermissionError::InvalidDeviceId)
        ));
        let mut non_canonical_flag = InvitePermission::new(device(), true)
            .encode()
            .expect("encode");
        *non_canonical_flag.last_mut().expect("flag byte") = 2;
        assert!(InvitePermission::decode(&non_canonical_flag).is_err());
        assert!(InvitePermission::decode(&[]).is_err());
    }
}
