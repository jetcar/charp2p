use serde::{Deserialize, Serialize};
use thiserror::Error;

const MESSAGE_DELETION_VERSION: u16 = 1;
const MAX_MESSAGE_DELETION_BYTES: usize = 64;

/// Group-wide tombstone request for an earlier message by the same author,
/// carried inside the end-to-end protected payload of a `MessageDeleted`
/// event. Conforming clients hide the target; erasure from devices that
/// already received it cannot be guaranteed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageDeletion {
    target_event_id: [u8; 32],
}

impl MessageDeletion {
    /// Creates a deletion request for one `MessageCreated` event.
    pub fn new(target_event_id: [u8; 32]) -> Self {
        Self { target_event_id }
    }

    /// Returns the identifier of the deleted `MessageCreated` event.
    pub fn target_event_id(&self) -> &[u8; 32] {
        &self.target_event_id
    }

    /// Encodes the deletion as versioned plaintext for MLS protection.
    pub fn encode(&self) -> Result<Vec<u8>, MessageDeletionError> {
        Ok(postcard::to_allocvec(&MessageDeletionWire {
            version: MESSAGE_DELETION_VERSION,
            target_event_id: self.target_event_id,
        })?)
    }

    /// Decodes and validates decrypted deletion plaintext.
    pub fn decode(encoded: &[u8]) -> Result<Self, MessageDeletionError> {
        if encoded.is_empty() || encoded.len() > MAX_MESSAGE_DELETION_BYTES {
            return Err(MessageDeletionError::InvalidSize);
        }
        let (wire, remaining): (MessageDeletionWire, _) = postcard::take_from_bytes(encoded)?;
        if !remaining.is_empty() {
            return Err(MessageDeletionError::InvalidSize);
        }
        if wire.version != MESSAGE_DELETION_VERSION {
            return Err(MessageDeletionError::UnsupportedVersion(wire.version));
        }
        Ok(Self::new(wire.target_event_id))
    }
}

/// Errors returned for invalid message deletions.
#[derive(Debug, Error)]
pub enum MessageDeletionError {
    /// The payload is empty, too large, or has trailing bytes.
    #[error("message deletion has an invalid size")]
    InvalidSize,
    /// Binary serialization or deserialization failed.
    #[error("message deletion binary payload is malformed")]
    Serialization(#[from] postcard::Error),
    /// The deletion version is unsupported.
    #[error("unsupported message deletion version {0}")]
    UnsupportedVersion(u16),
}

#[derive(Deserialize, Serialize)]
struct MessageDeletionWire {
    version: u16,
    target_event_id: [u8; 32],
}

#[cfg(test)]
mod tests {
    use super::{MessageDeletion, MessageDeletionError, MessageDeletionWire};

    #[test]
    fn deletion_round_trips() {
        let deletion = MessageDeletion::new([7; 32]);
        let decoded =
            MessageDeletion::decode(&deletion.encode().expect("encode")).expect("decode deletion");
        assert_eq!(decoded, deletion);
        assert_eq!(decoded.target_event_id(), &[7; 32]);
    }

    #[test]
    fn malformed_payloads_are_rejected() {
        let mut encoded = MessageDeletion::new([2; 32]).encode().expect("encode");
        encoded.push(0);
        assert!(matches!(
            MessageDeletion::decode(&encoded),
            Err(MessageDeletionError::InvalidSize)
        ));
        let future = postcard::to_allocvec(&MessageDeletionWire {
            version: 2,
            target_event_id: [2; 32],
        })
        .expect("encode");
        assert!(matches!(
            MessageDeletion::decode(&future),
            Err(MessageDeletionError::UnsupportedVersion(2))
        ));
        assert!(MessageDeletion::decode(&[]).is_err());
        assert!(MessageDeletion::decode(&[1, 0, 3]).is_err());
    }
}
