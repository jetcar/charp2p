use serde::{Deserialize, Serialize};
use thiserror::Error;

const MESSAGE_EDIT_VERSION: u16 = 1;
/// Largest replacement text accepted in a message edit.
pub const MAX_MESSAGE_EDIT_TEXT_BYTES: usize = 16 * 1024;
const MAX_MESSAGE_EDIT_BYTES: usize = MAX_MESSAGE_EDIT_TEXT_BYTES + 64;

/// Replacement text for an earlier message by the same author, carried inside
/// the end-to-end protected payload of a `MessageEdited` event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageEdit {
    target_event_id: [u8; 32],
    text: String,
}

impl MessageEdit {
    /// Creates an edit after validating the replacement text.
    pub fn new(target_event_id: [u8; 32], text: &str) -> Result<Self, MessageEditError> {
        if text.trim().is_empty() || text.len() > MAX_MESSAGE_EDIT_TEXT_BYTES {
            return Err(MessageEditError::InvalidText);
        }
        Ok(Self {
            target_event_id,
            text: text.to_owned(),
        })
    }

    /// Returns the identifier of the edited `MessageCreated` event.
    pub fn target_event_id(&self) -> &[u8; 32] {
        &self.target_event_id
    }

    /// Returns the replacement text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Encodes the edit as versioned plaintext for MLS protection.
    pub fn encode(&self) -> Result<Vec<u8>, MessageEditError> {
        Ok(postcard::to_allocvec(&MessageEditWire {
            version: MESSAGE_EDIT_VERSION,
            target_event_id: self.target_event_id,
            text: self.text.clone(),
        })?)
    }

    /// Decodes and validates decrypted edit plaintext.
    pub fn decode(encoded: &[u8]) -> Result<Self, MessageEditError> {
        if encoded.is_empty() || encoded.len() > MAX_MESSAGE_EDIT_BYTES {
            return Err(MessageEditError::InvalidSize);
        }
        let (wire, remaining): (MessageEditWire, _) = postcard::take_from_bytes(encoded)?;
        if !remaining.is_empty() {
            return Err(MessageEditError::InvalidSize);
        }
        if wire.version != MESSAGE_EDIT_VERSION {
            return Err(MessageEditError::UnsupportedVersion(wire.version));
        }
        Self::new(wire.target_event_id, &wire.text)
    }
}

/// Errors returned for invalid message edits.
#[derive(Debug, Error)]
pub enum MessageEditError {
    /// The payload is empty, too large, or has trailing bytes.
    #[error("message edit has an invalid size")]
    InvalidSize,
    /// Binary serialization or deserialization failed.
    #[error("message edit binary payload is malformed")]
    Serialization(#[from] postcard::Error),
    /// The edit version is unsupported.
    #[error("unsupported message edit version {0}")]
    UnsupportedVersion(u16),
    /// The replacement text is blank or too long.
    #[error("message edit text is invalid")]
    InvalidText,
}

#[derive(Deserialize, Serialize)]
struct MessageEditWire {
    version: u16,
    target_event_id: [u8; 32],
    text: String,
}

#[cfg(test)]
mod tests {
    use super::{MAX_MESSAGE_EDIT_TEXT_BYTES, MessageEdit, MessageEditError, MessageEditWire};

    #[test]
    fn edit_round_trips() {
        let edit = MessageEdit::new([7; 32], "corrected").expect("valid edit");
        let decoded = MessageEdit::decode(&edit.encode().expect("encode")).expect("decode edit");
        assert_eq!(decoded, edit);
        assert_eq!(decoded.target_event_id(), &[7; 32]);
        assert_eq!(decoded.text(), "corrected");
        let longest = "x".repeat(MAX_MESSAGE_EDIT_TEXT_BYTES);
        let edit = MessageEdit::new([1; 32], &longest).expect("longest edit");
        assert_eq!(
            MessageEdit::decode(&edit.encode().expect("encode")).expect("decode"),
            edit
        );
    }

    #[test]
    fn invalid_text_is_rejected() {
        for text in ["", "  \n", &"x".repeat(MAX_MESSAGE_EDIT_TEXT_BYTES + 1)] {
            assert!(matches!(
                MessageEdit::new([0; 32], text),
                Err(MessageEditError::InvalidText)
            ));
        }
    }

    #[test]
    fn malformed_payloads_are_rejected() {
        let mut encoded = MessageEdit::new([2; 32], "text")
            .expect("valid edit")
            .encode()
            .expect("encode");
        encoded.push(0);
        assert!(matches!(
            MessageEdit::decode(&encoded),
            Err(MessageEditError::InvalidSize)
        ));
        let future = postcard::to_allocvec(&MessageEditWire {
            version: 2,
            target_event_id: [2; 32],
            text: "text".to_owned(),
        })
        .expect("encode");
        assert!(matches!(
            MessageEdit::decode(&future),
            Err(MessageEditError::UnsupportedVersion(2))
        ));
        let blank = postcard::to_allocvec(&MessageEditWire {
            version: 1,
            target_event_id: [2; 32],
            text: " ".to_owned(),
        })
        .expect("encode");
        assert!(matches!(
            MessageEdit::decode(&blank),
            Err(MessageEditError::InvalidText)
        ));
        assert!(MessageEdit::decode(&[]).is_err());
    }
}
