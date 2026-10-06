use serde::{Deserialize, Serialize};
use thiserror::Error;

const MESSAGE_BODY_VERSION: u16 = 1;
/// Leading byte of a structured message body. It never begins valid UTF-8,
/// so bodies without it remain plain message text.
const STRUCTURED_BODY_MARKER: u8 = 0xff;
/// Largest message text accepted in a message body.
pub const MAX_MESSAGE_TEXT_BYTES: usize = 16 * 1024;
/// Largest encoded message body, including a reply reference.
pub const MAX_MESSAGE_BODY_BYTES: usize = MAX_MESSAGE_TEXT_BYTES + 64;

/// Message text and an optional reply reference, carried inside the
/// end-to-end protected payload of a `MessageCreated` event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageBody {
    reply_to: Option<[u8; 32]>,
    text: String,
}

impl MessageBody {
    /// Creates a body after validating the message text.
    pub fn new(text: &str, reply_to: Option<[u8; 32]>) -> Result<Self, MessageBodyError> {
        if text.trim().is_empty() || text.len() > MAX_MESSAGE_TEXT_BYTES {
            return Err(MessageBodyError::InvalidText);
        }
        Ok(Self {
            reply_to,
            text: text.to_owned(),
        })
    }

    /// Returns the identifier of the `MessageCreated` event this replies to.
    pub fn reply_to(&self) -> Option<&[u8; 32]> {
        self.reply_to.as_ref()
    }

    /// Returns the message text.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Encodes the body for MLS protection. A body without a reply is plain
    /// UTF-8 text; a reply is a marker byte followed by a versioned body.
    pub fn encode(&self) -> Result<Vec<u8>, MessageBodyError> {
        let Some(reply_to) = self.reply_to else {
            return Ok(self.text.as_bytes().to_vec());
        };
        let mut encoded = vec![STRUCTURED_BODY_MARKER];
        encoded.extend(postcard::to_allocvec(&MessageBodyWire {
            version: MESSAGE_BODY_VERSION,
            reply_to,
            text: self.text.clone(),
        })?);
        Ok(encoded)
    }

    /// Decodes and validates decrypted message plaintext.
    pub fn decode(encoded: &[u8]) -> Result<Self, MessageBodyError> {
        if encoded.is_empty() || encoded.len() > MAX_MESSAGE_BODY_BYTES {
            return Err(MessageBodyError::InvalidSize);
        }
        let Some(structured) = encoded.strip_prefix(&[STRUCTURED_BODY_MARKER]) else {
            let text = std::str::from_utf8(encoded).map_err(|_| MessageBodyError::InvalidText)?;
            return Self::new(text, None);
        };
        let (wire, remaining): (MessageBodyWire, _) = postcard::take_from_bytes(structured)?;
        if !remaining.is_empty() {
            return Err(MessageBodyError::InvalidSize);
        }
        if wire.version != MESSAGE_BODY_VERSION {
            return Err(MessageBodyError::UnsupportedVersion(wire.version));
        }
        Self::new(&wire.text, Some(wire.reply_to))
    }
}

/// Errors returned for invalid message bodies.
#[derive(Debug, Error)]
pub enum MessageBodyError {
    /// The payload is empty, too large, or has trailing bytes.
    #[error("message body has an invalid size")]
    InvalidSize,
    /// Binary serialization or deserialization failed.
    #[error("message body binary payload is malformed")]
    Serialization(#[from] postcard::Error),
    /// The body version is unsupported.
    #[error("unsupported message body version {0}")]
    UnsupportedVersion(u16),
    /// The text is not UTF-8, blank, or too long.
    #[error("message body text is invalid")]
    InvalidText,
}

#[derive(Deserialize, Serialize)]
struct MessageBodyWire {
    version: u16,
    reply_to: [u8; 32],
    text: String,
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_MESSAGE_BODY_BYTES, MAX_MESSAGE_TEXT_BYTES, MessageBody, MessageBodyError,
        MessageBodyWire,
    };

    #[test]
    fn plain_body_is_unchanged_message_text() {
        let body = MessageBody::new("hello", None).expect("valid body");
        let encoded = body.encode().expect("encode");
        assert_eq!(encoded, b"hello");
        let decoded = MessageBody::decode(&encoded).expect("decode");
        assert_eq!(decoded, body);
        assert_eq!(decoded.reply_to(), None);
    }

    #[test]
    fn reply_round_trips_within_the_size_limit() {
        let body = MessageBody::new("agreed", Some([4; 32])).expect("valid reply");
        let decoded = MessageBody::decode(&body.encode().expect("encode")).expect("decode");
        assert_eq!(decoded, body);
        assert_eq!(decoded.reply_to(), Some(&[4; 32]));
        assert_eq!(decoded.text(), "agreed");
        let longest = "x".repeat(MAX_MESSAGE_TEXT_BYTES);
        let body = MessageBody::new(&longest, Some([1; 32])).expect("longest reply");
        let encoded = body.encode().expect("encode");
        assert!(encoded.len() <= MAX_MESSAGE_BODY_BYTES);
        assert_eq!(MessageBody::decode(&encoded).expect("decode"), body);
    }

    #[test]
    fn invalid_text_is_rejected() {
        for text in ["", "  \n", &"x".repeat(MAX_MESSAGE_TEXT_BYTES + 1)] {
            assert!(matches!(
                MessageBody::new(text, None),
                Err(MessageBodyError::InvalidText)
            ));
        }
        assert!(matches!(
            MessageBody::decode(&[0xc3, 0x28]),
            Err(MessageBodyError::InvalidText)
        ));
    }

    #[test]
    fn malformed_replies_are_rejected() {
        let mut encoded = MessageBody::new("text", Some([2; 32]))
            .expect("valid reply")
            .encode()
            .expect("encode");
        encoded.push(0);
        assert!(matches!(
            MessageBody::decode(&encoded),
            Err(MessageBodyError::InvalidSize)
        ));
        let mut future = vec![0xff];
        future.extend(
            postcard::to_allocvec(&MessageBodyWire {
                version: 2,
                reply_to: [2; 32],
                text: "text".to_owned(),
            })
            .expect("encode"),
        );
        assert!(matches!(
            MessageBody::decode(&future),
            Err(MessageBodyError::UnsupportedVersion(2))
        ));
        assert!(MessageBody::decode(&[0xff]).is_err());
        assert!(MessageBody::decode(&[]).is_err());
    }
}
