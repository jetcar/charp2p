use std::collections::HashSet;

use libp2p_identity::{DecodingError, PeerId, PublicKey, SigningError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::DeviceIdentity;

const EVENT_VERSION: u16 = 1;
const EVENT_ID_DOMAIN: &[u8] = b"charp2p-event-id-v1\0";
const SIGNING_DOMAIN: &[u8] = b"charp2p-event-signature-v1\0";
const MAX_ENCODED_EVENT_BYTES: usize = 128 * 1024;
const MAX_PROTECTED_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_CAUSAL_PARENTS: usize = 16;

/// Stable event identifier derived from the canonical event body.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Deserialize, Serialize)]
pub struct EventId([u8; 32]);

impl EventId {
    /// Returns the identifier bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Protocol-level event type codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventKind {
    /// Creates the initial group state.
    GroupCreated,
    /// Changes authenticated display metadata.
    GroupMetadataChanged,
    /// Records an issued invitation.
    InvitationCreated,
    /// Revokes an invitation capability.
    InvitationRevoked,
    /// Adds a member identity.
    MemberAdded,
    /// Removes a member identity.
    MemberRemoved,
    /// Adds a device to a member.
    DeviceAdded,
    /// Revokes a member device.
    DeviceRevoked,
    /// Creates a message.
    MessageCreated,
    /// Replaces the visible form of a message.
    MessageEdited,
    /// Requests that clients hide a message.
    MessageDeleted,
    /// Advances group message-protection key material.
    KeyEpochAdvanced,
}

impl EventKind {
    const fn code(self) -> u16 {
        match self {
            Self::GroupCreated => 1,
            Self::GroupMetadataChanged => 2,
            Self::InvitationCreated => 3,
            Self::InvitationRevoked => 4,
            Self::MemberAdded => 5,
            Self::MemberRemoved => 6,
            Self::DeviceAdded => 7,
            Self::DeviceRevoked => 8,
            Self::MessageCreated => 9,
            Self::MessageEdited => 10,
            Self::MessageDeleted => 11,
            Self::KeyEpochAdvanced => 12,
        }
    }

    fn from_code(code: u16) -> Result<Self, EventError> {
        match code {
            1 => Ok(Self::GroupCreated),
            2 => Ok(Self::GroupMetadataChanged),
            3 => Ok(Self::InvitationCreated),
            4 => Ok(Self::InvitationRevoked),
            5 => Ok(Self::MemberAdded),
            6 => Ok(Self::MemberRemoved),
            7 => Ok(Self::DeviceAdded),
            8 => Ok(Self::DeviceRevoked),
            9 => Ok(Self::MessageCreated),
            10 => Ok(Self::MessageEdited),
            11 => Ok(Self::MessageDeleted),
            12 => Ok(Self::KeyEpochAdvanced),
            _ => Err(EventError::UnsupportedKind(code)),
        }
    }
}

/// Fields used by a device to create a signed group event.
pub struct EventSpec<'a> {
    /// Stable group identifier.
    pub group_id: PeerId,
    /// Strictly increasing sequence assigned by the author device.
    pub author_sequence: u64,
    /// Events that causally precede this event.
    pub causal_parents: &'a [EventId],
    /// Advisory sender timestamp in Unix milliseconds.
    pub created_at_unix_ms: u64,
    /// Type of protocol event.
    pub kind: EventKind,
    /// End-to-end protected event data.
    pub protected_payload: &'a [u8],
}

/// An authenticated group event safe to persist or send to another peer.
pub struct SignedEvent {
    body: EventBody,
    author_public_key: PublicKey,
    signature: Vec<u8>,
    id: EventId,
}

impl SignedEvent {
    /// Creates and signs an event with a device identity.
    pub fn create(author: &DeviceIdentity, spec: EventSpec<'_>) -> Result<Self, EventError> {
        let author_public_key = author.public_key();
        let body = EventBody {
            version: EVENT_VERSION,
            group_id: spec.group_id.to_bytes(),
            author_public_key: author_public_key.encode_protobuf(),
            author_sequence: spec.author_sequence,
            causal_parents: spec.causal_parents.to_vec(),
            created_at_unix_ms: spec.created_at_unix_ms,
            kind: spec.kind.code(),
            protected_payload: spec.protected_payload.to_vec(),
        };
        validate_body(&body)?;
        let body_bytes = postcard::to_allocvec(&body)?;
        let signature = author.sign(&signing_payload(&body_bytes))?;
        let id = event_id(&body_bytes);

        Ok(Self {
            body,
            author_public_key,
            signature,
            id,
        })
    }

    /// Encodes the event in its canonical binary wire form.
    pub fn encode(&self) -> Result<Vec<u8>, EventError> {
        Ok(postcard::to_allocvec(&SignedEventWire {
            body: self.body.clone(),
            signature: self.signature.clone(),
        })?)
    }

    /// Decodes, bounds-checks, and verifies an event received from storage or a
    /// peer.
    pub fn decode(encoded: &[u8]) -> Result<Self, EventError> {
        if encoded.is_empty() || encoded.len() > MAX_ENCODED_EVENT_BYTES {
            return Err(EventError::InvalidSize);
        }
        let wire: SignedEventWire = postcard::from_bytes(encoded)?;
        validate_body(&wire.body)?;
        let author_public_key = PublicKey::try_decode_protobuf(&wire.body.author_public_key)?;
        let body_bytes = postcard::to_allocvec(&wire.body)?;
        if !author_public_key.verify(&signing_payload(&body_bytes), &wire.signature) {
            return Err(EventError::InvalidSignature);
        }

        Ok(Self {
            id: event_id(&body_bytes),
            body: wire.body,
            author_public_key,
            signature: wire.signature,
        })
    }

    /// Returns the deterministic event identifier.
    pub fn id(&self) -> EventId {
        self.id
    }

    /// Returns the group this event belongs to.
    pub fn group_id(&self) -> PeerId {
        PeerId::from_bytes(&self.body.group_id).expect("validated during construction")
    }

    /// Returns the author device peer identifier.
    pub fn author_id(&self) -> PeerId {
        self.author_public_key.to_peer_id()
    }

    /// Returns the author-assigned sequence.
    pub fn author_sequence(&self) -> u64 {
        self.body.author_sequence
    }

    /// Returns the causal parent identifiers.
    pub fn causal_parents(&self) -> &[EventId] {
        &self.body.causal_parents
    }

    /// Returns the advisory sender timestamp.
    pub fn created_at_unix_ms(&self) -> u64 {
        self.body.created_at_unix_ms
    }

    /// Returns the protocol event kind.
    pub fn kind(&self) -> EventKind {
        EventKind::from_code(self.body.kind).expect("validated during construction")
    }

    /// Returns the opaque end-to-end protected event data.
    pub fn protected_payload(&self) -> &[u8] {
        &self.body.protected_payload
    }
}

/// Failures produced while creating or validating signed group events.
#[derive(Debug, Error)]
pub enum EventError {
    /// The wire event is empty or exceeds its protocol limit.
    #[error("event has an invalid encoded size")]
    InvalidSize,
    /// The protected payload exceeds the message-event limit.
    #[error("protected event payload is too large")]
    PayloadTooLarge,
    /// No author event may use sequence zero.
    #[error("author sequence must be greater than zero")]
    InvalidSequence,
    /// The event contains too many causal parents or duplicates one.
    #[error("causal parents are invalid")]
    InvalidParents,
    /// The group identifier is malformed.
    #[error("group identifier is invalid")]
    InvalidGroupId,
    /// The event version is unsupported.
    #[error("unsupported event version {0}")]
    UnsupportedVersion(u16),
    /// The event kind code is unsupported.
    #[error("unsupported event kind {0}")]
    UnsupportedKind(u16),
    /// The author public key is malformed.
    #[error("event author public key is invalid")]
    PublicKey(#[from] DecodingError),
    /// Binary serialization or deserialization failed.
    #[error("event binary payload is malformed")]
    Serialization(#[from] postcard::Error),
    /// Signing failed.
    #[error("event could not be signed")]
    Signing(#[from] SigningError),
    /// The author signature does not match the event body.
    #[error("event signature is invalid")]
    InvalidSignature,
}

#[derive(Clone, Deserialize, Serialize)]
struct EventBody {
    version: u16,
    group_id: Vec<u8>,
    author_public_key: Vec<u8>,
    author_sequence: u64,
    causal_parents: Vec<EventId>,
    created_at_unix_ms: u64,
    kind: u16,
    protected_payload: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
struct SignedEventWire {
    body: EventBody,
    signature: Vec<u8>,
}

fn validate_body(body: &EventBody) -> Result<(), EventError> {
    if body.version != EVENT_VERSION {
        return Err(EventError::UnsupportedVersion(body.version));
    }
    PeerId::from_bytes(&body.group_id).map_err(|_| EventError::InvalidGroupId)?;
    EventKind::from_code(body.kind)?;
    if body.author_sequence == 0 {
        return Err(EventError::InvalidSequence);
    }
    if body.protected_payload.len() > MAX_PROTECTED_PAYLOAD_BYTES {
        return Err(EventError::PayloadTooLarge);
    }
    if body.causal_parents.len() > MAX_CAUSAL_PARENTS {
        return Err(EventError::InvalidParents);
    }
    let unique_parents: HashSet<_> = body.causal_parents.iter().collect();
    if unique_parents.len() != body.causal_parents.len() {
        return Err(EventError::InvalidParents);
    }
    Ok(())
}

fn signing_payload(body_bytes: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(SIGNING_DOMAIN.len() + body_bytes.len());
    payload.extend_from_slice(SIGNING_DOMAIN);
    payload.extend_from_slice(body_bytes);
    payload
}

fn event_id(body_bytes: &[u8]) -> EventId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(EVENT_ID_DOMAIN);
    hasher.update(body_bytes);
    EventId(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use super::{EventError, EventKind, EventSpec, SignedEvent, SignedEventWire};
    use crate::{DeviceIdentity, EventId, GroupIdentity};

    fn create_message(
        author: &DeviceIdentity,
        group: &GroupIdentity,
        sequence: u64,
        parents: &[EventId],
        payload: &[u8],
    ) -> Result<SignedEvent, EventError> {
        SignedEvent::create(
            author,
            EventSpec {
                group_id: group.group_id(),
                author_sequence: sequence,
                causal_parents: parents,
                created_at_unix_ms: 1_800_000_000_000,
                kind: EventKind::MessageCreated,
                protected_payload: payload,
            },
        )
    }

    #[test]
    fn signed_event_round_trips_with_stable_identity_and_metadata() {
        let author = DeviceIdentity::generate();
        let group = GroupIdentity::generate();
        let parent = create_message(&author, &group, 1, &[], b"first").unwrap();
        let event = create_message(&author, &group, 2, &[parent.id()], b"protected").unwrap();
        let decoded = SignedEvent::decode(&event.encode().unwrap()).unwrap();

        assert_eq!(decoded.id(), event.id());
        assert_eq!(decoded.group_id(), group.group_id());
        assert_eq!(decoded.author_id(), author.peer_id());
        assert_eq!(decoded.author_sequence(), 2);
        assert_eq!(decoded.causal_parents(), &[parent.id()]);
        assert_eq!(decoded.created_at_unix_ms(), 1_800_000_000_000);
        assert_eq!(decoded.kind(), EventKind::MessageCreated);
        assert_eq!(decoded.protected_payload(), b"protected");
    }

    #[test]
    fn changing_event_content_invalidates_the_signature() {
        let author = DeviceIdentity::generate();
        let group = GroupIdentity::generate();
        let event = create_message(&author, &group, 1, &[], b"protected").unwrap();
        let mut wire: SignedEventWire = postcard::from_bytes(&event.encode().unwrap()).unwrap();
        wire.body.protected_payload = b"tampered".to_vec();
        let tampered = postcard::to_allocvec(&wire).unwrap();

        assert!(matches!(
            SignedEvent::decode(&tampered),
            Err(EventError::InvalidSignature)
        ));
    }

    #[test]
    fn content_changes_produce_different_event_ids() {
        let author = DeviceIdentity::generate();
        let group = GroupIdentity::generate();
        let first = create_message(&author, &group, 1, &[], b"first").unwrap();
        let second = create_message(&author, &group, 1, &[], b"second").unwrap();

        assert_ne!(first.id(), second.id());
    }

    #[test]
    fn sequence_zero_is_rejected() {
        let author = DeviceIdentity::generate();
        let group = GroupIdentity::generate();

        assert!(matches!(
            create_message(&author, &group, 0, &[], b"payload"),
            Err(EventError::InvalidSequence)
        ));
    }

    #[test]
    fn duplicate_parents_are_rejected() {
        let author = DeviceIdentity::generate();
        let group = GroupIdentity::generate();
        let parent = create_message(&author, &group, 1, &[], b"parent").unwrap();

        assert!(matches!(
            create_message(&author, &group, 2, &[parent.id(), parent.id()], b"child"),
            Err(EventError::InvalidParents)
        ));
    }

    #[test]
    fn oversized_protected_payload_is_rejected() {
        let author = DeviceIdentity::generate();
        let group = GroupIdentity::generate();
        let payload = vec![0; 64 * 1024 + 1];

        assert!(matches!(
            create_message(&author, &group, 1, &[], &payload),
            Err(EventError::PayloadTooLarge)
        ));
    }
}
