use std::collections::HashSet;

use libp2p_identity::PeerId;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{EventId, SignedEvent};

/// Largest author summary accepted from one peer.
pub const MAX_SYNC_AUTHORS: usize = 1_024;
/// Largest event or identifier page accepted in one synchronization exchange.
pub const MAX_SYNC_BATCH_ITEMS: usize = 256;
/// Largest encoded signed event accepted in synchronization.
pub const MAX_SYNC_EVENT_BYTES: usize = 128 * 1024;
/// Largest combined event payload accepted in one synchronization response.
pub const MAX_SYNC_RESPONSE_BYTES: usize = 2 * 1024 * 1024;

/// Highest gap-free event sequence stored for one group author.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SyncAuthorHead {
    /// Device that authored this sequence.
    pub author_id: PeerId,
    /// Highest sequence for which every event from one is present.
    pub contiguous_sequence: u64,
}

/// Highest gap-free sequence of one author that a peer reported storing.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SyncPeerHead {
    /// Device whose stored sequence this is.
    pub peer_id: PeerId,
    /// Highest sequence for which every event from one is stored on the peer.
    pub contiguous_sequence: u64,
}

/// Bounded synchronization request sent over an authenticated peer stream.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SyncRequest {
    /// Requests the receiver's gap-free author heads for a group.
    Summary { group_id: PeerId },
    /// Requests an ordered page of event IDs after one author sequence.
    EventIds {
        group_id: PeerId,
        author_id: PeerId,
        after_sequence: u64,
        limit: u16,
    },
    /// Requests signed envelopes by their identifiers.
    Events {
        group_id: PeerId,
        event_ids: Vec<EventId>,
    },
    /// Offers locally authored signed events to the group owner.
    PushEvents {
        group_id: PeerId,
        encoded_events: Vec<Vec<u8>>,
    },
    /// Reports the sender's gap-free author heads after a completed exchange
    /// and asks which heads of its own events other devices reported.
    ReportHeads {
        group_id: PeerId,
        heads: Vec<SyncAuthorHead>,
    },
}

impl SyncRequest {
    /// Checks collection bounds and duplicate identifiers before processing.
    pub fn validate(&self) -> Result<(), SyncError> {
        match self {
            Self::Summary { .. } => Ok(()),
            Self::EventIds { limit, .. } if (1..=MAX_SYNC_BATCH_ITEMS as u16).contains(limit) => {
                Ok(())
            }
            Self::EventIds { limit, .. } => Err(SyncError::InvalidBatchLimit(*limit)),
            Self::Events { event_ids, .. } => validate_event_ids(event_ids),
            Self::PushEvents {
                group_id,
                encoded_events,
            } => {
                if encoded_events.is_empty() {
                    return Err(SyncError::EmptyEventBatch);
                }
                validate_events(group_id, encoded_events)
            }
            Self::ReportHeads { heads, .. } => validate_heads(heads),
        }
    }
}

/// Bounded synchronization response returned over an authenticated peer stream.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SyncResponse {
    /// Gap-free author heads for the requested group.
    Summary {
        group_id: PeerId,
        heads: Vec<SyncAuthorHead>,
    },
    /// Ordered event identifiers for one author.
    EventIds {
        group_id: PeerId,
        author_id: PeerId,
        event_ids: Vec<EventId>,
        /// Whether no later identifiers remain for this author.
        complete: bool,
    },
    /// Canonical signed event envelopes.
    Events {
        group_id: PeerId,
        encoded_events: Vec<Vec<u8>>,
    },
    /// Confirms an authenticated push and reports newly persisted events.
    EventsAccepted { group_id: PeerId, inserted: u16 },
    /// The peer refused the request without disclosing group state.
    Rejected { reason: SyncRejectReason },
    /// Heads of the requester's own events last reported by each other device.
    ObservedHeads {
        group_id: PeerId,
        peers: Vec<SyncPeerHead>,
    },
}

impl SyncResponse {
    /// Checks bounds, uniqueness, signatures, and group scope before use.
    pub fn validate(&self) -> Result<(), SyncError> {
        match self {
            Self::Summary { heads, .. } => validate_heads(heads),
            Self::EventIds { event_ids, .. } => {
                if event_ids.len() > MAX_SYNC_BATCH_ITEMS {
                    return Err(SyncError::TooManyEventIds);
                }
                if has_duplicate_event_ids(event_ids) {
                    return Err(SyncError::DuplicateEventId);
                }
                Ok(())
            }
            Self::Events {
                group_id,
                encoded_events,
            } => validate_events(group_id, encoded_events),
            Self::EventsAccepted { inserted, .. }
                if usize::from(*inserted) <= MAX_SYNC_BATCH_ITEMS =>
            {
                Ok(())
            }
            Self::EventsAccepted { inserted, .. } => {
                Err(SyncError::InvalidAcceptedCount(*inserted))
            }
            Self::Rejected { .. } => Ok(()),
            Self::ObservedHeads { peers, .. } => validate_peer_heads(peers),
        }
    }
}

/// Stable reasons a peer may reject synchronization without extra details.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SyncRejectReason {
    /// The peer does not serve the requested group to this connection.
    Unauthorized,
    /// The request violated a protocol bound or shape rule.
    InvalidRequest,
    /// The peer is temporarily unable to serve synchronization.
    Busy,
}

/// Invalid or unsafe synchronization payload.
#[derive(Debug, Error)]
pub enum SyncError {
    /// A requested page size is zero or exceeds the protocol bound.
    #[error("invalid synchronization batch limit {0}")]
    InvalidBatchLimit(u16),
    /// A request or response carries too many event identifiers.
    #[error("synchronization payload contains too many event identifiers")]
    TooManyEventIds,
    /// An event upload request contains no events.
    #[error("synchronization event upload is empty")]
    EmptyEventBatch,
    /// An upload acknowledgement exceeds the protocol batch bound.
    #[error("invalid accepted event count {0}")]
    InvalidAcceptedCount(u16),
    /// A response carries too many author heads.
    #[error("synchronization summary contains too many authors")]
    TooManyAuthors,
    /// The same author appears more than once in a summary.
    #[error("synchronization summary repeats an author")]
    DuplicateAuthor,
    /// A response carries too many peer heads.
    #[error("synchronization receipt contains too many peers")]
    TooManyPeers,
    /// The same peer appears more than once in a receipt.
    #[error("synchronization receipt repeats a peer")]
    DuplicatePeer,
    /// The same event identifier appears more than once.
    #[error("synchronization payload repeats an event identifier")]
    DuplicateEventId,
    /// An event envelope exceeds its individual bound.
    #[error("synchronized event exceeds the encoded event bound")]
    EventTooLarge,
    /// Combined event envelopes exceed the response bound.
    #[error("synchronization response exceeds the event payload bound")]
    ResponseTooLarge,
    /// An encoded event failed canonical validation or signature verification.
    #[error("synchronized event is invalid")]
    InvalidEvent(#[from] crate::EventError),
    /// A signed event belongs to another group.
    #[error("synchronized event belongs to another group")]
    GroupMismatch,
}

fn validate_event_ids(event_ids: &[EventId]) -> Result<(), SyncError> {
    if event_ids.is_empty() || event_ids.len() > MAX_SYNC_BATCH_ITEMS {
        return Err(SyncError::TooManyEventIds);
    }
    if has_duplicate_event_ids(event_ids) {
        return Err(SyncError::DuplicateEventId);
    }
    Ok(())
}

fn has_duplicate_event_ids(event_ids: &[EventId]) -> bool {
    let unique: HashSet<_> = event_ids.iter().collect();
    unique.len() != event_ids.len()
}

fn validate_heads(heads: &[SyncAuthorHead]) -> Result<(), SyncError> {
    if heads.len() > MAX_SYNC_AUTHORS {
        return Err(SyncError::TooManyAuthors);
    }
    let unique: HashSet<_> = heads.iter().map(|head| head.author_id).collect();
    if unique.len() != heads.len() {
        return Err(SyncError::DuplicateAuthor);
    }
    Ok(())
}

fn validate_peer_heads(peers: &[SyncPeerHead]) -> Result<(), SyncError> {
    if peers.len() > MAX_SYNC_AUTHORS {
        return Err(SyncError::TooManyPeers);
    }
    let unique: HashSet<_> = peers.iter().map(|head| head.peer_id).collect();
    if unique.len() != peers.len() {
        return Err(SyncError::DuplicatePeer);
    }
    Ok(())
}

fn validate_events(group_id: &PeerId, encoded_events: &[Vec<u8>]) -> Result<(), SyncError> {
    if encoded_events.len() > MAX_SYNC_BATCH_ITEMS {
        return Err(SyncError::TooManyEventIds);
    }
    let mut total_bytes = 0_usize;
    let mut event_ids = HashSet::with_capacity(encoded_events.len());

    for encoded in encoded_events {
        if encoded.len() > MAX_SYNC_EVENT_BYTES {
            return Err(SyncError::EventTooLarge);
        }
        total_bytes = total_bytes
            .checked_add(encoded.len())
            .ok_or(SyncError::ResponseTooLarge)?;
        if total_bytes > MAX_SYNC_RESPONSE_BYTES {
            return Err(SyncError::ResponseTooLarge);
        }

        let event = SignedEvent::decode(encoded)?;
        if event.group_id() != *group_id {
            return Err(SyncError::GroupMismatch);
        }
        if !event_ids.insert(event.id()) {
            return Err(SyncError::DuplicateEventId);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::{DeviceIdentity, EventKind, EventSpec, GroupIdentity};

    use super::{
        MAX_SYNC_AUTHORS, MAX_SYNC_BATCH_ITEMS, SyncAuthorHead, SyncError, SyncPeerHead,
        SyncRequest, SyncResponse,
    };

    #[test]
    fn request_batch_limits_and_duplicate_ids_are_rejected() {
        let group = GroupIdentity::generate();
        let author = DeviceIdentity::generate();
        let event = signed_event(&author, &group, 1);

        assert!(matches!(
            SyncRequest::EventIds {
                group_id: group.group_id(),
                author_id: author.peer_id(),
                after_sequence: 0,
                limit: 0,
            }
            .validate(),
            Err(SyncError::InvalidBatchLimit(0))
        ));
        assert!(matches!(
            SyncRequest::Events {
                group_id: group.group_id(),
                event_ids: vec![event.id(), event.id()],
            }
            .validate(),
            Err(SyncError::DuplicateEventId)
        ));
    }

    #[test]
    fn summaries_reject_duplicate_and_excessive_authors() {
        let group = GroupIdentity::generate();
        let author = DeviceIdentity::generate();
        let duplicate = SyncAuthorHead {
            author_id: author.peer_id(),
            contiguous_sequence: 1,
        };
        assert!(matches!(
            SyncResponse::Summary {
                group_id: group.group_id(),
                heads: vec![duplicate.clone(), duplicate],
            }
            .validate(),
            Err(SyncError::DuplicateAuthor)
        ));

        let heads = (0..=MAX_SYNC_AUTHORS)
            .map(|_| SyncAuthorHead {
                author_id: DeviceIdentity::generate().peer_id(),
                contiguous_sequence: 0,
            })
            .collect();
        assert!(matches!(
            SyncResponse::Summary {
                group_id: group.group_id(),
                heads,
            }
            .validate(),
            Err(SyncError::TooManyAuthors)
        ));
    }

    #[test]
    fn head_reports_and_observed_heads_are_bounded_and_unique() {
        let group = GroupIdentity::generate();
        let author = DeviceIdentity::generate();
        let head = SyncAuthorHead {
            author_id: author.peer_id(),
            contiguous_sequence: 3,
        };
        SyncRequest::ReportHeads {
            group_id: group.group_id(),
            heads: vec![head.clone()],
        }
        .validate()
        .unwrap();
        assert!(matches!(
            SyncRequest::ReportHeads {
                group_id: group.group_id(),
                heads: vec![head.clone(), head],
            }
            .validate(),
            Err(SyncError::DuplicateAuthor)
        ));

        let peer = SyncPeerHead {
            peer_id: author.peer_id(),
            contiguous_sequence: 2,
        };
        assert!(matches!(
            SyncResponse::ObservedHeads {
                group_id: group.group_id(),
                peers: vec![peer.clone(), peer],
            }
            .validate(),
            Err(SyncError::DuplicatePeer)
        ));
        let peers = (0..=MAX_SYNC_AUTHORS)
            .map(|_| SyncPeerHead {
                peer_id: DeviceIdentity::generate().peer_id(),
                contiguous_sequence: 0,
            })
            .collect();
        assert!(matches!(
            SyncResponse::ObservedHeads {
                group_id: group.group_id(),
                peers,
            }
            .validate(),
            Err(SyncError::TooManyPeers)
        ));
    }

    #[test]
    fn signed_event_batches_are_verified_and_group_scoped() {
        let group = GroupIdentity::generate();
        let other_group = GroupIdentity::generate();
        let author = DeviceIdentity::generate();
        let event = signed_event(&author, &group, 1);
        let encoded = event.encode().unwrap();

        SyncResponse::Events {
            group_id: group.group_id(),
            encoded_events: vec![encoded.clone()],
        }
        .validate()
        .unwrap();
        assert!(matches!(
            SyncResponse::Events {
                group_id: other_group.group_id(),
                encoded_events: vec![encoded],
            }
            .validate(),
            Err(SyncError::GroupMismatch)
        ));
    }

    #[test]
    fn event_identifier_responses_are_bounded() {
        let group = GroupIdentity::generate();
        let author = DeviceIdentity::generate();
        let event_ids = (1..=MAX_SYNC_BATCH_ITEMS + 1)
            .map(|sequence| signed_event(&author, &group, sequence as u64).id())
            .collect();

        assert!(matches!(
            SyncResponse::EventIds {
                group_id: group.group_id(),
                author_id: author.peer_id(),
                event_ids,
                complete: false,
            }
            .validate(),
            Err(SyncError::TooManyEventIds)
        ));
    }

    fn signed_event(
        author: &DeviceIdentity,
        group: &GroupIdentity,
        sequence: u64,
    ) -> crate::SignedEvent {
        crate::SignedEvent::create(
            author,
            EventSpec {
                group_id: group.group_id(),
                author_sequence: sequence,
                causal_parents: &[],
                created_at_unix_ms: 1_800_000_000_000,
                kind: EventKind::MessageCreated,
                protected_payload: b"protected",
            },
        )
        .unwrap()
    }
}
