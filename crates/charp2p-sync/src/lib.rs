#![forbid(unsafe_code)]

//! Bounded synchronization orchestration between protocol messages and SQLite.

use std::collections::{HashMap, VecDeque};

use charp2p_core::{
    EventError, EventKind, PeerId, SignedEvent, SyncAuthorHead, SyncError, SyncRequest,
    SyncResponse, MAX_SYNC_BATCH_ITEMS, MAX_SYNC_RESPONSE_BYTES,
};
use charp2p_store::{EventStore, PutEventsOutcome, StoreError};
use thiserror::Error;

/// Builds a response after the caller has authorized the requesting peer for
/// the request's group.
pub fn build_authorized_response(
    store: &EventStore,
    request: &SyncRequest,
) -> Result<SyncResponse, SynchronizationError> {
    request.validate()?;
    let response = match request {
        SyncRequest::Summary { group_id } => SyncResponse::Summary {
            group_id: *group_id,
            heads: store.synchronization_summary(*group_id)?,
        },
        SyncRequest::EventIds {
            group_id,
            author_id,
            after_sequence,
            limit,
        } => {
            let event_ids = store.event_ids_after(
                *group_id,
                *author_id,
                *after_sequence,
                usize::from(*limit),
            )?;
            let complete = event_ids.len() < usize::from(*limit);
            SyncResponse::EventIds {
                group_id: *group_id,
                author_id: *author_id,
                event_ids,
                complete,
            }
        }
        SyncRequest::Events {
            group_id,
            event_ids,
        } => {
            let mut encoded_events = Vec::with_capacity(event_ids.len());
            let mut total_bytes = 0_usize;

            for event_id in event_ids {
                let Some(event) = store.get_event(*event_id)? else {
                    continue;
                };
                if event.group_id() != *group_id {
                    continue;
                }
                let encoded = event.encode()?;
                let next_total = total_bytes
                    .checked_add(encoded.len())
                    .ok_or(SynchronizationError::ResponseLimit)?;
                if next_total > MAX_SYNC_RESPONSE_BYTES {
                    break;
                }
                total_bytes = next_total;
                encoded_events.push(encoded);
            }

            SyncResponse::Events {
                group_id: *group_id,
                encoded_events,
            }
        }
        SyncRequest::PushEvents { .. } => {
            return Err(SynchronizationError::UnexpectedRequest);
        }
    };
    response.validate()?;
    Ok(response)
}

/// Validates and atomically stores events uploaded by an authenticated group member.
///
/// Uploads are restricted to messages signed by the connected device. Membership
/// authorization remains the caller's responsibility.
pub fn accept_pushed_events(
    store: &mut EventStore,
    authenticated_peer: PeerId,
    request: &SyncRequest,
) -> Result<ApplyOutcome, SynchronizationError> {
    request.validate()?;
    let SyncRequest::PushEvents { encoded_events, .. } = request else {
        return Err(SynchronizationError::UnexpectedRequest);
    };

    let mut events = Vec::with_capacity(encoded_events.len());
    for encoded in encoded_events {
        let event = SignedEvent::decode(encoded)?;
        if event.author_id() != authenticated_peer {
            return Err(SynchronizationError::PushedAuthorMismatch);
        }
        if event.kind() != EventKind::MessageCreated {
            return Err(SynchronizationError::UnsupportedPushedEvent);
        }
        events.push(event);
    }

    Ok(store.put_events(&events)?.into())
}

/// Validates and atomically commits signed events from a peer response.
pub fn apply_response(
    store: &mut EventStore,
    response: &SyncResponse,
) -> Result<ApplyOutcome, SynchronizationError> {
    response.validate()?;
    let SyncResponse::Events { encoded_events, .. } = response else {
        return Ok(ApplyOutcome::default());
    };

    let events: Result<Vec<_>, _> = encoded_events
        .iter()
        .map(|encoded| SignedEvent::decode(encoded))
        .collect();
    let outcome = store.put_events(&events?)?;
    Ok(outcome.into())
}

/// Sequential pull synchronization against one authenticated, authorized peer.
pub struct PullSession {
    group_id: PeerId,
    phase: PullPhase,
    remaining_authors: VecDeque<SyncAuthorHead>,
}

impl PullSession {
    /// Starts a session with a request for the peer's gap-free author heads.
    pub fn start(group_id: PeerId) -> (Self, SyncRequest) {
        (
            Self {
                group_id,
                phase: PullPhase::AwaitingSummary,
                remaining_authors: VecDeque::new(),
            },
            SyncRequest::Summary { group_id },
        )
    }

    /// Validates and applies one response, then returns the next bounded request.
    pub fn handle_response(
        &mut self,
        store: &mut EventStore,
        response: &SyncResponse,
    ) -> Result<SessionProgress, SynchronizationError> {
        response.validate()?;
        let phase = std::mem::replace(&mut self.phase, PullPhase::Complete);
        let mut applied = ApplyOutcome::default();

        let next_request = match (phase, response) {
            (PullPhase::AwaitingSummary, SyncResponse::Summary { group_id, heads }) => {
                self.ensure_group(*group_id)?;
                let local: HashMap<_, _> = store
                    .synchronization_summary(self.group_id)?
                    .into_iter()
                    .map(|head| (head.author_id, head.contiguous_sequence))
                    .collect();
                let mut missing: Vec<_> = heads
                    .iter()
                    .filter(|head| {
                        head.contiguous_sequence > local.get(&head.author_id).copied().unwrap_or(0)
                    })
                    .cloned()
                    .collect();
                missing.sort_by_key(|head| head.author_id.to_bytes());
                self.remaining_authors = missing.into();
                self.next_author_request(store)?
            }
            (
                PullPhase::AwaitingEventIds {
                    author_id,
                    remote_head,
                    local_head,
                },
                SyncResponse::EventIds {
                    group_id,
                    author_id: response_author,
                    event_ids,
                    ..
                },
            ) => {
                self.ensure_group(*group_id)?;
                if *response_author != author_id {
                    return Err(SynchronizationError::AuthorMismatch);
                }
                if event_ids.is_empty() {
                    return Err(SynchronizationError::NoProgress);
                }
                self.phase = PullPhase::AwaitingEvents {
                    author_id,
                    remote_head,
                    local_head,
                };
                Some(SyncRequest::Events {
                    group_id: self.group_id,
                    event_ids: event_ids.clone(),
                })
            }
            (
                PullPhase::AwaitingEvents {
                    author_id,
                    remote_head,
                    local_head,
                },
                SyncResponse::Events { group_id, .. },
            ) => {
                self.ensure_group(*group_id)?;
                applied = apply_response(store, response)?;
                let new_head = local_author_head(store, self.group_id, author_id)?;
                if new_head <= local_head {
                    return Err(SynchronizationError::NoProgress);
                }
                if new_head >= remote_head {
                    self.next_author_request(store)?
                } else {
                    self.phase = PullPhase::AwaitingEventIds {
                        author_id,
                        remote_head,
                        local_head: new_head,
                    };
                    Some(event_ids_request(self.group_id, author_id, new_head))
                }
            }
            (PullPhase::Complete, _) => return Err(SynchronizationError::SessionComplete),
            _ => return Err(SynchronizationError::UnexpectedResponse),
        };

        Ok(SessionProgress {
            next_request,
            applied,
            complete: matches!(self.phase, PullPhase::Complete),
        })
    }

    /// Returns whether the remote summary snapshot has been fully pulled.
    pub fn is_complete(&self) -> bool {
        matches!(self.phase, PullPhase::Complete)
    }

    /// Returns the group scope fixed when this pull session started.
    pub fn group_id(&self) -> PeerId {
        self.group_id
    }

    fn next_author_request(
        &mut self,
        store: &EventStore,
    ) -> Result<Option<SyncRequest>, SynchronizationError> {
        while let Some(remote) = self.remaining_authors.pop_front() {
            let local_head = local_author_head(store, self.group_id, remote.author_id)?;
            if local_head >= remote.contiguous_sequence {
                continue;
            }
            self.phase = PullPhase::AwaitingEventIds {
                author_id: remote.author_id,
                remote_head: remote.contiguous_sequence,
                local_head,
            };
            return Ok(Some(event_ids_request(
                self.group_id,
                remote.author_id,
                local_head,
            )));
        }
        self.phase = PullPhase::Complete;
        Ok(None)
    }

    fn ensure_group(&self, group_id: PeerId) -> Result<(), SynchronizationError> {
        if group_id != self.group_id {
            return Err(SynchronizationError::GroupMismatch);
        }
        Ok(())
    }
}

enum PullPhase {
    AwaitingSummary,
    AwaitingEventIds {
        author_id: PeerId,
        remote_head: u64,
        local_head: u64,
    },
    AwaitingEvents {
        author_id: PeerId,
        remote_head: u64,
        local_head: u64,
    },
    Complete,
}

/// Result of advancing a pull synchronization session.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SessionProgress {
    /// Next request to send to the same peer, if any.
    pub next_request: Option<SyncRequest>,
    /// Local event changes produced by this response.
    pub applied: ApplyOutcome,
    /// Whether the remote summary snapshot is fully synchronized.
    pub complete: bool,
}

/// Local changes caused by applying one synchronization response.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ApplyOutcome {
    /// Events persisted for the first time.
    pub inserted: usize,
    /// Exact events already present locally.
    pub already_present: usize,
}

impl From<PutEventsOutcome> for ApplyOutcome {
    fn from(outcome: PutEventsOutcome) -> Self {
        Self {
            inserted: outcome.inserted,
            already_present: outcome.already_present,
        }
    }
}

/// Failure while building or applying a synchronization exchange.
#[derive(Debug, Error)]
pub enum SynchronizationError {
    /// The synchronization message violated protocol validation.
    #[error("invalid synchronization message")]
    Protocol(#[from] SyncError),
    /// Local event persistence failed.
    #[error("synchronization storage failed")]
    Store(#[from] StoreError),
    /// A locally stored event could not be canonically encoded.
    #[error("stored event encoding failed")]
    Event(#[from] EventError),
    /// The response byte limit was exceeded while calculating a page.
    #[error("synchronization response exceeds its byte limit")]
    ResponseLimit,
    /// A response belongs to a different group than the session.
    #[error("synchronization response belongs to another group")]
    GroupMismatch,
    /// An event-ID response belongs to a different author.
    #[error("synchronization response belongs to another author")]
    AuthorMismatch,
    /// The response type does not match the outstanding request.
    #[error("unexpected synchronization response")]
    UnexpectedResponse,
    /// The remote peer failed to advance a sequence it advertised.
    #[error("synchronization peer made no progress")]
    NoProgress,
    /// A completed session received another response.
    #[error("synchronization session is already complete")]
    SessionComplete,
    /// A push request was passed to a read-only response builder, or vice versa.
    #[error("unexpected synchronization request")]
    UnexpectedRequest,
    /// An uploaded event was not authored by the authenticated connection.
    #[error("uploaded event author does not match the authenticated peer")]
    PushedAuthorMismatch,
    /// Only group messages can be uploaded by a member.
    #[error("uploaded event kind is not supported")]
    UnsupportedPushedEvent,
}

fn event_ids_request(group_id: PeerId, author_id: PeerId, after_sequence: u64) -> SyncRequest {
    SyncRequest::EventIds {
        group_id,
        author_id,
        after_sequence,
        limit: MAX_SYNC_BATCH_ITEMS as u16,
    }
}

fn local_author_head(
    store: &EventStore,
    group_id: PeerId,
    author_id: PeerId,
) -> Result<u64, StoreError> {
    Ok(store
        .synchronization_summary(group_id)?
        .into_iter()
        .find(|head| head.author_id == author_id)
        .map(|head| head.contiguous_sequence)
        .unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use charp2p_core::{
        DeviceIdentity, EventKind, EventSpec, GroupIdentity, SignedEvent, SyncRequest, SyncResponse,
    };
    use charp2p_store::EventStore;

    use super::{
        accept_pushed_events, apply_response, build_authorized_response, ApplyOutcome, PullSession,
        SynchronizationError,
    };

    #[test]
    fn missing_events_move_between_independent_stores() {
        let group = GroupIdentity::generate();
        let author = DeviceIdentity::generate();
        let first = message_event(&author, &group, 1, b"first");
        let second = message_event(&author, &group, 2, b"second");
        let third = message_event(&author, &group, 3, b"third");
        let mut source = EventStore::in_memory().unwrap();
        let mut target = EventStore::in_memory().unwrap();
        source.put_events(&[first, second, third]).unwrap();

        let summary = build_authorized_response(
            &source,
            &SyncRequest::Summary {
                group_id: group.group_id(),
            },
        )
        .unwrap();
        let SyncResponse::Summary { heads, .. } = summary else {
            panic!("summary request must return author heads");
        };
        assert_eq!(heads.len(), 1);
        assert_eq!(heads[0].contiguous_sequence, 3);

        let identifiers = build_authorized_response(
            &source,
            &SyncRequest::EventIds {
                group_id: group.group_id(),
                author_id: author.peer_id(),
                after_sequence: 0,
                limit: 256,
            },
        )
        .unwrap();
        let SyncResponse::EventIds {
            event_ids,
            complete,
            ..
        } = identifiers
        else {
            panic!("identifier request must return event IDs");
        };
        assert!(complete);
        assert_eq!(event_ids.len(), 3);

        let events = build_authorized_response(
            &source,
            &SyncRequest::Events {
                group_id: group.group_id(),
                event_ids,
            },
        )
        .unwrap();
        assert_eq!(
            apply_response(&mut target, &events).unwrap(),
            ApplyOutcome {
                inserted: 3,
                already_present: 0,
            }
        );
        assert_eq!(
            target.synchronization_summary(group.group_id()).unwrap(),
            heads
        );
    }

    #[test]
    fn applying_the_same_response_is_idempotent() {
        let group = GroupIdentity::generate();
        let author = DeviceIdentity::generate();
        let event = message_event(&author, &group, 1, b"message");
        let response = SyncResponse::Events {
            group_id: group.group_id(),
            encoded_events: vec![event.encode().unwrap()],
        };
        let mut store = EventStore::in_memory().unwrap();

        assert_eq!(apply_response(&mut store, &response).unwrap().inserted, 1);
        assert_eq!(
            apply_response(&mut store, &response)
                .unwrap()
                .already_present,
            1
        );
    }

    #[test]
    fn authenticated_message_push_is_idempotent() {
        let group = GroupIdentity::generate();
        let author = DeviceIdentity::generate();
        let event = message_event(&author, &group, 1, b"message");
        let request = SyncRequest::PushEvents {
            group_id: group.group_id(),
            encoded_events: vec![event.encode().unwrap()],
        };
        let mut store = EventStore::in_memory().unwrap();

        assert_eq!(
            accept_pushed_events(&mut store, author.peer_id(), &request)
                .unwrap()
                .inserted,
            1
        );
        assert_eq!(
            accept_pushed_events(&mut store, author.peer_id(), &request)
                .unwrap()
                .already_present,
            1
        );
    }

    #[test]
    fn push_rejects_events_signed_by_another_device() {
        let group = GroupIdentity::generate();
        let author = DeviceIdentity::generate();
        let authenticated = DeviceIdentity::generate();
        let event = message_event(&author, &group, 1, b"message");
        let request = SyncRequest::PushEvents {
            group_id: group.group_id(),
            encoded_events: vec![event.encode().unwrap()],
        };
        let mut store = EventStore::in_memory().unwrap();

        assert!(matches!(
            accept_pushed_events(&mut store, authenticated.peer_id(), &request),
            Err(SynchronizationError::PushedAuthorMismatch)
        ));
    }

    #[test]
    fn pull_session_synchronizes_multiple_identifier_pages() {
        let group = GroupIdentity::generate();
        let author = DeviceIdentity::generate();
        let events: Vec<_> = (1..=300)
            .map(|sequence| message_event(&author, &group, sequence, b"page"))
            .collect();
        let mut source = EventStore::in_memory().unwrap();
        let mut target = EventStore::in_memory().unwrap();
        source.put_events(&events).unwrap();

        let (mut session, mut request) = PullSession::start(group.group_id());
        let mut inserted = 0;
        let mut exchanges = 0;
        loop {
            let response = build_authorized_response(&source, &request).unwrap();
            let progress = session.handle_response(&mut target, &response).unwrap();
            inserted += progress.applied.inserted;
            exchanges += 1;
            let Some(next_request) = progress.next_request else {
                assert!(progress.complete);
                break;
            };
            request = next_request;
        }

        assert!(session.is_complete());
        assert_eq!(inserted, 300);
        assert_eq!(exchanges, 5);
        assert_eq!(
            target.synchronization_summary(group.group_id()).unwrap(),
            source.synchronization_summary(group.group_id()).unwrap()
        );
    }

    fn message_event(
        author: &DeviceIdentity,
        group: &GroupIdentity,
        sequence: u64,
        payload: &[u8],
    ) -> SignedEvent {
        SignedEvent::create(
            author,
            EventSpec {
                group_id: group.group_id(),
                author_sequence: sequence,
                causal_parents: &[],
                created_at_unix_ms: 1_800_000_000_000,
                kind: EventKind::MessageCreated,
                protected_payload: payload,
            },
        )
        .unwrap()
    }
}
