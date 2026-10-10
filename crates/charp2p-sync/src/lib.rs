#![forbid(unsafe_code)]

//! Bounded synchronization orchestration between protocol messages and SQLite.

use std::collections::{HashMap, VecDeque};

use charp2p_core::{
    EventError, EventKind, MAX_SYNC_BATCH_ITEMS, MAX_SYNC_RESPONSE_BYTES, PeerId, SignedEvent,
    SyncAuthorHead, SyncError, SyncMembershipState, SyncPeerHead, SyncRequest, SyncResponse,
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
            membership: store.membership_state(*group_id)?,
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
        SyncRequest::PushEvents { .. } | SyncRequest::ReportHeads { .. } => {
            return Err(SynchronizationError::UnexpectedRequest);
        }
    };
    response.validate()?;
    Ok(response)
}

/// Records the author heads an authenticated group member reported storing
/// and answers with the heads of that member's own events reported by every
/// other current member. This device's head comes from its own event store.
///
/// The caller authorizes the peer and supplies the current membership.
pub fn record_reported_heads(
    store: &mut EventStore,
    local_device_id: PeerId,
    authenticated_peer: PeerId,
    current_members: &[PeerId],
    request: &SyncRequest,
) -> Result<SyncResponse, SynchronizationError> {
    request.validate()?;
    let SyncRequest::ReportHeads { group_id, heads } = request else {
        return Err(SynchronizationError::UnexpectedRequest);
    };
    store.acknowledge_author_heads(*group_id, authenticated_peer, heads)?;
    let acknowledged = store.acknowledged_author_heads(*group_id, authenticated_peer)?;
    let local_head = local_author_head(store, *group_id, authenticated_peer)?;
    let peers = current_members
        .iter()
        .filter(|member| **member != authenticated_peer)
        .map(|member| SyncPeerHead {
            peer_id: *member,
            contiguous_sequence: if *member == local_device_id {
                local_head
            } else {
                acknowledged.get(member).copied().unwrap_or(0)
            },
        })
        .collect();
    let response = SyncResponse::ObservedHeads {
        group_id: *group_id,
        peers,
    };
    response.validate()?;
    Ok(response)
}

/// Validates and atomically stores events uploaded by an authenticated group member.
///
/// Uploads are restricted to messages and message edits signed by the connected
/// device. Membership
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
        if !matches!(
            event.kind(),
            EventKind::MessageCreated | EventKind::MessageEdited | EventKind::MessageDeleted
        ) {
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
    membership: Option<MembershipComparison>,
}

/// How the local membership state compared with the peer's summary before
/// the pull started.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MembershipComparison {
    /// Both devices store the same newest membership commit.
    Same,
    /// The peer stores membership commits this device has not stored yet.
    RemoteNewer,
    /// This device stores membership commits the peer has not stored yet.
    RemoteStale,
    /// Both store the same number of commits but a different newest commit.
    Diverged,
}

impl MembershipComparison {
    /// Compares the local membership state with a peer's reported state.
    pub fn between(local: &SyncMembershipState, remote: &SyncMembershipState) -> Self {
        match remote.commits.cmp(&local.commits) {
            std::cmp::Ordering::Greater => Self::RemoteNewer,
            std::cmp::Ordering::Less => Self::RemoteStale,
            std::cmp::Ordering::Equal if remote.latest_commit == local.latest_commit => Self::Same,
            std::cmp::Ordering::Equal => Self::Diverged,
        }
    }
}

impl PullSession {
    /// Starts a session with a request for the peer's gap-free author heads.
    pub fn start(group_id: PeerId) -> (Self, SyncRequest) {
        (
            Self {
                group_id,
                phase: PullPhase::AwaitingSummary,
                remaining_authors: VecDeque::new(),
                membership: None,
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
            (
                PullPhase::AwaitingSummary,
                SyncResponse::Summary {
                    group_id,
                    heads,
                    membership,
                },
            ) => {
                self.ensure_group(*group_id)?;
                self.membership = Some(MembershipComparison::between(
                    &store.membership_state(self.group_id)?,
                    membership,
                ));
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

    /// Returns how local membership compared with the peer's summary, once
    /// the summary has been received.
    pub fn membership_comparison(&self) -> Option<MembershipComparison> {
        self.membership
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
    /// Only group messages and message edits can be uploaded by a member.
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
        DeviceIdentity, EventId, EventKind, EventSpec, GroupIdentity, SignedEvent, SyncAuthorHead,
        SyncMembershipState, SyncPeerHead, SyncRequest, SyncResponse,
    };
    use charp2p_store::EventStore;

    use super::{
        ApplyOutcome, MembershipComparison, PullSession, SynchronizationError,
        accept_pushed_events, apply_response, build_authorized_response, record_reported_heads,
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
    fn reported_heads_answer_with_every_other_members_observation() {
        let group = GroupIdentity::generate();
        let owner = DeviceIdentity::generate();
        let sender = DeviceIdentity::generate();
        let reader = DeviceIdentity::generate();
        let removed = DeviceIdentity::generate();
        let mut store = EventStore::in_memory().unwrap();
        store
            .put_events(&[
                message_event(&sender, &group, 1, b"first"),
                message_event(&sender, &group, 2, b"second"),
            ])
            .unwrap();
        let members = [owner.peer_id(), sender.peer_id(), reader.peer_id()];
        let report = |heads| SyncRequest::ReportHeads {
            group_id: group.group_id(),
            heads,
        };

        record_reported_heads(
            &mut store,
            owner.peer_id(),
            reader.peer_id(),
            &members,
            &report(vec![SyncAuthorHead {
                author_id: sender.peer_id(),
                contiguous_sequence: 1,
            }]),
        )
        .unwrap();
        store
            .acknowledge_author_head(group.group_id(), removed.peer_id(), sender.peer_id(), 2)
            .unwrap();

        let response = record_reported_heads(
            &mut store,
            owner.peer_id(),
            sender.peer_id(),
            &members,
            &report(Vec::new()),
        )
        .unwrap();
        assert_eq!(
            response,
            SyncResponse::ObservedHeads {
                group_id: group.group_id(),
                peers: vec![
                    SyncPeerHead {
                        peer_id: owner.peer_id(),
                        contiguous_sequence: 2,
                    },
                    SyncPeerHead {
                        peer_id: reader.peer_id(),
                        contiguous_sequence: 1,
                    },
                ],
            }
        );
        assert!(matches!(
            build_authorized_response(&store, &report(Vec::new())),
            Err(SynchronizationError::UnexpectedRequest)
        ));
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
    fn push_accepts_message_edits_and_deletions_and_rejects_membership_events() {
        let group = GroupIdentity::generate();
        let author = DeviceIdentity::generate();
        let event_of = |sequence, kind| {
            SignedEvent::create(
                &author,
                EventSpec {
                    group_id: group.group_id(),
                    author_sequence: sequence,
                    causal_parents: &[],
                    created_at_unix_ms: 1_800_000_000_000,
                    kind,
                    protected_payload: b"protected",
                },
            )
            .unwrap()
        };
        let mut store = EventStore::in_memory().unwrap();
        let edits = SyncRequest::PushEvents {
            group_id: group.group_id(),
            encoded_events: vec![
                message_event(&author, &group, 1, b"message")
                    .encode()
                    .unwrap(),
                event_of(2, EventKind::MessageEdited).encode().unwrap(),
                event_of(3, EventKind::MessageDeleted).encode().unwrap(),
            ],
        };
        assert_eq!(
            accept_pushed_events(&mut store, author.peer_id(), &edits)
                .unwrap()
                .inserted,
            3
        );
        let metadata = SyncRequest::PushEvents {
            group_id: group.group_id(),
            encoded_events: vec![
                event_of(4, EventKind::GroupMetadataChanged)
                    .encode()
                    .unwrap(),
            ],
        };
        assert!(matches!(
            accept_pushed_events(&mut store, author.peer_id(), &metadata),
            Err(SynchronizationError::UnsupportedPushedEvent)
        ));
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

    #[test]
    fn pull_session_compares_membership_before_pulling() {
        let group = GroupIdentity::generate();
        let owner = DeviceIdentity::generate();
        let commit = SignedEvent::create(
            &owner,
            EventSpec {
                group_id: group.group_id(),
                author_sequence: 1,
                causal_parents: &[],
                created_at_unix_ms: 1_800_000_000_000,
                kind: EventKind::MemberAdded,
                protected_payload: b"membership commit",
            },
        )
        .unwrap();
        let mut source = EventStore::in_memory().unwrap();
        let mut target = EventStore::in_memory().unwrap();
        source.put_event(&commit).unwrap();

        let (mut session, request) = PullSession::start(group.group_id());
        assert_eq!(session.membership_comparison(), None);
        let summary = build_authorized_response(&source, &request).unwrap();
        let SyncResponse::Summary { membership, .. } = &summary else {
            panic!("summary request must return membership state");
        };
        assert_eq!(
            membership,
            &SyncMembershipState {
                commits: 1,
                latest_commit: Some(commit.id()),
            }
        );
        session.handle_response(&mut target, &summary).unwrap();
        assert_eq!(
            session.membership_comparison(),
            Some(MembershipComparison::RemoteNewer)
        );

        let (mut reverse, request) = PullSession::start(group.group_id());
        let summary = build_authorized_response(&target, &request).unwrap();
        reverse.handle_response(&mut source, &summary).unwrap();
        assert_eq!(
            reverse.membership_comparison(),
            Some(MembershipComparison::RemoteStale)
        );
    }

    #[test]
    fn membership_comparison_detects_same_and_diverged_heads() {
        let state = |commits, byte| SyncMembershipState {
            commits,
            latest_commit: Some(EventId::from_bytes([byte; 32])),
        };
        assert_eq!(
            MembershipComparison::between(&state(2, 1), &state(2, 1)),
            MembershipComparison::Same
        );
        assert_eq!(
            MembershipComparison::between(&state(2, 1), &state(2, 2)),
            MembershipComparison::Diverged
        );
        assert_eq!(
            MembershipComparison::between(
                &SyncMembershipState::default(),
                &SyncMembershipState::default()
            ),
            MembershipComparison::Same
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
