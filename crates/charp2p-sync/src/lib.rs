#![forbid(unsafe_code)]

//! Bounded synchronization orchestration between protocol messages and SQLite.

use charp2p_core::{
    EventError, MAX_SYNC_RESPONSE_BYTES, SignedEvent, SyncError, SyncRequest, SyncResponse,
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
    };
    response.validate()?;
    Ok(response)
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
}

#[cfg(test)]
mod tests {
    use charp2p_core::{
        DeviceIdentity, EventKind, EventSpec, GroupIdentity, SignedEvent, SyncRequest, SyncResponse,
    };
    use charp2p_store::EventStore;

    use super::{ApplyOutcome, apply_response, build_authorized_response};

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
