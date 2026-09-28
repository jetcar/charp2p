#![forbid(unsafe_code)]

//! Durable local persistence for verified CharP2P protocol data.

use std::{
    collections::{BTreeSet, HashMap},
    path::Path,
};

use charp2p_core::{EventError, EventId, PeerId, SignedEvent};
use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;

const SCHEMA_VERSION: i64 = 1;

/// Largest event-identifier page returned for one synchronization request.
pub const MAX_SYNC_BATCH_EVENTS: usize = 256;

/// Highest gap-free event sequence stored for one group author.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorHead {
    /// Device that authored this sequence.
    pub author_id: PeerId,
    /// Highest sequence for which every event from one is present.
    pub contiguous_sequence: u64,
}

/// Result of adding an already-verified event to the local store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PutEventOutcome {
    /// The event was persisted for the first time.
    Inserted,
    /// The exact event was already present.
    AlreadyPresent,
}

/// SQLite-backed storage for signed group events.
pub struct EventStore {
    connection: Connection,
}

impl EventStore {
    /// Opens or creates a store at `path` and applies supported migrations.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::from_connection(Connection::open(path)?)
    }

    /// Creates an isolated in-memory store, primarily for tests and previews.
    pub fn in_memory() -> Result<Self, StoreError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    /// Persists a verified event transactionally.
    ///
    /// Repeating the same event is idempotent. Reusing one author sequence for
    /// different content is rejected.
    pub fn put_event(&mut self, event: &SignedEvent) -> Result<PutEventOutcome, StoreError> {
        let sequence = i64::try_from(event.author_sequence())
            .map_err(|_| StoreError::SequenceTooLarge(event.author_sequence()))?;
        let event_id = event.id();
        let group_id = event.group_id().to_bytes();
        let author_id = event.author_id().to_bytes();
        let encoded = event.encode()?;
        let transaction = self.connection.transaction()?;

        let existing: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT event_id FROM events
                 WHERE group_id = ?1 AND author_id = ?2 AND author_sequence = ?3",
                params![group_id, author_id, sequence],
                |row| row.get(0),
            )
            .optional()?;

        if let Some(existing_id) = existing {
            if existing_id.as_slice() == event_id.as_bytes() {
                transaction.commit()?;
                return Ok(PutEventOutcome::AlreadyPresent);
            }
            return Err(StoreError::SequenceConflict {
                sequence: event.author_sequence(),
            });
        }

        transaction.execute(
            "INSERT INTO events (
                event_id, group_id, author_id, author_sequence, encoded
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                event_id.as_bytes().as_slice(),
                group_id,
                author_id,
                sequence,
                encoded
            ],
        )?;
        transaction.commit()?;
        Ok(PutEventOutcome::Inserted)
    }

    /// Loads and re-verifies an event by its identifier.
    pub fn get_event(&self, event_id: EventId) -> Result<Option<SignedEvent>, StoreError> {
        let encoded: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT encoded FROM events WHERE event_id = ?1",
                [event_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;

        let event = encoded
            .map(|bytes| SignedEvent::decode(&bytes).map_err(StoreError::from))
            .transpose()?;
        if event.as_ref().is_some_and(|event| event.id() != event_id) {
            return Err(StoreError::CorruptIndex);
        }
        Ok(event)
    }

    /// Returns gap-free author heads for compact synchronization comparison.
    pub fn synchronization_summary(&self, group_id: PeerId) -> Result<Vec<AuthorHead>, StoreError> {
        let mut statement = self
            .connection
            .prepare("SELECT encoded FROM events WHERE group_id = ?1")?;
        let encoded = statement.query_map([group_id.to_bytes()], |row| row.get::<_, Vec<u8>>(0))?;
        let mut sequences: HashMap<PeerId, BTreeSet<u64>> = HashMap::new();

        for bytes in encoded {
            let event = SignedEvent::decode(&bytes?)?;
            if event.group_id() != group_id {
                return Err(StoreError::CorruptIndex);
            }
            sequences
                .entry(event.author_id())
                .or_default()
                .insert(event.author_sequence());
        }

        let mut summary: Vec<_> = sequences
            .into_iter()
            .map(|(author_id, sequences)| AuthorHead {
                author_id,
                contiguous_sequence: contiguous_head(&sequences),
            })
            .collect();
        summary.sort_by_key(|head| head.author_id.to_bytes());
        Ok(summary)
    }

    /// Returns an ordered, bounded page of event IDs after an author sequence.
    pub fn event_ids_after(
        &self,
        group_id: PeerId,
        author_id: PeerId,
        after_sequence: u64,
        limit: usize,
    ) -> Result<Vec<EventId>, StoreError> {
        if !(1..=MAX_SYNC_BATCH_EVENTS).contains(&limit) {
            return Err(StoreError::InvalidBatchLimit(limit));
        }
        let Ok(after_sequence) = i64::try_from(after_sequence) else {
            return Ok(Vec::new());
        };

        let mut statement = self.connection.prepare(
            "SELECT encoded FROM events
             WHERE group_id = ?1 AND author_id = ?2 AND author_sequence > ?3
             ORDER BY author_sequence
             LIMIT ?4",
        )?;
        let encoded = statement.query_map(
            params![
                group_id.to_bytes(),
                author_id.to_bytes(),
                after_sequence,
                limit as i64
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        let mut event_ids = Vec::with_capacity(limit);

        for bytes in encoded {
            let event = SignedEvent::decode(&bytes?)?;
            if event.group_id() != group_id
                || event.author_id() != author_id
                || event.author_sequence() <= after_sequence as u64
            {
                return Err(StoreError::CorruptIndex);
            }
            event_ids.push(event.id());
        }
        Ok(event_ids)
    }

    fn from_connection(mut connection: Connection) -> Result<Self, StoreError> {
        connection.pragma_update(None, "foreign_keys", "ON")?;
        let version: i64 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;

        match version {
            0 => {
                let transaction = connection.transaction()?;
                transaction.execute_batch(
                    "CREATE TABLE events (
                        event_id BLOB PRIMARY KEY NOT NULL
                            CHECK(length(event_id) = 32),
                        group_id BLOB NOT NULL,
                        author_id BLOB NOT NULL,
                        author_sequence INTEGER NOT NULL
                            CHECK(author_sequence > 0),
                        encoded BLOB NOT NULL,
                        UNIQUE(group_id, author_id, author_sequence)
                     ) STRICT;

                     CREATE INDEX events_by_group_author_sequence
                        ON events(group_id, author_id, author_sequence);",
                )?;
                transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
                transaction.commit()?;
            }
            SCHEMA_VERSION => {}
            unsupported => return Err(StoreError::UnsupportedSchema(unsupported)),
        }

        Ok(Self { connection })
    }
}

/// Failures produced by local event persistence.
#[derive(Debug, Error)]
pub enum StoreError {
    /// SQLite returned an error.
    #[error("SQLite event store failed")]
    Sqlite(#[from] rusqlite::Error),
    /// A stored or supplied event failed protocol validation.
    #[error("event validation failed")]
    Event(#[from] EventError),
    /// The database was created by an unsupported schema version.
    #[error("unsupported event-store schema version {0}")]
    UnsupportedSchema(i64),
    /// SQLite cannot represent this unsigned author sequence.
    #[error("author sequence {0} exceeds the local-store limit")]
    SequenceTooLarge(u64),
    /// One author attempted to reuse a sequence for different content.
    #[error("author sequence {sequence} is already assigned to another event")]
    SequenceConflict {
        /// Conflicting author sequence.
        sequence: u64,
    },
    /// A synchronization page size is zero or exceeds the protocol bound.
    #[error("invalid synchronization batch limit {0}")]
    InvalidBatchLimit(usize),
    /// Stored index columns disagree with the verified signed envelope.
    #[error("event-store index does not match its signed event")]
    CorruptIndex,
}

fn contiguous_head(sequences: &BTreeSet<u64>) -> u64 {
    sequences
        .iter()
        .copied()
        .zip(1..)
        .take_while(|(actual, expected)| actual == expected)
        .map(|(sequence, _)| sequence)
        .last()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use charp2p_core::{DeviceIdentity, EventKind, EventSpec, GroupIdentity, SignedEvent};
    use rusqlite::params;
    use tempfile::NamedTempFile;

    use super::{AuthorHead, EventStore, MAX_SYNC_BATCH_EVENTS, PutEventOutcome, StoreError};

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

    #[test]
    fn event_survives_closing_and_reopening_the_database() {
        let file = NamedTempFile::new().unwrap();
        let author = DeviceIdentity::generate();
        let group = GroupIdentity::generate();
        let event = message_event(&author, &group, 1, b"protected");

        {
            let mut store = EventStore::open(file.path()).unwrap();
            assert_eq!(store.put_event(&event).unwrap(), PutEventOutcome::Inserted);
        }

        let store = EventStore::open(file.path()).unwrap();
        let loaded = store.get_event(event.id()).unwrap().unwrap();
        assert_eq!(loaded.id(), event.id());
        assert_eq!(loaded.protected_payload(), b"protected");
    }

    #[test]
    fn inserting_the_same_event_is_idempotent() {
        let mut store = EventStore::in_memory().unwrap();
        let event = message_event(
            &DeviceIdentity::generate(),
            &GroupIdentity::generate(),
            1,
            b"protected",
        );

        assert_eq!(store.put_event(&event).unwrap(), PutEventOutcome::Inserted);
        assert_eq!(
            store.put_event(&event).unwrap(),
            PutEventOutcome::AlreadyPresent
        );
    }

    #[test]
    fn reusing_an_author_sequence_for_different_content_is_rejected() {
        let mut store = EventStore::in_memory().unwrap();
        let author = DeviceIdentity::generate();
        let group = GroupIdentity::generate();
        let first = message_event(&author, &group, 1, b"first");
        let conflict = message_event(&author, &group, 1, b"different");

        store.put_event(&first).unwrap();
        assert!(matches!(
            store.put_event(&conflict),
            Err(StoreError::SequenceConflict { sequence: 1 })
        ));
        assert!(store.get_event(first.id()).unwrap().is_some());
        assert!(store.get_event(conflict.id()).unwrap().is_none());
    }

    #[test]
    fn missing_event_returns_none() {
        let store = EventStore::in_memory().unwrap();
        let event = message_event(
            &DeviceIdentity::generate(),
            &GroupIdentity::generate(),
            1,
            b"not stored",
        );

        assert!(store.get_event(event.id()).unwrap().is_none());
    }

    #[test]
    fn summary_reports_only_gap_free_author_sequences() {
        let mut store = EventStore::in_memory().unwrap();
        let group = GroupIdentity::generate();
        let first_author = DeviceIdentity::generate();
        let second_author = DeviceIdentity::generate();
        let first = message_event(&first_author, &group, 1, b"first");
        let missing = message_event(&first_author, &group, 2, b"second");
        let third = message_event(&first_author, &group, 3, b"third");
        let second_author_gap = message_event(&second_author, &group, 2, b"gap");

        store.put_event(&first).unwrap();
        store.put_event(&third).unwrap();
        store.put_event(&second_author_gap).unwrap();

        let mut expected = vec![
            AuthorHead {
                author_id: first_author.peer_id(),
                contiguous_sequence: 1,
            },
            AuthorHead {
                author_id: second_author.peer_id(),
                contiguous_sequence: 0,
            },
        ];
        expected.sort_by_key(|head| head.author_id.to_bytes());
        assert_eq!(
            store.synchronization_summary(group.group_id()).unwrap(),
            expected
        );

        store.put_event(&missing).unwrap();
        let summary = store.synchronization_summary(group.group_id()).unwrap();
        let first_head = summary
            .iter()
            .find(|head| head.author_id == first_author.peer_id())
            .unwrap();
        assert_eq!(first_head.contiguous_sequence, 3);
    }

    #[test]
    fn event_id_pages_are_ordered_bounded_and_group_scoped() {
        let mut store = EventStore::in_memory().unwrap();
        let group = GroupIdentity::generate();
        let other_group = GroupIdentity::generate();
        let author = DeviceIdentity::generate();
        let first = message_event(&author, &group, 1, b"first");
        let second = message_event(&author, &group, 2, b"second");
        let third = message_event(&author, &group, 3, b"third");
        let unrelated = message_event(&author, &other_group, 4, b"unrelated");

        for event in [&third, &unrelated, &first, &second] {
            store.put_event(event).unwrap();
        }

        assert_eq!(
            store
                .event_ids_after(group.group_id(), author.peer_id(), 0, 2)
                .unwrap(),
            vec![first.id(), second.id()]
        );
        assert_eq!(
            store
                .event_ids_after(group.group_id(), author.peer_id(), 1, MAX_SYNC_BATCH_EVENTS,)
                .unwrap(),
            vec![second.id(), third.id()]
        );
        assert!(matches!(
            store.event_ids_after(group.group_id(), author.peer_id(), 0, 0),
            Err(StoreError::InvalidBatchLimit(0))
        ));
    }

    #[test]
    fn stored_event_id_is_checked_against_the_signed_envelope() {
        let mut store = EventStore::in_memory().unwrap();
        let group = GroupIdentity::generate();
        let author = DeviceIdentity::generate();
        let stored = message_event(&author, &group, 1, b"stored");
        let replacement = message_event(&author, &group, 1, b"replacement");
        store.put_event(&stored).unwrap();
        store
            .connection
            .execute(
                "UPDATE events SET encoded = ?1 WHERE event_id = ?2",
                params![
                    replacement.encode().unwrap(),
                    stored.id().as_bytes().as_slice()
                ],
            )
            .unwrap();

        assert!(matches!(
            store.get_event(stored.id()),
            Err(StoreError::CorruptIndex)
        ));
    }
}
