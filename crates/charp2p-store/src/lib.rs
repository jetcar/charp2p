#![forbid(unsafe_code)]

//! Durable local persistence for verified CharP2P protocol data.

use std::path::Path;

use charp2p_core::{EventError, EventId, SignedEvent};
use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;

const SCHEMA_VERSION: i64 = 1;

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

        encoded
            .map(|bytes| SignedEvent::decode(&bytes).map_err(StoreError::from))
            .transpose()
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
}

#[cfg(test)]
mod tests {
    use charp2p_core::{DeviceIdentity, EventKind, EventSpec, GroupIdentity, SignedEvent};
    use tempfile::NamedTempFile;

    use super::{EventStore, PutEventOutcome, StoreError};

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
}
