#![forbid(unsafe_code)]

//! Durable local persistence for verified CharP2P protocol data.

use std::{
    collections::{BTreeSet, HashMap},
    path::Path,
    time::Duration,
};

use charp2p_core::{
    EventError, EventId, HistoryPolicy, InvitationId, PeerId, SignedEvent,
    MAX_JOIN_MLS_MESSAGE_BYTES, MAX_SYNC_BATCH_ITEMS,
};
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use thiserror::Error;

pub use charp2p_core::SyncAuthorHead as AuthorHead;

const SCHEMA_VERSION: i64 = 8;

/// Largest authenticated ciphertext accepted for one MLS provider snapshot.
pub const MAX_ENCRYPTED_MLS_PROVIDER_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024 + 128;
/// Largest locally encrypted body for one materialized text message.
pub const MAX_ENCRYPTED_MESSAGE_BODY_BYTES: usize = 16 * 1024 + 42;
/// Largest recent-message page exposed to an application view.
pub const MAX_RECENT_MESSAGE_EVENTS: usize = 256;

/// Non-secret local metadata for a group owned by this device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LocalGroupMetadata {
    pub group_id: PeerId,
    pub group_name: String,
    pub icon: u8,
    pub history_policy: HistoryPolicy,
    pub approval_required: bool,
    pub invitation_lifetime_seconds: u64,
    pub reusable_invitation: bool,
}

/// Non-secret metadata for an invitation waiting for a reachable group peer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingInvitationMetadata {
    /// Stable identifier derived from the group root public key.
    pub group_id: PeerId,
    /// Authenticated group display name.
    pub group_name: String,
    /// Authenticated inviter display name.
    pub inviter_name: String,
    /// Invitation expiry as a Unix timestamp.
    pub expires_at_unix: u64,
    /// History access granted by the invitation.
    pub history_policy: HistoryPolicy,
    /// Whether the invitation may authorize multiple memberships.
    pub reusable: bool,
}

/// Non-secret display metadata for a group joined by this device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JoinedGroupMetadata {
    pub group_id: PeerId,
    pub group_name: String,
    pub inviter_name: String,
    pub inviter_device_id: PeerId,
    pub history_policy: HistoryPolicy,
}

/// Bounded page of locally materialized encrypted messages.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedMessagePage {
    pub messages: Vec<EncryptedMessage>,
    pub has_earlier: bool,
}

/// Non-secret index for a bearer invitation issued by a locally owned group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuedInvitationMetadata {
    pub invitation_id: InvitationId,
    pub group_id: PeerId,
    pub expires_at_unix: u64,
}

/// Largest event-identifier page returned for one synchronization request.
pub const MAX_SYNC_BATCH_EVENTS: usize = MAX_SYNC_BATCH_ITEMS;

/// Result of adding an already-verified event to the local store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PutEventOutcome {
    /// The event was persisted for the first time.
    Inserted,
    /// The exact event was already present.
    AlreadyPresent,
}

/// Result of transactionally adding a batch of verified events.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PutEventsOutcome {
    /// Events persisted for the first time.
    pub inserted: usize,
    /// Exact events already present.
    pub already_present: usize,
}

/// One locally materialized message whose body remains application-encrypted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedMessage {
    pub event_id: [u8; 32],
    pub group_id: PeerId,
    pub author_id: PeerId,
    pub created_at_unix_ms: u64,
    pub encrypted_body: Vec<u8>,
}

/// SQLite-backed storage for signed events and non-secret application metadata.
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
        let transaction = self.connection.transaction()?;
        let outcome = put_event_in_transaction(&transaction, event)?;
        transaction.commit()?;
        Ok(outcome)
    }

    /// Persists a batch atomically after checking every author sequence.
    pub fn put_events(&mut self, events: &[SignedEvent]) -> Result<PutEventsOutcome, StoreError> {
        let transaction = self.connection.transaction()?;
        let mut outcome = PutEventsOutcome::default();

        for event in events {
            match put_event_in_transaction(&transaction, event)? {
                PutEventOutcome::Inserted => outcome.inserted += 1,
                PutEventOutcome::AlreadyPresent => outcome.already_present += 1,
            }
        }

        transaction.commit()?;
        Ok(outcome)
    }

    /// Atomically persists one verified event and the MLS provider state that
    /// results from applying it.
    pub fn put_event_and_encrypted_mls_provider_snapshot(
        &mut self,
        event: &SignedEvent,
        encrypted: &[u8],
    ) -> Result<PutEventOutcome, StoreError> {
        validate_encrypted_mls_provider_snapshot(encrypted)?;
        let transaction = self.connection.transaction()?;
        let outcome = put_event_in_transaction(&transaction, event)?;
        put_encrypted_mls_provider_snapshot_in_transaction(&transaction, encrypted)?;
        transaction.commit()?;
        Ok(outcome)
    }

    /// Atomically persists a protected message event, advanced MLS state, and
    /// its locally encrypted display body.
    pub fn put_message_and_encrypted_mls_provider_snapshot(
        &mut self,
        event: &SignedEvent,
        encrypted_snapshot: &[u8],
        encrypted_body: &[u8],
    ) -> Result<PutEventOutcome, StoreError> {
        if event.kind() != charp2p_core::EventKind::MessageCreated {
            return Err(StoreError::InvalidMessageEvent);
        }
        validate_encrypted_mls_provider_snapshot(encrypted_snapshot)?;
        validate_encrypted_message_body(encrypted_body)?;
        let created_at = i64::try_from(event.created_at_unix_ms())
            .map_err(|_| StoreError::TimestampTooLarge(event.created_at_unix_ms()))?;
        let transaction = self.connection.transaction()?;
        let outcome = put_event_in_transaction(&transaction, event)?;
        put_encrypted_mls_provider_snapshot_in_transaction(&transaction, encrypted_snapshot)?;
        transaction.execute(
            "INSERT INTO materialized_messages (
                event_id, group_id, author_id, created_at_unix_ms, encrypted_body
             ) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(event_id) DO NOTHING",
            params![
                event.id().as_bytes().as_slice(),
                event.group_id().to_bytes(),
                event.author_id().to_bytes(),
                created_at,
                encrypted_body,
            ],
        )?;
        transaction.commit()?;
        Ok(outcome)
    }

    /// Lists locally materialized messages in stable display order.
    pub fn encrypted_messages(&self, group_id: PeerId) -> Result<EncryptedMessagePage, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT e.encoded, m.group_id, m.author_id, m.created_at_unix_ms,
                    m.encrypted_body
             FROM materialized_messages m
             JOIN events e ON e.event_id = m.event_id
             WHERE m.group_id = ?1
             ORDER BY m.created_at_unix_ms DESC, m.event_id DESC
             LIMIT ?2",
        )?;
        let rows = statement.query_map(
            params![group_id.to_bytes(), (MAX_RECENT_MESSAGE_EVENTS + 1) as i64],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Vec<u8>>(4)?,
                ))
            },
        )?;
        let mut messages = Vec::with_capacity(MAX_RECENT_MESSAGE_EVENTS + 1);
        for row in rows {
            let (encoded, stored_group, stored_author, stored_created_at, encrypted_body) = row?;
            let event = SignedEvent::decode(&encoded)?;
            let created_at_unix_ms =
                u64::try_from(stored_created_at).map_err(|_| StoreError::CorruptIndex)?;
            validate_encrypted_message_body(&encrypted_body)?;
            if event.kind() != charp2p_core::EventKind::MessageCreated
                || event.group_id() != group_id
                || event.group_id().to_bytes() != stored_group
                || event.author_id().to_bytes() != stored_author
                || event.created_at_unix_ms() != created_at_unix_ms
            {
                return Err(StoreError::CorruptIndex);
            }
            messages.push(EncryptedMessage {
                event_id: *event.id().as_bytes(),
                group_id,
                author_id: event.author_id(),
                created_at_unix_ms,
                encrypted_body,
            });
        }
        let has_earlier = messages.len() > MAX_RECENT_MESSAGE_EVENTS;
        messages.truncate(MAX_RECENT_MESSAGE_EVENTS);
        messages.reverse();
        Ok(EncryptedMessagePage {
            messages,
            has_earlier,
        })
    }

    /// Returns at most `limit` verified message events that do not yet have a
    /// local materialized body. Events are ordered by author and sequence so
    /// each sender ratchet advances consistently.
    pub fn unmaterialized_message_events(
        &self,
        group_id: PeerId,
        limit: usize,
    ) -> Result<Vec<SignedEvent>, StoreError> {
        if !(1..=MAX_SYNC_BATCH_EVENTS).contains(&limit) {
            return Err(StoreError::InvalidBatchLimit(limit));
        }
        let mut statement = self.connection.prepare(
            "SELECT e.encoded
             FROM events e
             LEFT JOIN materialized_messages m ON m.event_id = e.event_id
             WHERE e.group_id = ?1 AND m.event_id IS NULL
             ORDER BY e.author_id, e.author_sequence",
        )?;
        let rows = statement.query_map([group_id.to_bytes()], |row| row.get::<_, Vec<u8>>(0))?;
        let mut events = Vec::with_capacity(limit);
        for encoded in rows {
            let event = SignedEvent::decode(&encoded?)?;
            if event.group_id() != group_id {
                return Err(StoreError::CorruptIndex);
            }
            if event.kind() == charp2p_core::EventKind::MessageCreated {
                events.push(event);
                if events.len() == limit {
                    break;
                }
            }
        }
        Ok(events)
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

    /// Adds or refreshes non-secret metadata for one pending invitation.
    pub fn put_pending_invitation(
        &mut self,
        pending: &PendingInvitationMetadata,
    ) -> Result<(), StoreError> {
        let expires_at_unix = i64::try_from(pending.expires_at_unix)
            .map_err(|_| StoreError::TimestampTooLarge(pending.expires_at_unix))?;
        self.connection.execute(
            "INSERT INTO pending_invitations (
                group_id, group_name, inviter_name, expires_at_unix,
                history_policy, reusable
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(group_id) DO UPDATE SET
                group_name = excluded.group_name,
                inviter_name = excluded.inviter_name,
                expires_at_unix = excluded.expires_at_unix,
                history_policy = excluded.history_policy,
                reusable = excluded.reusable",
            params![
                pending.group_id.to_bytes(),
                pending.group_name,
                pending.inviter_name,
                expires_at_unix,
                history_policy_code(pending.history_policy),
                pending.reusable
            ],
        )?;
        Ok(())
    }

    /// Lists pending invitations without exposing their bearer credentials.
    pub fn pending_invitations(&self) -> Result<Vec<PendingInvitationMetadata>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT group_id, group_name, inviter_name, expires_at_unix,
                    history_policy, reusable
             FROM pending_invitations
             ORDER BY group_name, group_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, bool>(5)?,
            ))
        })?;
        let mut pending = Vec::new();

        for row in rows {
            let (group_id, group_name, inviter_name, expires_at_unix, history_policy, reusable) =
                row?;
            pending.push(PendingInvitationMetadata {
                group_id: PeerId::from_bytes(&group_id).map_err(|_| StoreError::CorruptIndex)?,
                group_name,
                inviter_name,
                expires_at_unix: u64::try_from(expires_at_unix)
                    .map_err(|_| StoreError::CorruptIndex)?,
                history_policy: history_policy_from_code(history_policy)?,
                reusable,
            });
        }
        Ok(pending)
    }

    /// Removes a pending invitation after joining or cancellation.
    pub fn remove_pending_invitation(&mut self, group_id: PeerId) -> Result<bool, StoreError> {
        Ok(self.connection.execute(
            "DELETE FROM pending_invitations WHERE group_id = ?1",
            [group_id.to_bytes()],
        )? != 0)
    }

    /// Atomically turns a pending invitation into durable joined-group display
    /// metadata without retaining the bearer credential in SQLite.
    pub fn promote_pending_invitation_to_joined_group(
        &mut self,
        group_id: PeerId,
        inviter_device_id: PeerId,
    ) -> Result<bool, StoreError> {
        let transaction = self.connection.transaction()?;
        let pending = pending_invitation_in_transaction(&transaction, group_id)?;
        let Some(pending) = pending else {
            let exists = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM joined_groups WHERE group_id = ?1)",
                [group_id.to_bytes()],
                |row| row.get::<_, bool>(0),
            )?;
            transaction.commit()?;
            return Ok(exists);
        };
        transaction.execute(
            "INSERT INTO joined_groups (
                group_id, group_name, inviter_name, inviter_device_id, history_policy
             ) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(group_id) DO UPDATE SET
                group_name = excluded.group_name,
                inviter_name = excluded.inviter_name,
                inviter_device_id = excluded.inviter_device_id,
                history_policy = excluded.history_policy",
            params![
                pending.group_id.to_bytes(),
                pending.group_name,
                pending.inviter_name,
                inviter_device_id.to_bytes(),
                history_policy_code(pending.history_policy),
            ],
        )?;
        transaction.execute(
            "DELETE FROM pending_invitations WHERE group_id = ?1",
            [group_id.to_bytes()],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    /// Lists durable metadata for groups joined by this device.
    pub fn joined_groups(&self) -> Result<Vec<JoinedGroupMetadata>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT group_id, group_name, inviter_name, inviter_device_id, history_policy
             FROM joined_groups
             ORDER BY group_name, group_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, Vec<u8>>(3)?,
                row.get::<_, i64>(4)?,
            ))
        })?;
        let mut groups = Vec::new();
        for row in rows {
            let (group_id, group_name, inviter_name, inviter_device_id, history_policy) = row?;
            groups.push(JoinedGroupMetadata {
                group_id: PeerId::from_bytes(&group_id).map_err(|_| StoreError::CorruptIndex)?,
                group_name,
                inviter_name,
                inviter_device_id: PeerId::from_bytes(&inviter_device_id)
                    .map_err(|_| StoreError::CorruptIndex)?,
                history_policy: history_policy_from_code(history_policy)?,
            });
        }
        Ok(groups)
    }

    /// Adds the non-secret index for a newly issued bearer invitation.
    pub fn put_issued_invitation(
        &mut self,
        invitation: &IssuedInvitationMetadata,
    ) -> Result<(), StoreError> {
        let expires_at_unix = i64::try_from(invitation.expires_at_unix)
            .map_err(|_| StoreError::TimestampTooLarge(invitation.expires_at_unix))?;
        self.connection.execute(
            "INSERT INTO issued_invitations (invitation_id, group_id, expires_at_unix)
             VALUES (?1, ?2, ?3)",
            params![
                invitation.invitation_id.as_bytes().as_slice(),
                invitation.group_id.to_bytes(),
                expires_at_unix,
            ],
        )?;
        Ok(())
    }

    /// Lists issued invitation indexes without exposing their bearer secrets.
    pub fn issued_invitations(&self) -> Result<Vec<IssuedInvitationMetadata>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT invitation_id, group_id, expires_at_unix
             FROM issued_invitations
             ORDER BY expires_at_unix DESC, invitation_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        let mut invitations = Vec::new();
        for row in rows {
            let (invitation_id, group_id, expires_at_unix) = row?;
            let invitation_id: [u8; 16] = invitation_id
                .try_into()
                .map_err(|_| StoreError::CorruptIndex)?;
            invitations.push(IssuedInvitationMetadata {
                invitation_id: InvitationId::from_bytes(invitation_id),
                group_id: PeerId::from_bytes(&group_id).map_err(|_| StoreError::CorruptIndex)?,
                expires_at_unix: u64::try_from(expires_at_unix)
                    .map_err(|_| StoreError::CorruptIndex)?,
            });
        }
        Ok(invitations)
    }

    /// Removes an issued invitation index after expiry or revocation.
    pub fn remove_issued_invitation(
        &mut self,
        invitation_id: InvitationId,
    ) -> Result<bool, StoreError> {
        Ok(self.connection.execute(
            "DELETE FROM issued_invitations WHERE invitation_id = ?1",
            [invitation_id.as_bytes().as_slice()],
        )? != 0)
    }

    /// Persists the non-secret settings for a locally owned group.
    pub fn put_local_group(&mut self, group: &LocalGroupMetadata) -> Result<(), StoreError> {
        let lifetime = i64::try_from(group.invitation_lifetime_seconds)
            .map_err(|_| StoreError::TimestampTooLarge(group.invitation_lifetime_seconds))?;
        self.connection.execute(
            "INSERT INTO local_groups (
                group_id, group_name, icon, history_policy, approval_required,
                invitation_lifetime_seconds, reusable_invitation
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(group_id) DO UPDATE SET
                group_name = excluded.group_name,
                icon = excluded.icon,
                history_policy = excluded.history_policy,
                approval_required = excluded.approval_required,
                invitation_lifetime_seconds = excluded.invitation_lifetime_seconds,
                reusable_invitation = excluded.reusable_invitation",
            params![
                group.group_id.to_bytes(),
                group.group_name,
                i64::from(group.icon),
                history_policy_code(group.history_policy),
                group.approval_required,
                lifetime,
                group.reusable_invitation,
            ],
        )?;
        Ok(())
    }

    /// Lists locally owned group metadata without exposing root keys.
    pub fn local_groups(&self) -> Result<Vec<LocalGroupMetadata>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT group_id, group_name, icon, history_policy, approval_required,
                    invitation_lifetime_seconds, reusable_invitation
             FROM local_groups
             ORDER BY group_name, group_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, bool>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, bool>(6)?,
            ))
        })?;
        let mut groups = Vec::new();
        for row in rows {
            let (group_id, group_name, icon, history_policy, approval_required, lifetime, reusable) =
                row?;
            groups.push(LocalGroupMetadata {
                group_id: PeerId::from_bytes(&group_id).map_err(|_| StoreError::CorruptIndex)?,
                group_name,
                icon: u8::try_from(icon).map_err(|_| StoreError::CorruptIndex)?,
                history_policy: history_policy_from_code(history_policy)?,
                approval_required,
                invitation_lifetime_seconds: u64::try_from(lifetime)
                    .map_err(|_| StoreError::CorruptIndex)?,
                reusable_invitation: reusable,
            });
        }
        Ok(groups)
    }

    /// Removes local metadata when protected root creation did not complete.
    pub fn remove_local_group(&mut self, group_id: PeerId) -> Result<bool, StoreError> {
        Ok(self.connection.execute(
            "DELETE FROM local_groups WHERE group_id = ?1",
            [group_id.to_bytes()],
        )? != 0)
    }

    /// Atomically replaces the encrypted MLS provider snapshot.
    pub fn put_encrypted_mls_provider_snapshot(
        &mut self,
        encrypted: &[u8],
    ) -> Result<(), StoreError> {
        validate_encrypted_mls_provider_snapshot(encrypted)?;
        self.connection.execute(
            "INSERT INTO mls_provider_snapshot (singleton, encrypted)
             VALUES (1, ?1)
             ON CONFLICT(singleton) DO UPDATE SET encrypted = excluded.encrypted",
            [encrypted],
        )?;
        Ok(())
    }

    /// Loads the encrypted MLS provider snapshot without interpreting secrets.
    pub fn encrypted_mls_provider_snapshot(&self) -> Result<Option<Vec<u8>>, StoreError> {
        let encrypted: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT encrypted FROM mls_provider_snapshot WHERE singleton = 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        if encrypted.as_ref().is_some_and(|encrypted| {
            encrypted.is_empty() || encrypted.len() > MAX_ENCRYPTED_MLS_PROVIDER_SNAPSHOT_BYTES
        }) {
            return Err(StoreError::CorruptIndex);
        }
        Ok(encrypted)
    }

    /// Loads the public one-time KeyPackage retained for a pending join.
    pub fn pending_mls_join_key_package(
        &self,
        group_id: PeerId,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        let encoded: Option<Vec<u8>> = self
            .connection
            .query_row(
                "SELECT key_package FROM pending_mls_joins WHERE group_id = ?1",
                [group_id.to_bytes()],
                |row| row.get(0),
            )
            .optional()?;
        if encoded
            .as_ref()
            .is_some_and(|encoded| encoded.is_empty() || encoded.len() > MAX_JOIN_MLS_MESSAGE_BYTES)
        {
            return Err(StoreError::CorruptIndex);
        }
        Ok(encoded)
    }

    /// Atomically retains one public KeyPackage and the provider state holding
    /// its matching private material.
    pub fn put_pending_mls_join_and_encrypted_mls_provider_snapshot(
        &mut self,
        group_id: PeerId,
        key_package: &[u8],
        encrypted: &[u8],
    ) -> Result<(), StoreError> {
        validate_mls_key_package(key_package)?;
        validate_encrypted_mls_provider_snapshot(encrypted)?;
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO pending_mls_joins (group_id, key_package)
             VALUES (?1, ?2)
             ON CONFLICT(group_id) DO UPDATE SET key_package = excluded.key_package",
            params![group_id.to_bytes(), key_package],
        )?;
        put_encrypted_mls_provider_snapshot_in_transaction(&transaction, encrypted)?;
        transaction.commit()?;
        Ok(())
    }

    /// Atomically removes a completed pending join and stores the provider
    /// state containing the joined MLS group.
    pub fn remove_pending_mls_join_and_put_encrypted_mls_provider_snapshot(
        &mut self,
        group_id: PeerId,
        encrypted: &[u8],
    ) -> Result<bool, StoreError> {
        validate_encrypted_mls_provider_snapshot(encrypted)?;
        let transaction = self.connection.transaction()?;
        let removed = transaction.execute(
            "DELETE FROM pending_mls_joins WHERE group_id = ?1",
            [group_id.to_bytes()],
        )? != 0;
        if !removed {
            return Ok(false);
        }
        put_encrypted_mls_provider_snapshot_in_transaction(&transaction, encrypted)?;
        transaction.commit()?;
        Ok(true)
    }

    fn from_connection(mut connection: Connection) -> Result<Self, StoreError> {
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.busy_timeout(Duration::from_secs(5))?;
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
                        ON events(group_id, author_id, author_sequence);

                     CREATE TABLE pending_invitations (
                        group_id BLOB PRIMARY KEY NOT NULL,
                        group_name TEXT NOT NULL,
                        inviter_name TEXT NOT NULL,
                        expires_at_unix INTEGER NOT NULL CHECK(expires_at_unix > 0),
                        history_policy INTEGER NOT NULL CHECK(history_policy BETWEEN 0 AND 2),
                        reusable INTEGER NOT NULL CHECK(reusable IN (0, 1))
                     ) STRICT;

                     CREATE TABLE local_groups (
                        group_id BLOB PRIMARY KEY NOT NULL,
                        group_name TEXT NOT NULL,
                        icon INTEGER NOT NULL CHECK(icon BETWEEN 0 AND 4),
                        history_policy INTEGER NOT NULL CHECK(history_policy BETWEEN 0 AND 2),
                        approval_required INTEGER NOT NULL CHECK(approval_required IN (0, 1)),
                        invitation_lifetime_seconds INTEGER NOT NULL
                            CHECK(invitation_lifetime_seconds > 0),
                        reusable_invitation INTEGER NOT NULL
                            CHECK(reusable_invitation IN (0, 1))
                     ) STRICT;

                     CREATE TABLE issued_invitations (
                        invitation_id BLOB PRIMARY KEY NOT NULL
                            CHECK(length(invitation_id) = 16),
                        group_id BLOB NOT NULL,
                        expires_at_unix INTEGER NOT NULL CHECK(expires_at_unix > 0)
                     ) STRICT;

                     CREATE TABLE mls_provider_snapshot (
                        singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
                        encrypted BLOB NOT NULL
                            CHECK(length(encrypted) BETWEEN 1 AND 8388736)
                     ) STRICT;

                     CREATE TABLE pending_mls_joins (
                        group_id BLOB PRIMARY KEY NOT NULL,
                        key_package BLOB NOT NULL
                            CHECK(length(key_package) BETWEEN 1 AND 131072)
                     ) STRICT;",
                )?;
                transaction.pragma_update(None, "user_version", 6)?;
                transaction.commit()?;
            }
            1 => {
                let transaction = connection.transaction()?;
                transaction.execute_batch(
                    "CREATE TABLE pending_invitations (
                        group_id BLOB PRIMARY KEY NOT NULL,
                        group_name TEXT NOT NULL,
                        inviter_name TEXT NOT NULL,
                        expires_at_unix INTEGER NOT NULL CHECK(expires_at_unix > 0),
                        history_policy INTEGER NOT NULL CHECK(history_policy BETWEEN 0 AND 2),
                        reusable INTEGER NOT NULL CHECK(reusable IN (0, 1))
                     ) STRICT;

                     CREATE TABLE local_groups (
                        group_id BLOB PRIMARY KEY NOT NULL,
                        group_name TEXT NOT NULL,
                        icon INTEGER NOT NULL CHECK(icon BETWEEN 0 AND 4),
                        history_policy INTEGER NOT NULL CHECK(history_policy BETWEEN 0 AND 2),
                        approval_required INTEGER NOT NULL CHECK(approval_required IN (0, 1)),
                        invitation_lifetime_seconds INTEGER NOT NULL
                            CHECK(invitation_lifetime_seconds > 0),
                        reusable_invitation INTEGER NOT NULL
                            CHECK(reusable_invitation IN (0, 1))
                     ) STRICT;

                     CREATE TABLE issued_invitations (
                        invitation_id BLOB PRIMARY KEY NOT NULL
                            CHECK(length(invitation_id) = 16),
                        group_id BLOB NOT NULL,
                        expires_at_unix INTEGER NOT NULL CHECK(expires_at_unix > 0)
                     ) STRICT;

                     CREATE TABLE mls_provider_snapshot (
                        singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
                        encrypted BLOB NOT NULL
                            CHECK(length(encrypted) BETWEEN 1 AND 8388736)
                     ) STRICT;

                     CREATE TABLE pending_mls_joins (
                        group_id BLOB PRIMARY KEY NOT NULL,
                        key_package BLOB NOT NULL
                            CHECK(length(key_package) BETWEEN 1 AND 131072)
                     ) STRICT;",
                )?;
                transaction.pragma_update(None, "user_version", 6)?;
                transaction.commit()?;
            }
            2 => {
                let transaction = connection.transaction()?;
                transaction.execute_batch(
                    "CREATE TABLE local_groups (
                        group_id BLOB PRIMARY KEY NOT NULL,
                        group_name TEXT NOT NULL,
                        icon INTEGER NOT NULL CHECK(icon BETWEEN 0 AND 4),
                        history_policy INTEGER NOT NULL CHECK(history_policy BETWEEN 0 AND 2),
                        approval_required INTEGER NOT NULL CHECK(approval_required IN (0, 1)),
                        invitation_lifetime_seconds INTEGER NOT NULL
                            CHECK(invitation_lifetime_seconds > 0),
                        reusable_invitation INTEGER NOT NULL
                            CHECK(reusable_invitation IN (0, 1))
                     ) STRICT;

                     CREATE TABLE issued_invitations (
                        invitation_id BLOB PRIMARY KEY NOT NULL
                            CHECK(length(invitation_id) = 16),
                        group_id BLOB NOT NULL,
                        expires_at_unix INTEGER NOT NULL CHECK(expires_at_unix > 0)
                     ) STRICT;

                     CREATE TABLE mls_provider_snapshot (
                        singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
                        encrypted BLOB NOT NULL
                            CHECK(length(encrypted) BETWEEN 1 AND 8388736)
                     ) STRICT;

                     CREATE TABLE pending_mls_joins (
                        group_id BLOB PRIMARY KEY NOT NULL,
                        key_package BLOB NOT NULL
                            CHECK(length(key_package) BETWEEN 1 AND 131072)
                     ) STRICT;",
                )?;
                transaction.pragma_update(None, "user_version", 6)?;
                transaction.commit()?;
            }
            3 => {
                let transaction = connection.transaction()?;
                transaction.execute_batch(
                    "CREATE TABLE issued_invitations (
                        invitation_id BLOB PRIMARY KEY NOT NULL
                            CHECK(length(invitation_id) = 16),
                        group_id BLOB NOT NULL,
                        expires_at_unix INTEGER NOT NULL CHECK(expires_at_unix > 0)
                     ) STRICT;

                     CREATE TABLE mls_provider_snapshot (
                        singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
                        encrypted BLOB NOT NULL
                            CHECK(length(encrypted) BETWEEN 1 AND 8388736)
                     ) STRICT;

                     CREATE TABLE pending_mls_joins (
                        group_id BLOB PRIMARY KEY NOT NULL,
                        key_package BLOB NOT NULL
                            CHECK(length(key_package) BETWEEN 1 AND 131072)
                     ) STRICT;",
                )?;
                transaction.pragma_update(None, "user_version", 6)?;
                transaction.commit()?;
            }
            4 => {
                let transaction = connection.transaction()?;
                transaction.execute_batch(
                    "CREATE TABLE mls_provider_snapshot (
                        singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
                        encrypted BLOB NOT NULL
                            CHECK(length(encrypted) BETWEEN 1 AND 8388736)
                     ) STRICT;

                     CREATE TABLE pending_mls_joins (
                        group_id BLOB PRIMARY KEY NOT NULL,
                        key_package BLOB NOT NULL
                            CHECK(length(key_package) BETWEEN 1 AND 131072)
                     ) STRICT;",
                )?;
                transaction.pragma_update(None, "user_version", 6)?;
                transaction.commit()?;
            }
            5 => {
                let transaction = connection.transaction()?;
                transaction.execute_batch(
                    "CREATE TABLE pending_mls_joins (
                        group_id BLOB PRIMARY KEY NOT NULL,
                        key_package BLOB NOT NULL
                            CHECK(length(key_package) BETWEEN 1 AND 131072)
                     ) STRICT;",
                )?;
                transaction.pragma_update(None, "user_version", 6)?;
                transaction.commit()?;
            }
            6 | 7 => {}
            SCHEMA_VERSION => {}
            unsupported => return Err(StoreError::UnsupportedSchema(unsupported)),
        }

        if version <= 6 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE joined_groups (
                    group_id BLOB PRIMARY KEY NOT NULL,
                    group_name TEXT NOT NULL,
                    inviter_name TEXT NOT NULL,
                    inviter_device_id BLOB NOT NULL,
                    history_policy INTEGER NOT NULL CHECK(history_policy BETWEEN 0 AND 2)
                 ) STRICT;",
            )?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.commit()?;
        }

        if version <= 7 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE materialized_messages (
                    event_id BLOB PRIMARY KEY NOT NULL
                        CHECK(length(event_id) = 32)
                        REFERENCES events(event_id) ON DELETE CASCADE,
                    group_id BLOB NOT NULL,
                    author_id BLOB NOT NULL,
                    created_at_unix_ms INTEGER NOT NULL
                        CHECK(created_at_unix_ms >= 0),
                    encrypted_body BLOB NOT NULL
                        CHECK(length(encrypted_body) BETWEEN 1 AND 16426)
                 ) STRICT;

                 CREATE INDEX materialized_messages_by_group_time
                    ON materialized_messages(group_id, created_at_unix_ms, event_id);",
            )?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.commit()?;
        }

        Ok(Self { connection })
    }
}

fn validate_encrypted_mls_provider_snapshot(encrypted: &[u8]) -> Result<(), StoreError> {
    if encrypted.is_empty() || encrypted.len() > MAX_ENCRYPTED_MLS_PROVIDER_SNAPSHOT_BYTES {
        return Err(StoreError::InvalidMlsProviderSnapshotSize(encrypted.len()));
    }
    Ok(())
}

fn validate_encrypted_message_body(encrypted: &[u8]) -> Result<(), StoreError> {
    if encrypted.is_empty() || encrypted.len() > MAX_ENCRYPTED_MESSAGE_BODY_BYTES {
        return Err(StoreError::InvalidEncryptedMessageSize(encrypted.len()));
    }
    Ok(())
}

fn validate_mls_key_package(encoded: &[u8]) -> Result<(), StoreError> {
    if encoded.is_empty() || encoded.len() > MAX_JOIN_MLS_MESSAGE_BYTES {
        return Err(StoreError::InvalidMlsKeyPackageSize(encoded.len()));
    }
    Ok(())
}

fn put_encrypted_mls_provider_snapshot_in_transaction(
    transaction: &Transaction<'_>,
    encrypted: &[u8],
) -> Result<(), StoreError> {
    transaction.execute(
        "INSERT INTO mls_provider_snapshot (singleton, encrypted)
         VALUES (1, ?1)
         ON CONFLICT(singleton) DO UPDATE SET encrypted = excluded.encrypted",
        [encrypted],
    )?;
    Ok(())
}

fn pending_invitation_in_transaction(
    transaction: &Transaction<'_>,
    group_id: PeerId,
) -> Result<Option<PendingInvitationMetadata>, StoreError> {
    let row = transaction
        .query_row(
            "SELECT group_id, group_name, inviter_name, expires_at_unix,
                    history_policy, reusable
             FROM pending_invitations WHERE group_id = ?1",
            [group_id.to_bytes()],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, bool>(5)?,
                ))
            },
        )
        .optional()?;
    row.map(
        |(stored_group_id, group_name, inviter_name, expires_at_unix, history_policy, reusable)| {
            Ok(PendingInvitationMetadata {
                group_id: PeerId::from_bytes(&stored_group_id)
                    .map_err(|_| StoreError::CorruptIndex)?,
                group_name,
                inviter_name,
                expires_at_unix: u64::try_from(expires_at_unix)
                    .map_err(|_| StoreError::CorruptIndex)?,
                history_policy: history_policy_from_code(history_policy)?,
                reusable,
            })
        },
    )
    .transpose()
}

fn history_policy_code(policy: HistoryPolicy) -> i64 {
    match policy {
        HistoryPolicy::None => 0,
        HistoryPolicy::FromInvitation => 1,
        HistoryPolicy::AllRetained => 2,
    }
}

fn history_policy_from_code(code: i64) -> Result<HistoryPolicy, StoreError> {
    match code {
        0 => Ok(HistoryPolicy::None),
        1 => Ok(HistoryPolicy::FromInvitation),
        2 => Ok(HistoryPolicy::AllRetained),
        _ => Err(StoreError::CorruptIndex),
    }
}

fn put_event_in_transaction(
    transaction: &Transaction<'_>,
    event: &SignedEvent,
) -> Result<PutEventOutcome, StoreError> {
    let sequence = i64::try_from(event.author_sequence())
        .map_err(|_| StoreError::SequenceTooLarge(event.author_sequence()))?;
    let event_id = event.id();
    let group_id = event.group_id().to_bytes();
    let author_id = event.author_id().to_bytes();
    let encoded = event.encode()?;
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
    Ok(PutEventOutcome::Inserted)
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
    /// SQLite cannot represent this unsigned timestamp.
    #[error("timestamp {0} exceeds the local-store limit")]
    TimestampTooLarge(u64),
    /// One author attempted to reuse a sequence for different content.
    #[error("author sequence {sequence} is already assigned to another event")]
    SequenceConflict {
        /// Conflicting author sequence.
        sequence: u64,
    },
    /// A synchronization page size is zero or exceeds the protocol bound.
    #[error("invalid synchronization batch limit {0}")]
    InvalidBatchLimit(usize),
    /// The encrypted MLS provider snapshot is empty or above the local bound.
    #[error("invalid encrypted MLS provider snapshot size {0}")]
    InvalidMlsProviderSnapshotSize(usize),
    /// A pending join KeyPackage is empty or above the protocol bound.
    #[error("invalid pending MLS KeyPackage size {0}")]
    InvalidMlsKeyPackageSize(usize),
    /// A local encrypted message body is empty or above the application bound.
    #[error("invalid encrypted message body size {0}")]
    InvalidEncryptedMessageSize(usize),
    /// Only a signed message-creation event can materialize a message body.
    #[error("event is not a message creation")]
    InvalidMessageEvent,
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
    use charp2p_core::{
        DeviceIdentity, EventKind, EventSpec, GroupIdentity, HistoryPolicy, InvitationId,
        SignedEvent, MAX_JOIN_MLS_MESSAGE_BYTES,
    };
    use rusqlite::{params, Connection};
    use tempfile::NamedTempFile;

    use super::{
        AuthorHead, EventStore, IssuedInvitationMetadata, JoinedGroupMetadata, LocalGroupMetadata,
        PendingInvitationMetadata, PutEventOutcome, StoreError, MAX_ENCRYPTED_MESSAGE_BODY_BYTES,
        MAX_ENCRYPTED_MLS_PROVIDER_SNAPSHOT_BYTES, MAX_SYNC_BATCH_EVENTS,
    };

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

    #[test]
    fn conflicting_batch_rolls_back_every_new_event() {
        let mut store = EventStore::in_memory().unwrap();
        let group = GroupIdentity::generate();
        let author = DeviceIdentity::generate();
        let first = message_event(&author, &group, 1, b"first");
        let second = message_event(&author, &group, 2, b"second");
        let conflict = message_event(&author, &group, 1, b"conflict");
        store.put_event(&first).unwrap();

        assert!(matches!(
            store.put_events(&[second, conflict]),
            Err(StoreError::SequenceConflict { sequence: 1 })
        ));
        assert!(store
            .event_ids_after(group.group_id(), author.peer_id(), 1, 1)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn pending_invitation_metadata_survives_restart_and_can_be_removed() {
        let file = NamedTempFile::new().unwrap();
        let group = GroupIdentity::generate();
        let pending = PendingInvitationMetadata {
            group_id: group.group_id(),
            group_name: "Design Crew".to_owned(),
            inviter_name: "Maya".to_owned(),
            expires_at_unix: 1_800_003_600,
            history_policy: HistoryPolicy::FromInvitation,
            reusable: false,
        };

        EventStore::open(file.path())
            .unwrap()
            .put_pending_invitation(&pending)
            .unwrap();

        let mut reopened = EventStore::open(file.path()).unwrap();
        assert_eq!(
            reopened.pending_invitations().unwrap(),
            vec![pending.clone()]
        );
        assert!(reopened
            .remove_pending_invitation(group.group_id())
            .unwrap());
        assert!(reopened.pending_invitations().unwrap().is_empty());
    }

    #[test]
    fn saving_a_new_invitation_for_the_same_group_refreshes_metadata() {
        let mut store = EventStore::in_memory().unwrap();
        let group_id = GroupIdentity::generate().group_id();
        let mut pending = PendingInvitationMetadata {
            group_id,
            group_name: "Design Crew".to_owned(),
            inviter_name: "Maya".to_owned(),
            expires_at_unix: 1_800_003_600,
            history_policy: HistoryPolicy::None,
            reusable: false,
        };
        store.put_pending_invitation(&pending).unwrap();

        pending.inviter_name = "Noah".to_owned();
        pending.expires_at_unix += 3_600;
        pending.history_policy = HistoryPolicy::AllRetained;
        pending.reusable = true;
        store.put_pending_invitation(&pending).unwrap();

        assert_eq!(store.pending_invitations().unwrap(), vec![pending]);
    }

    #[test]
    fn pending_invitation_promotes_atomically_to_joined_group_metadata() {
        let mut store = EventStore::in_memory().unwrap();
        let group_id = GroupIdentity::generate().group_id();
        let inviter_device_id = DeviceIdentity::generate().peer_id();
        let pending = PendingInvitationMetadata {
            group_id,
            group_name: "Design Crew".to_owned(),
            inviter_name: "Maya".to_owned(),
            expires_at_unix: 1_800_003_600,
            history_policy: HistoryPolicy::FromInvitation,
            reusable: false,
        };
        store.put_pending_invitation(&pending).unwrap();

        assert!(store
            .promote_pending_invitation_to_joined_group(group_id, inviter_device_id)
            .unwrap());
        assert!(store.pending_invitations().unwrap().is_empty());
        assert_eq!(
            store.joined_groups().unwrap(),
            vec![JoinedGroupMetadata {
                group_id,
                group_name: "Design Crew".to_owned(),
                inviter_name: "Maya".to_owned(),
                inviter_device_id,
                history_policy: HistoryPolicy::FromInvitation,
            }]
        );
        assert!(store
            .promote_pending_invitation_to_joined_group(group_id, inviter_device_id)
            .unwrap());
    }

    #[test]
    fn joined_group_write_failure_keeps_the_pending_invitation() {
        let mut store = EventStore::in_memory().unwrap();
        let group_id = GroupIdentity::generate().group_id();
        let pending = PendingInvitationMetadata {
            group_id,
            group_name: "Design Crew".to_owned(),
            inviter_name: "Maya".to_owned(),
            expires_at_unix: 1_800_003_600,
            history_policy: HistoryPolicy::None,
            reusable: false,
        };
        store.put_pending_invitation(&pending).unwrap();
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER reject_joined_group
                 BEFORE INSERT ON joined_groups
                 BEGIN
                    SELECT RAISE(ABORT, 'injected joined-group failure');
                 END;",
            )
            .unwrap();

        assert!(matches!(
            store.promote_pending_invitation_to_joined_group(
                group_id,
                DeviceIdentity::generate().peer_id(),
            ),
            Err(StoreError::Sqlite(_))
        ));
        assert_eq!(store.pending_invitations().unwrap(), vec![pending]);
        assert!(store.joined_groups().unwrap().is_empty());
    }

    #[test]
    fn local_group_metadata_survives_restart() {
        let file = NamedTempFile::new().unwrap();
        let metadata = LocalGroupMetadata {
            group_id: GroupIdentity::generate().group_id(),
            group_name: "Project Atlas".to_owned(),
            icon: 2,
            history_policy: HistoryPolicy::FromInvitation,
            approval_required: false,
            invitation_lifetime_seconds: 604_800,
            reusable_invitation: false,
        };

        EventStore::open(file.path())
            .unwrap()
            .put_local_group(&metadata)
            .unwrap();

        assert_eq!(
            EventStore::open(file.path())
                .unwrap()
                .local_groups()
                .unwrap(),
            vec![metadata]
        );
    }

    #[test]
    fn issued_invitation_metadata_survives_restart_and_can_be_removed() {
        let file = NamedTempFile::new().unwrap();
        let invitation = IssuedInvitationMetadata {
            invitation_id: InvitationId::from_bytes([7; 16]),
            group_id: GroupIdentity::generate().group_id(),
            expires_at_unix: 1_800_003_600,
        };
        EventStore::open(file.path())
            .unwrap()
            .put_issued_invitation(&invitation)
            .unwrap();

        let mut reopened = EventStore::open(file.path()).unwrap();
        assert_eq!(
            reopened.issued_invitations().unwrap(),
            vec![invitation.clone()]
        );
        assert!(reopened
            .remove_issued_invitation(invitation.invitation_id)
            .unwrap());
        assert!(reopened.issued_invitations().unwrap().is_empty());
    }

    #[test]
    fn encrypted_mls_provider_snapshot_is_bounded_and_atomically_replaced() {
        let mut store = EventStore::in_memory().unwrap();
        assert!(store.encrypted_mls_provider_snapshot().unwrap().is_none());

        store
            .put_encrypted_mls_provider_snapshot(b"first authenticated ciphertext")
            .unwrap();
        assert_eq!(
            store.encrypted_mls_provider_snapshot().unwrap().unwrap(),
            b"first authenticated ciphertext"
        );

        store
            .put_encrypted_mls_provider_snapshot(b"replacement ciphertext")
            .unwrap();
        assert_eq!(
            store.encrypted_mls_provider_snapshot().unwrap().unwrap(),
            b"replacement ciphertext"
        );
        assert!(matches!(
            store.put_encrypted_mls_provider_snapshot(&vec![
                0;
                MAX_ENCRYPTED_MLS_PROVIDER_SNAPSHOT_BYTES
                    + 1
            ]),
            Err(StoreError::InvalidMlsProviderSnapshotSize(_))
        ));
        assert_eq!(
            store.encrypted_mls_provider_snapshot().unwrap().unwrap(),
            b"replacement ciphertext"
        );
    }

    #[test]
    fn pending_mls_join_and_provider_snapshot_follow_one_atomic_lifecycle() {
        let mut store = EventStore::in_memory().unwrap();
        let group_id = GroupIdentity::generate().group_id();
        assert!(store
            .pending_mls_join_key_package(group_id)
            .unwrap()
            .is_none());

        store
            .put_pending_mls_join_and_encrypted_mls_provider_snapshot(
                group_id,
                b"public key package",
                b"provider with private key package",
            )
            .unwrap();
        assert_eq!(
            store
                .pending_mls_join_key_package(group_id)
                .unwrap()
                .unwrap(),
            b"public key package"
        );
        assert_eq!(
            store.encrypted_mls_provider_snapshot().unwrap().unwrap(),
            b"provider with private key package"
        );

        assert!(store
            .remove_pending_mls_join_and_put_encrypted_mls_provider_snapshot(
                group_id,
                b"provider with joined group",
            )
            .unwrap());
        assert!(store
            .pending_mls_join_key_package(group_id)
            .unwrap()
            .is_none());
        assert_eq!(
            store.encrypted_mls_provider_snapshot().unwrap().unwrap(),
            b"provider with joined group"
        );
        assert!(!store
            .remove_pending_mls_join_and_put_encrypted_mls_provider_snapshot(
                group_id,
                b"must not replace provider without a pending join",
            )
            .unwrap());
        assert_eq!(
            store.encrypted_mls_provider_snapshot().unwrap().unwrap(),
            b"provider with joined group"
        );
        assert!(matches!(
            store.put_pending_mls_join_and_encrypted_mls_provider_snapshot(
                group_id,
                &vec![0; MAX_JOIN_MLS_MESSAGE_BYTES + 1],
                b"valid snapshot",
            ),
            Err(StoreError::InvalidMlsKeyPackageSize(_))
        ));
    }

    #[test]
    fn snapshot_failure_rolls_back_pending_mls_join_changes() {
        let mut store = EventStore::in_memory().unwrap();
        let group_id = GroupIdentity::generate().group_id();
        store
            .put_pending_mls_join_and_encrypted_mls_provider_snapshot(
                group_id,
                b"public key package",
                b"preceding provider snapshot",
            )
            .unwrap();
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER reject_pending_join_snapshot_update
                 BEFORE UPDATE ON mls_provider_snapshot
                 BEGIN
                    SELECT RAISE(ABORT, 'injected snapshot failure');
                 END;",
            )
            .unwrap();

        assert!(matches!(
            store.remove_pending_mls_join_and_put_encrypted_mls_provider_snapshot(
                group_id,
                b"provider with joined group",
            ),
            Err(StoreError::Sqlite(_))
        ));
        assert_eq!(
            store
                .pending_mls_join_key_package(group_id)
                .unwrap()
                .unwrap(),
            b"public key package"
        );
        assert_eq!(
            store.encrypted_mls_provider_snapshot().unwrap().unwrap(),
            b"preceding provider snapshot"
        );
    }

    #[test]
    fn event_and_resulting_mls_snapshot_commit_together() {
        let mut store = EventStore::in_memory().unwrap();
        let event = message_event(
            &DeviceIdentity::generate(),
            &GroupIdentity::generate(),
            1,
            b"protected membership change",
        );

        assert_eq!(
            store
                .put_event_and_encrypted_mls_provider_snapshot(
                    &event,
                    b"resulting authenticated snapshot",
                )
                .unwrap(),
            PutEventOutcome::Inserted
        );
        assert!(store.get_event(event.id()).unwrap().is_some());
        assert_eq!(
            store.encrypted_mls_provider_snapshot().unwrap().unwrap(),
            b"resulting authenticated snapshot"
        );
    }

    #[test]
    fn snapshot_write_failure_rolls_back_the_event() {
        let mut store = EventStore::in_memory().unwrap();
        store
            .put_encrypted_mls_provider_snapshot(b"preceding authenticated snapshot")
            .unwrap();
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER reject_mls_snapshot_update
                 BEFORE UPDATE ON mls_provider_snapshot
                 BEGIN
                    SELECT RAISE(ABORT, 'injected snapshot failure');
                 END;",
            )
            .unwrap();
        let event = message_event(
            &DeviceIdentity::generate(),
            &GroupIdentity::generate(),
            1,
            b"protected membership change",
        );

        assert!(matches!(
            store.put_event_and_encrypted_mls_provider_snapshot(
                &event,
                b"resulting authenticated snapshot",
            ),
            Err(StoreError::Sqlite(_))
        ));
        assert!(store.get_event(event.id()).unwrap().is_none());
        assert_eq!(
            store.encrypted_mls_provider_snapshot().unwrap().unwrap(),
            b"preceding authenticated snapshot"
        );
    }

    #[test]
    fn materialized_message_and_snapshot_commit_atomically() {
        let mut store = EventStore::in_memory().unwrap();
        let author = DeviceIdentity::generate();
        let group = GroupIdentity::generate();
        let event = message_event(&author, &group, 1, b"MLS ciphertext");
        store.put_event(&event).unwrap();
        assert_eq!(
            store
                .unmaterialized_message_events(group.group_id(), 1)
                .unwrap()[0]
                .id(),
            event.id()
        );

        assert_eq!(
            store
                .put_message_and_encrypted_mls_provider_snapshot(
                    &event,
                    b"advanced encrypted provider",
                    b"encrypted local message",
                )
                .unwrap(),
            PutEventOutcome::AlreadyPresent
        );
        assert_eq!(
            store.encrypted_mls_provider_snapshot().unwrap().unwrap(),
            b"advanced encrypted provider"
        );
        assert_eq!(
            store.encrypted_messages(group.group_id()).unwrap(),
            super::EncryptedMessagePage {
                messages: vec![super::EncryptedMessage {
                    event_id: *event.id().as_bytes(),
                    group_id: group.group_id(),
                    author_id: author.peer_id(),
                    created_at_unix_ms: event.created_at_unix_ms(),
                    encrypted_body: b"encrypted local message".to_vec(),
                }],
                has_earlier: false,
            }
        );
        assert!(store
            .unmaterialized_message_events(group.group_id(), 1)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn recent_message_page_is_bounded_and_keeps_display_order() {
        let mut store = EventStore::in_memory().unwrap();
        let author = DeviceIdentity::generate();
        let group = GroupIdentity::generate();
        for sequence in 1..=super::MAX_RECENT_MESSAGE_EVENTS as u64 + 1 {
            let event = SignedEvent::create(
                &author,
                EventSpec {
                    group_id: group.group_id(),
                    author_sequence: sequence,
                    causal_parents: &[],
                    created_at_unix_ms: sequence,
                    kind: EventKind::MessageCreated,
                    protected_payload: b"MLS ciphertext",
                },
            )
            .unwrap();
            store
                .put_message_and_encrypted_mls_provider_snapshot(
                    &event,
                    b"advanced encrypted provider",
                    b"encrypted local message",
                )
                .unwrap();
        }

        let page = store.encrypted_messages(group.group_id()).unwrap();
        assert!(page.has_earlier);
        assert_eq!(page.messages.len(), super::MAX_RECENT_MESSAGE_EVENTS);
        assert_eq!(page.messages.first().unwrap().created_at_unix_ms, 2);
        assert_eq!(
            page.messages.last().unwrap().created_at_unix_ms,
            super::MAX_RECENT_MESSAGE_EVENTS as u64 + 1
        );
    }

    #[test]
    fn materialized_message_failure_rolls_back_event_and_snapshot() {
        let mut store = EventStore::in_memory().unwrap();
        store
            .put_encrypted_mls_provider_snapshot(b"preceding encrypted provider")
            .unwrap();
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER reject_materialized_message
                 BEFORE INSERT ON materialized_messages
                 BEGIN
                    SELECT RAISE(ABORT, 'injected message failure');
                 END;",
            )
            .unwrap();
        let event = message_event(
            &DeviceIdentity::generate(),
            &GroupIdentity::generate(),
            1,
            b"MLS ciphertext",
        );

        assert!(matches!(
            store.put_message_and_encrypted_mls_provider_snapshot(
                &event,
                b"advanced encrypted provider",
                b"encrypted local message",
            ),
            Err(StoreError::Sqlite(_))
        ));
        assert!(store.get_event(event.id()).unwrap().is_none());
        assert_eq!(
            store.encrypted_mls_provider_snapshot().unwrap().unwrap(),
            b"preceding encrypted provider"
        );
    }

    #[test]
    fn encrypted_message_body_is_bounded() {
        let mut store = EventStore::in_memory().unwrap();
        let event = message_event(
            &DeviceIdentity::generate(),
            &GroupIdentity::generate(),
            1,
            b"MLS ciphertext",
        );
        assert!(matches!(
            store.put_message_and_encrypted_mls_provider_snapshot(
                &event,
                b"advanced encrypted provider",
                &vec![0; MAX_ENCRYPTED_MESSAGE_BODY_BYTES + 1],
            ),
            Err(StoreError::InvalidEncryptedMessageSize(_))
        ));
    }

    #[test]
    fn version_four_database_adds_mls_provider_snapshot() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch("PRAGMA user_version = 4;")
            .unwrap();

        let mut store = EventStore::from_connection(connection).unwrap();
        assert!(store.encrypted_mls_provider_snapshot().unwrap().is_none());
        store
            .put_encrypted_mls_provider_snapshot(b"authenticated ciphertext")
            .unwrap();
        assert_eq!(
            store.encrypted_mls_provider_snapshot().unwrap().unwrap(),
            b"authenticated ciphertext"
        );
    }

    #[test]
    fn version_five_database_adds_pending_mls_joins() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE mls_provider_snapshot (
                    singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
                    encrypted BLOB NOT NULL CHECK(length(encrypted) BETWEEN 1 AND 8388736)
                 ) STRICT;
                 PRAGMA user_version = 5;",
            )
            .unwrap();

        let mut store = EventStore::from_connection(connection).unwrap();
        let group_id = GroupIdentity::generate().group_id();
        store
            .put_pending_mls_join_and_encrypted_mls_provider_snapshot(
                group_id,
                b"public key package",
                b"authenticated provider ciphertext",
            )
            .unwrap();
        assert_eq!(
            store
                .pending_mls_join_key_package(group_id)
                .unwrap()
                .unwrap(),
            b"public key package"
        );
    }

    #[test]
    fn version_six_database_adds_joined_groups() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE pending_invitations (
                    group_id BLOB PRIMARY KEY NOT NULL,
                    group_name TEXT NOT NULL,
                    inviter_name TEXT NOT NULL,
                    expires_at_unix INTEGER NOT NULL CHECK(expires_at_unix > 0),
                    history_policy INTEGER NOT NULL CHECK(history_policy BETWEEN 0 AND 2),
                    reusable INTEGER NOT NULL CHECK(reusable IN (0, 1))
                 ) STRICT;
                 PRAGMA user_version = 6;",
            )
            .unwrap();

        let mut store = EventStore::from_connection(connection).unwrap();
        let group_id = GroupIdentity::generate().group_id();
        let inviter_device_id = DeviceIdentity::generate().peer_id();
        store
            .put_pending_invitation(&PendingInvitationMetadata {
                group_id,
                group_name: "Design Crew".to_owned(),
                inviter_name: "Maya".to_owned(),
                expires_at_unix: 1_800_003_600,
                history_policy: HistoryPolicy::None,
                reusable: false,
            })
            .unwrap();
        assert!(store
            .promote_pending_invitation_to_joined_group(group_id, inviter_device_id)
            .unwrap());
        assert_eq!(store.joined_groups().unwrap().len(), 1);
    }

    #[test]
    fn version_seven_database_adds_materialized_messages() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE events (
                    event_id BLOB PRIMARY KEY NOT NULL CHECK(length(event_id) = 32),
                    group_id BLOB NOT NULL,
                    author_id BLOB NOT NULL,
                    author_sequence INTEGER NOT NULL CHECK(author_sequence > 0),
                    encoded BLOB NOT NULL,
                    UNIQUE(group_id, author_id, author_sequence)
                 ) STRICT;
                 CREATE TABLE mls_provider_snapshot (
                    singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton = 1),
                    encrypted BLOB NOT NULL CHECK(length(encrypted) BETWEEN 1 AND 8388736)
                 ) STRICT;
                 PRAGMA user_version = 7;",
            )
            .unwrap();

        let mut store = EventStore::from_connection(connection).unwrap();
        let author = DeviceIdentity::generate();
        let group = GroupIdentity::generate();
        let event = message_event(&author, &group, 1, b"MLS ciphertext");
        store
            .put_message_and_encrypted_mls_provider_snapshot(
                &event,
                b"advanced encrypted provider",
                b"encrypted local message",
            )
            .unwrap();
        assert_eq!(
            store
                .encrypted_messages(group.group_id())
                .unwrap()
                .messages
                .len(),
            1
        );
    }

    #[test]
    fn version_two_database_adds_local_groups() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE events (
                    event_id BLOB PRIMARY KEY NOT NULL CHECK(length(event_id) = 32),
                    group_id BLOB NOT NULL,
                    author_id BLOB NOT NULL,
                    author_sequence INTEGER NOT NULL CHECK(author_sequence > 0),
                    encoded BLOB NOT NULL,
                    UNIQUE(group_id, author_id, author_sequence)
                 ) STRICT;
                 CREATE INDEX events_by_group_author_sequence
                    ON events(group_id, author_id, author_sequence);
                 CREATE TABLE pending_invitations (
                    group_id BLOB PRIMARY KEY NOT NULL,
                    group_name TEXT NOT NULL,
                    inviter_name TEXT NOT NULL,
                    expires_at_unix INTEGER NOT NULL CHECK(expires_at_unix > 0),
                    history_policy INTEGER NOT NULL CHECK(history_policy BETWEEN 0 AND 2),
                    reusable INTEGER NOT NULL CHECK(reusable IN (0, 1))
                 ) STRICT;
                 PRAGMA user_version = 2;",
            )
            .unwrap();

        let store = EventStore::from_connection(connection).unwrap();
        assert!(store.local_groups().unwrap().is_empty());
        assert!(store.issued_invitations().unwrap().is_empty());
    }

    #[test]
    fn version_three_database_adds_issued_invitations() {
        let connection = Connection::open_in_memory().unwrap();
        connection
            .execute_batch(
                "CREATE TABLE events (
                    event_id BLOB PRIMARY KEY NOT NULL CHECK(length(event_id) = 32),
                    group_id BLOB NOT NULL,
                    author_id BLOB NOT NULL,
                    author_sequence INTEGER NOT NULL CHECK(author_sequence > 0),
                    encoded BLOB NOT NULL,
                    UNIQUE(group_id, author_id, author_sequence)
                 ) STRICT;
                 CREATE INDEX events_by_group_author_sequence
                    ON events(group_id, author_id, author_sequence);
                 CREATE TABLE pending_invitations (
                    group_id BLOB PRIMARY KEY NOT NULL,
                    group_name TEXT NOT NULL,
                    inviter_name TEXT NOT NULL,
                    expires_at_unix INTEGER NOT NULL CHECK(expires_at_unix > 0),
                    history_policy INTEGER NOT NULL CHECK(history_policy BETWEEN 0 AND 2),
                    reusable INTEGER NOT NULL CHECK(reusable IN (0, 1))
                 ) STRICT;
                 CREATE TABLE local_groups (
                    group_id BLOB PRIMARY KEY NOT NULL,
                    group_name TEXT NOT NULL,
                    icon INTEGER NOT NULL CHECK(icon BETWEEN 0 AND 4),
                    history_policy INTEGER NOT NULL CHECK(history_policy BETWEEN 0 AND 2),
                    approval_required INTEGER NOT NULL CHECK(approval_required IN (0, 1)),
                    invitation_lifetime_seconds INTEGER NOT NULL
                        CHECK(invitation_lifetime_seconds > 0),
                    reusable_invitation INTEGER NOT NULL
                        CHECK(reusable_invitation IN (0, 1))
                 ) STRICT;
                 PRAGMA user_version = 3;",
            )
            .unwrap();

        let store = EventStore::from_connection(connection).unwrap();
        assert!(store.issued_invitations().unwrap().is_empty());
    }

    #[test]
    fn version_one_database_migrates_without_losing_events() {
        let file = NamedTempFile::new().unwrap();
        let event = message_event(
            &DeviceIdentity::generate(),
            &GroupIdentity::generate(),
            1,
            b"before migration",
        );
        let connection = Connection::open(file.path()).unwrap();
        connection
            .execute_batch(
                "CREATE TABLE events (
                    event_id BLOB PRIMARY KEY NOT NULL CHECK(length(event_id) = 32),
                    group_id BLOB NOT NULL,
                    author_id BLOB NOT NULL,
                    author_sequence INTEGER NOT NULL CHECK(author_sequence > 0),
                    encoded BLOB NOT NULL,
                    UNIQUE(group_id, author_id, author_sequence)
                 ) STRICT;
                 CREATE INDEX events_by_group_author_sequence
                    ON events(group_id, author_id, author_sequence);
                 PRAGMA user_version = 1;",
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO events (
                    event_id, group_id, author_id, author_sequence, encoded
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    event.id().as_bytes().as_slice(),
                    event.group_id().to_bytes(),
                    event.author_id().to_bytes(),
                    event.author_sequence() as i64,
                    event.encode().unwrap()
                ],
            )
            .unwrap();
        drop(connection);

        let store = EventStore::open(file.path()).unwrap();
        assert!(store.pending_invitations().unwrap().is_empty());
        assert_eq!(
            store.get_event(event.id()).unwrap().unwrap().id(),
            event.id()
        );
    }
}
