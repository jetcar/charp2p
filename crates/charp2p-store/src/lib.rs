#![forbid(unsafe_code)]

//! Durable local persistence for verified CharP2P protocol data.

use std::{
    collections::{BTreeSet, HashMap},
    path::Path,
    time::Duration,
};

use charp2p_core::{
    EventError, EventId, HistoryPolicy, InvitationId, MAX_JOIN_MLS_MESSAGE_BYTES,
    MAX_JOIN_RESPONSE_WIRE_BYTES, MAX_SYNC_BATCH_ITEMS, PeerId, SignedEvent, SyncMembershipState,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use thiserror::Error;

pub use charp2p_core::SyncAuthorHead as AuthorHead;

const SCHEMA_VERSION: i64 = 28;

/// Largest authenticated ciphertext accepted for one MLS provider snapshot.
pub const MAX_ENCRYPTED_MLS_PROVIDER_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024 + 128;
/// Largest locally encrypted body for one materialized text message.
pub const MAX_ENCRYPTED_MESSAGE_BODY_BYTES: usize = 16 * 1024 + 42;
/// Largest encrypted cached join response accepted by the local store.
pub const MAX_ENCRYPTED_JOIN_RESPONSE_BYTES: usize = MAX_JOIN_RESPONSE_WIRE_BYTES + 42;
/// Largest recent-message page exposed to an application view.
pub const MAX_RECENT_MESSAGE_EVENTS: usize = 256;
/// Maximum encoded length of one remembered peer address.
pub const MAX_PEER_ADDRESS_BYTES: usize = 512;
/// Remembered successful addresses per group peer; older ones are dropped.
pub const MAX_PEER_ADDRESSES: usize = 4;
/// Most conflicting author sequences recorded per group author.
pub const MAX_SEQUENCE_CONFLICTS_PER_AUTHOR: usize = 64;
/// Maximum undecided owner approval requests kept for one group (ADR-041).
pub const MAX_PENDING_APPROVAL_REQUESTS_PER_GROUP: usize = 64;

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
    pub last_synchronized_at_unix: Option<u64>,
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
    /// Member device whose request made the owner issue it (ADR-036).
    pub requested_by: Option<PeerId>,
}

/// Owner decision state for a device asking to join an approval-required group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalState {
    Pending,
    Approved,
    Declined,
}

/// Owner-local record of an authorized join request awaiting approval (ADR-041).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerApprovalRequest {
    pub group_id: PeerId,
    pub device_id: PeerId,
    pub invitation_id: InvitationId,
    pub expires_at_unix: u64,
    pub first_requested_at_unix: u64,
    pub last_requested_at_unix: u64,
    pub state: ApprovalState,
}

/// Result of recording one authorized join request for an approval-required group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApprovalRequestOutcome {
    /// The request is recorded and awaits the owner's decision.
    Pending,
    /// The owner approved this device; admission may proceed.
    Approved,
    /// The owner declined this device; the request must be rejected.
    Declined,
    /// The group already holds the maximum undecided requests.
    Full,
}

/// Non-secret index for an owner-side rendezvous key retained after join.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerDiscoveryKeyMetadata {
    pub invitation_id: InvitationId,
    pub group_id: PeerId,
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
    pub author_sequence: u64,
    pub created_at_unix_ms: u64,
    pub encrypted_body: Vec<u8>,
    /// Latest applied edit by the same author, if any.
    pub edit: Option<EncryptedMessageEdit>,
    /// Identifier of the message this one replies to, if any.
    pub reply_to: Option<[u8; 32]>,
}

/// Locally encrypted replacement text from a signed `MessageEdited` event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EncryptedMessageEdit {
    pub event_id: [u8; 32],
    pub encrypted_body: Vec<u8>,
}

/// Cached response for an already committed MLS member admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlsJoinAdmission {
    pub request_hash: [u8; 32],
    pub encrypted_response: Vec<u8>,
}

/// Signed evidence that one author reused sequences for different content.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SequenceConflictSummary {
    pub author_id: PeerId,
    /// Distinct author sequences seen with conflicting content (bounded).
    pub conflicting_sequences: u64,
    /// Lowest author sequence seen with conflicting content.
    pub first_sequence: u64,
}

/// SQLite-backed storage for signed events and non-secret application metadata.
/// One address a group peer was last reached at successfully.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerAddress {
    /// Opaque encoded transport address.
    pub address: Vec<u8>,
    /// When synchronization through this address last completed.
    pub last_success_at_unix: u64,
}

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
    /// different content is rejected and recorded as a sequence conflict.
    pub fn put_event(&mut self, event: &SignedEvent) -> Result<PutEventOutcome, StoreError> {
        let transaction = self.connection.transaction()?;
        let outcome = match put_event_in_transaction(&transaction, event) {
            Ok(outcome) => outcome,
            Err(error @ StoreError::SequenceConflict { .. }) => {
                drop(transaction);
                self.record_sequence_conflict(event)?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };
        transaction.commit()?;
        Ok(outcome)
    }

    /// Persists a batch atomically after checking every author sequence.
    ///
    /// A reused author sequence rejects the whole batch and is recorded as a
    /// sequence conflict of its author.
    pub fn put_events(&mut self, events: &[SignedEvent]) -> Result<PutEventsOutcome, StoreError> {
        let transaction = self.connection.transaction()?;
        let mut outcome = PutEventsOutcome::default();

        for event in events {
            match put_event_in_transaction(&transaction, event) {
                Ok(PutEventOutcome::Inserted) => outcome.inserted += 1,
                Ok(PutEventOutcome::AlreadyPresent) => outcome.already_present += 1,
                Err(error @ StoreError::SequenceConflict { .. }) => {
                    drop(transaction);
                    self.record_sequence_conflict(event)?;
                    return Err(error);
                }
                Err(error) => return Err(error),
            }
        }

        transaction.commit()?;
        Ok(outcome)
    }

    /// Records that a verified event reuses its author's sequence for content
    /// other than the stored event. Both events are validly signed by the
    /// author, so the record is evidence of equivocation. At most
    /// [`MAX_SEQUENCE_CONFLICTS_PER_AUTHOR`] sequences are kept per author.
    fn record_sequence_conflict(&mut self, event: &SignedEvent) -> Result<(), StoreError> {
        let sequence = i64::try_from(event.author_sequence())
            .map_err(|_| StoreError::SequenceTooLarge(event.author_sequence()))?;
        let group_id = event.group_id().to_bytes();
        let author_id = event.author_id().to_bytes();
        let conflicting_id = event.id();
        let transaction = self.connection.transaction()?;
        let stored: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT event_id FROM events
                     WHERE group_id = ?1 AND author_id = ?2 AND author_sequence = ?3",
                params![group_id, author_id, sequence],
                |row| row.get(0),
            )
            .optional()?;
        let Some(stored_id) = stored else {
            return Ok(());
        };
        if stored_id.as_slice() == conflicting_id.as_bytes() {
            return Ok(());
        }
        let recorded: i64 = transaction.query_row(
            "SELECT COUNT(*) FROM sequence_conflicts WHERE group_id = ?1 AND author_id = ?2",
            params![group_id, author_id],
            |row| row.get(0),
        )?;
        if usize::try_from(recorded).map_err(|_| StoreError::CorruptIndex)?
            >= MAX_SEQUENCE_CONFLICTS_PER_AUTHOR
        {
            return Ok(());
        }
        transaction.execute(
            "INSERT OR IGNORE INTO sequence_conflicts (
                group_id, author_id, author_sequence, stored_event_id, conflicting_event_id
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                group_id,
                author_id,
                sequence,
                stored_id,
                conflicting_id.as_bytes().as_slice()
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Summarizes recorded sequence conflicts per author of a group.
    pub fn sequence_conflicts(
        &self,
        group_id: PeerId,
    ) -> Result<Vec<SequenceConflictSummary>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT author_id, COUNT(*), MIN(author_sequence) FROM sequence_conflicts
             WHERE group_id = ?1
             GROUP BY author_id
             ORDER BY author_id",
        )?;
        let rows = statement.query_map([group_id.to_bytes()], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?;
        let mut conflicts = Vec::new();
        for row in rows {
            let (author_id, count, first_sequence) = row?;
            conflicts.push(SequenceConflictSummary {
                author_id: PeerId::from_bytes(&author_id).map_err(|_| StoreError::CorruptIndex)?,
                conflicting_sequences: u64::try_from(count)
                    .map_err(|_| StoreError::CorruptIndex)?,
                first_sequence: u64::try_from(first_sequence)
                    .map_err(|_| StoreError::CorruptIndex)?,
            });
        }
        Ok(conflicts)
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

    /// Atomically persists an admitted member event, the advanced MLS state,
    /// and the encrypted response used to retry that exact join request.
    /// A single-use invitation is consumed in the same transaction; if it was
    /// already consumed nothing is stored.
    pub fn put_mls_join_admission(
        &mut self,
        event: &SignedEvent,
        encrypted_snapshot: &[u8],
        member_id: PeerId,
        request_hash: &[u8; 32],
        encrypted_response: &[u8],
        single_use_invitation: Option<InvitationId>,
    ) -> Result<PutEventOutcome, StoreError> {
        if event.kind() != charp2p_core::EventKind::MemberAdded {
            return Err(StoreError::CorruptIndex);
        }
        validate_encrypted_mls_provider_snapshot(encrypted_snapshot)?;
        validate_encrypted_join_response(encrypted_response)?;
        let transaction = self.connection.transaction()?;
        let outcome = put_event_in_transaction(&transaction, event)?;
        put_encrypted_mls_provider_snapshot_in_transaction(&transaction, encrypted_snapshot)?;
        transaction.execute(
            "INSERT INTO mls_join_admissions (
                group_id, member_id, request_hash, encrypted_response, event_id
             ) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                event.group_id().to_bytes(),
                member_id.to_bytes(),
                request_hash.as_slice(),
                encrypted_response,
                event.id().as_bytes().as_slice(),
            ],
        )?;
        if let Some(invitation_id) = single_use_invitation {
            let inserted = transaction.execute(
                "INSERT INTO consumed_single_use_invitations (
                    invitation_id, group_id, member_id, event_id
                 ) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(invitation_id) DO NOTHING",
                params![
                    invitation_id.as_bytes().as_slice(),
                    event.group_id().to_bytes(),
                    member_id.to_bytes(),
                    event.id().as_bytes().as_slice(),
                ],
            )?;
            if inserted == 0 {
                return Err(StoreError::InvitationConsumed);
            }
        }
        transaction.commit()?;
        Ok(outcome)
    }

    /// Returns the device that consumed a single-use invitation of this
    /// group, if any.
    pub fn single_use_invitation_consumer(
        &self,
        group_id: PeerId,
        invitation_id: InvitationId,
    ) -> Result<Option<PeerId>, StoreError> {
        self.connection
            .query_row(
                "SELECT member_id FROM consumed_single_use_invitations
                 WHERE invitation_id = ?1 AND group_id = ?2",
                params![invitation_id.as_bytes().as_slice(), group_id.to_bytes()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .map(|member_id| PeerId::from_bytes(&member_id).map_err(|_| StoreError::CorruptIndex))
            .transpose()
    }

    /// Loads the cached response for a previously admitted device.
    pub fn mls_join_admission(
        &self,
        group_id: PeerId,
        member_id: PeerId,
    ) -> Result<Option<MlsJoinAdmission>, StoreError> {
        let row = self
            .connection
            .query_row(
                "SELECT request_hash, encrypted_response
                 FROM mls_join_admissions
                 WHERE group_id = ?1 AND member_id = ?2",
                params![group_id.to_bytes(), member_id.to_bytes()],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
            )
            .optional()?;
        row.map(|(request_hash, encrypted_response)| {
            let request_hash: [u8; 32] = request_hash
                .try_into()
                .map_err(|_| StoreError::CorruptIndex)?;
            validate_encrypted_join_response(&encrypted_response)?;
            Ok(MlsJoinAdmission {
                request_hash,
                encrypted_response,
            })
        })
        .transpose()
    }

    /// Reports whether an owner has removed this device from the group.
    pub fn is_removed_mls_member(
        &self,
        group_id: PeerId,
        member_id: PeerId,
    ) -> Result<bool, StoreError> {
        Ok(self
            .connection
            .query_row(
                "SELECT 1 FROM removed_mls_members
                 WHERE group_id = ?1 AND member_id = ?2",
                params![group_id.to_bytes(), member_id.to_bytes()],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    /// Lists the devices an owner has removed from the group and not yet
    /// allowed to join again, ordered by device identifier.
    pub fn removed_mls_members(&self, group_id: PeerId) -> Result<Vec<PeerId>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT member_id FROM removed_mls_members
             WHERE group_id = ?1
             ORDER BY member_id",
        )?;
        let rows = statement.query_map([group_id.to_bytes()], |row| row.get::<_, Vec<u8>>(0))?;
        let mut members = Vec::new();
        for row in rows {
            members.push(PeerId::from_bytes(&row?).map_err(|_| StoreError::CorruptIndex)?);
        }
        Ok(members)
    }

    /// Clears the re-admission block of a removed device so a valid
    /// invitation can admit it again with a new KeyPackage. The signed
    /// removal event stays in history. Returns whether a block was cleared.
    pub fn allow_removed_mls_member_readmission(
        &mut self,
        group_id: PeerId,
        member_id: PeerId,
    ) -> Result<bool, StoreError> {
        Ok(self.connection.execute(
            "DELETE FROM removed_mls_members WHERE group_id = ?1 AND member_id = ?2",
            params![group_id.to_bytes(), member_id.to_bytes()],
        )? > 0)
    }

    /// Atomically persists a member-removal event, the advanced MLS state,
    /// and the durable re-admission block for that device.
    pub fn put_mls_member_removal(
        &mut self,
        event: &SignedEvent,
        encrypted_snapshot: &[u8],
        removed_member_id: PeerId,
    ) -> Result<PutEventOutcome, StoreError> {
        if event.kind() != charp2p_core::EventKind::MemberRemoved {
            return Err(StoreError::CorruptIndex);
        }
        validate_encrypted_mls_provider_snapshot(encrypted_snapshot)?;
        let transaction = self.connection.transaction()?;
        let outcome = put_event_in_transaction(&transaction, event)?;
        put_encrypted_mls_provider_snapshot_in_transaction(&transaction, encrypted_snapshot)?;
        transaction.execute(
            "DELETE FROM mls_join_admissions WHERE group_id = ?1 AND member_id = ?2",
            params![event.group_id().to_bytes(), removed_member_id.to_bytes()],
        )?;
        transaction.execute(
            "INSERT INTO removed_mls_members (
                group_id, member_id, removal_event_id
             ) VALUES (?1, ?2, ?3)
             ON CONFLICT(group_id, member_id) DO UPDATE SET
                removal_event_id = excluded.removal_event_id",
            params![
                event.group_id().to_bytes(),
                removed_member_id.to_bytes(),
                event.id().as_bytes().as_slice(),
            ],
        )?;
        transaction.execute(
            "UPDATE applied_invite_permissions SET granted = 0
             WHERE group_id = ?1 AND target_device_id = ?2",
            params![event.group_id().to_bytes(), removed_member_id.to_bytes()],
        )?;
        // A removed device needs a new approval to join again (ADR-041).
        transaction.execute(
            "DELETE FROM owner_approval_requests
             WHERE group_id = ?1 AND device_id = ?2 AND state = ?3",
            params![
                event.group_id().to_bytes(),
                removed_member_id.to_bytes(),
                approval_state_code(ApprovalState::Approved),
            ],
        )?;
        transaction.commit()?;
        Ok(outcome)
    }

    /// Atomically persists an owner key refresh event and the advanced MLS
    /// state (ADR-045).
    pub fn put_mls_key_refresh(
        &mut self,
        event: &SignedEvent,
        encrypted_snapshot: &[u8],
    ) -> Result<PutEventOutcome, StoreError> {
        if event.kind() != charp2p_core::EventKind::KeyEpochAdvanced {
            return Err(StoreError::CorruptIndex);
        }
        validate_encrypted_mls_provider_snapshot(encrypted_snapshot)?;
        let transaction = self.connection.transaction()?;
        let outcome = put_event_in_transaction(&transaction, event)?;
        put_encrypted_mls_provider_snapshot_in_transaction(&transaction, encrypted_snapshot)?;
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
        self.put_materialized_message(event, encrypted_snapshot, encrypted_body, None, false)
    }

    /// Atomically persists a message received from another device and marks
    /// its new display copy unread on this device.
    pub fn put_received_message_and_encrypted_mls_provider_snapshot(
        &mut self,
        event: &SignedEvent,
        encrypted_snapshot: &[u8],
        encrypted_body: &[u8],
    ) -> Result<PutEventOutcome, StoreError> {
        self.put_materialized_message(event, encrypted_snapshot, encrypted_body, None, true)
    }

    /// Atomically persists a message that replies to another message. The
    /// reply reference comes from the decrypted protected payload; a message
    /// received from another device is marked unread.
    pub fn put_reply_message_and_encrypted_mls_provider_snapshot(
        &mut self,
        event: &SignedEvent,
        encrypted_snapshot: &[u8],
        encrypted_body: &[u8],
        reply_to: &[u8; 32],
        received: bool,
    ) -> Result<PutEventOutcome, StoreError> {
        self.put_materialized_message(
            event,
            encrypted_snapshot,
            encrypted_body,
            Some(reply_to),
            received,
        )
    }

    fn put_materialized_message(
        &mut self,
        event: &SignedEvent,
        encrypted_snapshot: &[u8],
        encrypted_body: &[u8],
        reply_to: Option<&[u8; 32]>,
        unread: bool,
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
        let materialized = transaction.execute(
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
        if let Some(reply_to) = reply_to.filter(|_| materialized == 1) {
            transaction.execute(
                "INSERT INTO message_reply_references (event_id, reply_to_event_id)
                 VALUES (?1, ?2)
                 ON CONFLICT(event_id) DO NOTHING",
                params![event.id().as_bytes().as_slice(), reply_to.as_slice()],
            )?;
        }
        if unread && materialized == 1 {
            transaction.execute(
                "INSERT INTO unread_local_messages (event_id, group_id)
                 SELECT ?1, ?2
                 WHERE NOT EXISTS (
                     SELECT 1 FROM blocked_local_devices
                     WHERE group_id = ?2 AND device_id = ?3
                 )
                 ON CONFLICT(event_id) DO NOTHING",
                params![
                    event.id().as_bytes().as_slice(),
                    event.group_id().to_bytes(),
                    event.author_id().to_bytes()
                ],
            )?;
        }
        transaction.commit()?;
        Ok(outcome)
    }

    /// Lists locally materialized messages in stable display order.
    pub fn encrypted_messages(&self, group_id: PeerId) -> Result<EncryptedMessagePage, StoreError> {
        let mut messages =
            self.newest_encrypted_messages(group_id, MAX_RECENT_MESSAGE_EVENTS + 1)?;
        let has_earlier = messages.len() > MAX_RECENT_MESSAGE_EVENTS;
        messages.truncate(MAX_RECENT_MESSAGE_EVENTS);
        messages.reverse();
        Ok(EncryptedMessagePage {
            messages,
            has_earlier,
        })
    }

    /// Returns the newest displayable message of one group, used for the
    /// group list preview, or `None` when no message is shown there.
    pub fn latest_encrypted_message(
        &self,
        group_id: PeerId,
    ) -> Result<Option<EncryptedMessage>, StoreError> {
        Ok(self.newest_encrypted_messages(group_id, 1)?.pop())
    }

    /// Lists up to `limit` displayable messages of one group, newest first.
    fn newest_encrypted_messages(
        &self,
        group_id: PeerId,
        limit: usize,
    ) -> Result<Vec<EncryptedMessage>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT e.encoded, m.group_id, m.author_id, m.created_at_unix_ms,
                    m.encrypted_body, x.event_id, x.encrypted_body, r.reply_to_event_id
             FROM materialized_messages m
             JOIN events e ON e.event_id = m.event_id
             LEFT JOIN message_reply_references r ON r.event_id = m.event_id
             LEFT JOIN applied_message_edits x ON x.event_id = (
                 SELECT latest.event_id FROM applied_message_edits latest
                 WHERE latest.target_event_id = m.event_id
                   AND latest.group_id = m.group_id
                   AND latest.author_id = m.author_id
                 ORDER BY latest.author_sequence DESC
                 LIMIT 1
             )
             WHERE m.group_id = ?1
               AND NOT EXISTS (
                   SELECT 1 FROM blocked_local_devices b
                   WHERE b.group_id = m.group_id AND b.device_id = m.author_id
               )
               AND NOT EXISTS (
                   SELECT 1 FROM applied_message_deletions d
                   WHERE d.target_event_id = m.event_id
                     AND d.group_id = m.group_id
                     AND d.author_id = m.author_id
               )
             ORDER BY m.created_at_unix_ms DESC, m.event_id DESC
             LIMIT ?2",
        )?;
        let rows = statement.query_map(params![group_id.to_bytes(), limit as i64], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, Option<Vec<u8>>>(5)?,
                row.get::<_, Option<Vec<u8>>>(6)?,
                row.get::<_, Option<Vec<u8>>>(7)?,
            ))
        })?;
        let mut messages = Vec::with_capacity(limit);
        for row in rows {
            let (
                encoded,
                stored_group,
                stored_author,
                stored_created_at,
                encrypted_body,
                edit_event_id,
                edit_body,
                reply_to,
            ) = row?;
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
            let edit = match (edit_event_id, edit_body) {
                (Some(event_id), Some(encrypted_body)) => {
                    validate_encrypted_message_body(&encrypted_body)?;
                    Some(EncryptedMessageEdit {
                        event_id: event_id.try_into().map_err(|_| StoreError::CorruptIndex)?,
                        encrypted_body,
                    })
                }
                (None, None) => None,
                _ => return Err(StoreError::CorruptIndex),
            };
            messages.push(EncryptedMessage {
                event_id: *event.id().as_bytes(),
                group_id,
                author_id: event.author_id(),
                author_sequence: event.author_sequence(),
                created_at_unix_ms,
                encrypted_body,
                edit,
                reply_to: reply_to
                    .map(|reply_to| reply_to.try_into().map_err(|_| StoreError::CorruptIndex))
                    .transpose()?,
            });
        }
        Ok(messages)
    }

    /// Records the highest contiguous sequence for one author explicitly
    /// accepted by a peer. A later stale acknowledgement cannot move it back.
    pub fn acknowledge_author_head(
        &mut self,
        group_id: PeerId,
        peer_id: PeerId,
        author_id: PeerId,
        sequence: u64,
    ) -> Result<(), StoreError> {
        if sequence == 0 {
            return Ok(());
        }
        let sequence =
            i64::try_from(sequence).map_err(|_| StoreError::SequenceTooLarge(sequence))?;
        self.connection.execute(
            "INSERT INTO peer_acknowledged_author_heads
                (group_id, peer_id, author_id, contiguous_sequence)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(group_id, peer_id, author_id) DO UPDATE SET
                contiguous_sequence = MAX(contiguous_sequence, excluded.contiguous_sequence)",
            params![
                group_id.to_bytes(),
                peer_id.to_bytes(),
                author_id.to_bytes(),
                sequence,
            ],
        )?;
        Ok(())
    }

    /// Records several author heads reported by one peer in one transaction.
    /// Each head only moves forward, as with [`Self::acknowledge_author_head`].
    pub fn acknowledge_author_heads(
        &mut self,
        group_id: PeerId,
        peer_id: PeerId,
        heads: &[AuthorHead],
    ) -> Result<(), StoreError> {
        let transaction = self.connection.transaction()?;
        {
            let mut statement = transaction.prepare(
                "INSERT INTO peer_acknowledged_author_heads
                    (group_id, peer_id, author_id, contiguous_sequence)
                 VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(group_id, peer_id, author_id) DO UPDATE SET
                    contiguous_sequence = MAX(contiguous_sequence, excluded.contiguous_sequence)",
            )?;
            for head in heads.iter().filter(|head| head.contiguous_sequence > 0) {
                let sequence = i64::try_from(head.contiguous_sequence)
                    .map_err(|_| StoreError::SequenceTooLarge(head.contiguous_sequence))?;
                statement.execute(params![
                    group_id.to_bytes(),
                    peer_id.to_bytes(),
                    head.author_id.to_bytes(),
                    sequence,
                ])?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    /// Returns each peer's acknowledged head for one author.
    pub fn acknowledged_author_heads(
        &self,
        group_id: PeerId,
        author_id: PeerId,
    ) -> Result<HashMap<PeerId, u64>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT peer_id, contiguous_sequence
             FROM peer_acknowledged_author_heads
             WHERE group_id = ?1 AND author_id = ?2",
        )?;
        let rows = statement
            .query_map(params![group_id.to_bytes(), author_id.to_bytes()], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
            })?;
        let mut heads = HashMap::new();
        for row in rows {
            let (peer_id, sequence) = row?;
            let peer_id = PeerId::from_bytes(&peer_id).map_err(|_| StoreError::CorruptIndex)?;
            let sequence = u64::try_from(sequence).map_err(|_| StoreError::CorruptIndex)?;
            heads.insert(peer_id, sequence);
        }
        Ok(heads)
    }

    /// Returns the highest sequence for an author accepted by any peer.
    pub fn max_acknowledged_author_head(
        &self,
        group_id: PeerId,
        author_id: PeerId,
    ) -> Result<u64, StoreError> {
        let sequence: Option<i64> = self.connection.query_row(
            "SELECT MAX(contiguous_sequence)
             FROM peer_acknowledged_author_heads
             WHERE group_id = ?1 AND author_id = ?2",
            params![group_id.to_bytes(), author_id.to_bytes()],
            |row| row.get(0),
        )?;
        sequence
            .map(|value| u64::try_from(value).map_err(|_| StoreError::CorruptIndex))
            .unwrap_or(Ok(0))
    }

    /// Removes a readable message copy from this device and prevents the
    /// retained signed event from materializing it again locally.
    pub fn hide_message_locally(
        &mut self,
        group_id: PeerId,
        event_id: &[u8; 32],
    ) -> Result<bool, StoreError> {
        let transaction = self.connection.transaction()?;
        let encoded = transaction
            .query_row(
                "SELECT encoded FROM events WHERE event_id = ?1",
                [event_id.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        let Some(encoded) = encoded else {
            return Ok(false);
        };
        let event = SignedEvent::decode(&encoded)?;
        if event.id().as_bytes() != event_id
            || event.group_id() != group_id
            || event.kind() != charp2p_core::EventKind::MessageCreated
        {
            return Err(StoreError::CorruptIndex);
        }
        let deleted = transaction.execute(
            "DELETE FROM materialized_messages WHERE event_id = ?1",
            [event_id.as_slice()],
        )?;
        if deleted == 0 {
            return Ok(false);
        }
        transaction.execute(
            "DELETE FROM unread_local_messages WHERE event_id = ?1",
            [event_id.as_slice()],
        )?;
        transaction.execute(
            "INSERT INTO hidden_local_messages (event_id, group_id)
             VALUES (?1, ?2)
             ON CONFLICT(event_id) DO NOTHING",
            params![event_id.as_slice(), group_id.to_bytes()],
        )?;
        transaction.commit()?;
        Ok(true)
    }

    /// Applies device-local retention (ADR-035): removes every readable
    /// message copy created before the cutoff, in all groups, and hides the
    /// retained signed events from future materialization. Returns the
    /// number of message copies removed.
    pub fn hide_messages_created_before(&mut self, cutoff_unix_ms: u64) -> Result<u64, StoreError> {
        let cutoff = i64::try_from(cutoff_unix_ms)
            .map_err(|_| StoreError::TimestampTooLarge(cutoff_unix_ms))?;
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO hidden_local_messages (event_id, group_id)
             SELECT event_id, group_id FROM materialized_messages
             WHERE created_at_unix_ms < ?1
             ON CONFLICT(event_id) DO NOTHING",
            [cutoff],
        )?;
        transaction.execute(
            "DELETE FROM unread_local_messages
             WHERE event_id IN (
                 SELECT event_id FROM materialized_messages
                 WHERE created_at_unix_ms < ?1
             )",
            [cutoff],
        )?;
        let removed = transaction.execute(
            "DELETE FROM materialized_messages WHERE created_at_unix_ms < ?1",
            [cutoff],
        )?;
        transaction.commit()?;
        Ok(removed as u64)
    }

    /// Counts readable messages from other devices not yet viewed on this
    /// device, grouped by group identifier.
    pub fn unread_message_counts(&self) -> Result<Vec<(PeerId, u64)>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT u.group_id, COUNT(*)
             FROM unread_local_messages u
             JOIN materialized_messages m ON m.event_id = u.event_id
             WHERE m.group_id = u.group_id
               AND NOT EXISTS (
                   SELECT 1 FROM blocked_local_devices b
                   WHERE b.group_id = m.group_id AND b.device_id = m.author_id
               )
               AND NOT EXISTS (
                   SELECT 1 FROM applied_message_deletions d
                   WHERE d.target_event_id = m.event_id
                     AND d.group_id = m.group_id
                     AND d.author_id = m.author_id
               )
             GROUP BY u.group_id
             ORDER BY u.group_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
        })?;
        rows.map(|row| {
            let (group_id, count) = row?;
            let group_id = PeerId::from_bytes(&group_id).map_err(|_| StoreError::CorruptIndex)?;
            let count = u64::try_from(count).map_err(|_| StoreError::CorruptIndex)?;
            Ok((group_id, count))
        })
        .collect()
    }

    /// Clears this device's unread markers for one group after its timeline
    /// has been shown. Returns the number of messages marked read.
    pub fn mark_messages_read(&mut self, group_id: PeerId) -> Result<u64, StoreError> {
        let cleared = self.connection.execute(
            "DELETE FROM unread_local_messages WHERE group_id = ?1",
            [group_id.to_bytes()],
        )?;
        Ok(cleared as u64)
    }

    /// Blocks one device's messages from display on this device. Its signed
    /// events stay stored and keep advancing MLS state. Returns false when the
    /// device was already blocked.
    pub fn block_device_locally(
        &mut self,
        group_id: PeerId,
        device_id: PeerId,
    ) -> Result<bool, StoreError> {
        let transaction = self.connection.transaction()?;
        let inserted = transaction.execute(
            "INSERT INTO blocked_local_devices (group_id, device_id)
             VALUES (?1, ?2)
             ON CONFLICT(group_id, device_id) DO NOTHING",
            params![group_id.to_bytes(), device_id.to_bytes()],
        )?;
        transaction.execute(
            "DELETE FROM unread_local_messages
             WHERE group_id = ?1 AND event_id IN (
                 SELECT event_id FROM materialized_messages
                 WHERE group_id = ?1 AND author_id = ?2
             )",
            params![group_id.to_bytes(), device_id.to_bytes()],
        )?;
        transaction.commit()?;
        Ok(inserted == 1)
    }

    /// Shows a locally blocked device's retained messages again. Returns
    /// false when the device was not blocked.
    pub fn unblock_device_locally(
        &mut self,
        group_id: PeerId,
        device_id: PeerId,
    ) -> Result<bool, StoreError> {
        let deleted = self.connection.execute(
            "DELETE FROM blocked_local_devices WHERE group_id = ?1 AND device_id = ?2",
            params![group_id.to_bytes(), device_id.to_bytes()],
        )?;
        Ok(deleted == 1)
    }

    /// Lists devices blocked on this device for one group.
    pub fn blocked_devices(&self, group_id: PeerId) -> Result<Vec<PeerId>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT device_id FROM blocked_local_devices
             WHERE group_id = ?1
             ORDER BY device_id",
        )?;
        let rows = statement.query_map([group_id.to_bytes()], |row| row.get::<_, Vec<u8>>(0))?;
        rows.map(|row| PeerId::from_bytes(&row?).map_err(|_| StoreError::CorruptIndex))
            .collect()
    }

    /// Returns the author of a message still readable on this device, or
    /// `None` when it is unknown or hidden locally.
    pub fn materialized_message_author(
        &self,
        group_id: PeerId,
        event_id: &[u8; 32],
    ) -> Result<Option<PeerId>, StoreError> {
        let author = self
            .connection
            .query_row(
                "SELECT author_id FROM materialized_messages
                 WHERE event_id = ?1 AND group_id = ?2",
                params![event_id.as_slice(), group_id.to_bytes()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        author
            .map(|author| PeerId::from_bytes(&author).map_err(|_| StoreError::CorruptIndex))
            .transpose()
    }

    /// Atomically stores a decrypted message edit, its locally encrypted
    /// replacement text, and the advanced encrypted MLS provider state. The
    /// edit is displayed only for a target message by the same author; the
    /// edit with the highest author sequence wins.
    pub fn put_message_edit_and_encrypted_mls_provider_snapshot(
        &mut self,
        event: &SignedEvent,
        encrypted_snapshot: &[u8],
        target_event_id: &[u8; 32],
        encrypted_body: &[u8],
    ) -> Result<PutEventOutcome, StoreError> {
        if event.kind() != charp2p_core::EventKind::MessageEdited {
            return Err(StoreError::InvalidMessageEditEvent);
        }
        validate_encrypted_mls_provider_snapshot(encrypted_snapshot)?;
        validate_encrypted_message_body(encrypted_body)?;
        let sequence = i64::try_from(event.author_sequence())
            .map_err(|_| StoreError::SequenceTooLarge(event.author_sequence()))?;
        let transaction = self.connection.transaction()?;
        let outcome = put_event_in_transaction(&transaction, event)?;
        put_encrypted_mls_provider_snapshot_in_transaction(&transaction, encrypted_snapshot)?;
        transaction.execute(
            "INSERT INTO applied_message_edits (
                event_id, group_id, author_id, author_sequence, target_event_id,
                encrypted_body
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(event_id) DO NOTHING",
            params![
                event.id().as_bytes().as_slice(),
                event.group_id().to_bytes(),
                event.author_id().to_bytes(),
                sequence,
                target_event_id.as_slice(),
                encrypted_body,
            ],
        )?;
        transaction.commit()?;
        Ok(outcome)
    }

    /// Atomically stores a decrypted group-wide message deletion and the
    /// advanced encrypted MLS provider state. The tombstone hides only a
    /// target message by the same author, whether that message is already
    /// readable here (its local copy is removed) or arrives later.
    pub fn put_message_deletion_and_encrypted_mls_provider_snapshot(
        &mut self,
        event: &SignedEvent,
        encrypted_snapshot: &[u8],
        target_event_id: &[u8; 32],
    ) -> Result<PutEventOutcome, StoreError> {
        if event.kind() != charp2p_core::EventKind::MessageDeleted {
            return Err(StoreError::InvalidMessageDeletionEvent);
        }
        validate_encrypted_mls_provider_snapshot(encrypted_snapshot)?;
        let sequence = i64::try_from(event.author_sequence())
            .map_err(|_| StoreError::SequenceTooLarge(event.author_sequence()))?;
        let transaction = self.connection.transaction()?;
        let outcome = put_event_in_transaction(&transaction, event)?;
        put_encrypted_mls_provider_snapshot_in_transaction(&transaction, encrypted_snapshot)?;
        transaction.execute(
            "INSERT INTO applied_message_deletions (
                event_id, group_id, author_id, author_sequence, target_event_id
             ) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(event_id) DO NOTHING",
            params![
                event.id().as_bytes().as_slice(),
                event.group_id().to_bytes(),
                event.author_id().to_bytes(),
                sequence,
                target_event_id.as_slice(),
            ],
        )?;
        let removed = transaction.execute(
            "DELETE FROM materialized_messages
             WHERE event_id = ?1 AND group_id = ?2 AND author_id = ?3",
            params![
                target_event_id.as_slice(),
                event.group_id().to_bytes(),
                event.author_id().to_bytes()
            ],
        )?;
        if removed == 1 {
            transaction.execute(
                "DELETE FROM unread_local_messages WHERE event_id = ?1",
                [target_event_id.as_slice()],
            )?;
            transaction.execute(
                "INSERT INTO hidden_local_messages (event_id, group_id)
                 VALUES (?1, ?2)
                 ON CONFLICT(event_id) DO NOTHING",
                params![target_event_id.as_slice(), event.group_id().to_bytes()],
            )?;
        }
        transaction.commit()?;
        Ok(outcome)
    }

    /// Atomically stores a decrypted group-metadata change and the advanced
    /// encrypted MLS provider state. The caller authorizes the author; the
    /// change with the highest author sequence becomes the current name, and
    /// the highest-sequence change carrying an icon the current icon.
    pub fn put_group_metadata_and_encrypted_mls_provider_snapshot(
        &mut self,
        event: &SignedEvent,
        encrypted_snapshot: &[u8],
        metadata: &charp2p_core::GroupMetadata,
    ) -> Result<PutEventOutcome, StoreError> {
        if event.kind() != charp2p_core::EventKind::GroupMetadataChanged {
            return Err(StoreError::InvalidGroupMetadataEvent);
        }
        validate_encrypted_mls_provider_snapshot(encrypted_snapshot)?;
        let sequence = i64::try_from(event.author_sequence())
            .map_err(|_| StoreError::SequenceTooLarge(event.author_sequence()))?;
        let transaction = self.connection.transaction()?;
        let outcome = put_event_in_transaction(&transaction, event)?;
        put_encrypted_mls_provider_snapshot_in_transaction(&transaction, encrypted_snapshot)?;
        transaction.execute(
            "INSERT INTO applied_group_metadata (
                event_id, group_id, author_id, author_sequence, group_name, icon
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(event_id) DO NOTHING",
            params![
                event.id().as_bytes().as_slice(),
                event.group_id().to_bytes(),
                event.author_id().to_bytes(),
                sequence,
                metadata.group_name(),
                metadata.icon().map(i64::from),
            ],
        )?;
        transaction.commit()?;
        Ok(outcome)
    }

    /// Atomically stores a decrypted invite permission change and the advanced
    /// encrypted MLS provider state. The caller authorizes the owner author;
    /// for each target device the change with the highest author sequence is
    /// current. A change for a removed device is stored as withdrawn.
    pub fn put_invite_permission_and_encrypted_mls_provider_snapshot(
        &mut self,
        event: &SignedEvent,
        encrypted_snapshot: &[u8],
        permission: &charp2p_core::InvitePermission,
    ) -> Result<PutEventOutcome, StoreError> {
        if event.kind() != charp2p_core::EventKind::InvitePermissionChanged {
            return Err(StoreError::InvalidInvitePermissionEvent);
        }
        validate_encrypted_mls_provider_snapshot(encrypted_snapshot)?;
        let sequence = i64::try_from(event.author_sequence())
            .map_err(|_| StoreError::SequenceTooLarge(event.author_sequence()))?;
        let transaction = self.connection.transaction()?;
        let outcome = put_event_in_transaction(&transaction, event)?;
        put_encrypted_mls_provider_snapshot_in_transaction(&transaction, encrypted_snapshot)?;
        let removed = transaction
            .query_row(
                "SELECT 1 FROM removed_mls_members
                 WHERE group_id = ?1 AND member_id = ?2",
                params![
                    event.group_id().to_bytes(),
                    permission.device_id().to_bytes()
                ],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        transaction.execute(
            "INSERT INTO applied_invite_permissions (
                event_id, group_id, author_id, author_sequence, target_device_id, granted
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(event_id) DO NOTHING",
            params![
                event.id().as_bytes().as_slice(),
                event.group_id().to_bytes(),
                event.author_id().to_bytes(),
                sequence,
                permission.device_id().to_bytes(),
                permission.granted() && !removed,
            ],
        )?;
        transaction.commit()?;
        Ok(outcome)
    }

    /// Reports whether the owner's latest applied change for this device
    /// grants permission to request invitations and the device is not removed.
    pub fn has_invite_permission(
        &self,
        group_id: PeerId,
        device_id: PeerId,
    ) -> Result<bool, StoreError> {
        Ok(self
            .invite_permitted_devices(group_id)?
            .contains(&device_id))
    }

    /// Lists the non-removed devices currently granted permission to request
    /// invitations, ordered by device identifier.
    pub fn invite_permitted_devices(&self, group_id: PeerId) -> Result<Vec<PeerId>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT p.target_device_id
             FROM applied_invite_permissions p
             WHERE p.group_id = ?1 AND p.granted = 1
               AND p.author_sequence = (
                   SELECT MAX(latest.author_sequence)
                   FROM applied_invite_permissions latest
                   WHERE latest.group_id = p.group_id
                     AND latest.target_device_id = p.target_device_id
               )
               AND NOT EXISTS (
                   SELECT 1 FROM removed_mls_members r
                   WHERE r.group_id = p.group_id AND r.member_id = p.target_device_id
               )
             ORDER BY p.target_device_id",
        )?;
        let rows = statement.query_map([group_id.to_bytes()], |row| row.get::<_, Vec<u8>>(0))?;
        let mut devices = Vec::new();
        for row in rows {
            devices.push(PeerId::from_bytes(&row?).map_err(|_| StoreError::CorruptIndex)?);
        }
        Ok(devices)
    }

    /// Returns the current authenticated group name for every group with an
    /// applied metadata change.
    pub fn current_group_names(&self) -> Result<Vec<(PeerId, String)>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT g.group_id, g.group_name
             FROM applied_group_metadata g
             WHERE g.author_sequence = (
                 SELECT MAX(latest.author_sequence)
                 FROM applied_group_metadata latest
                 WHERE latest.group_id = g.group_id
             )
             ORDER BY g.group_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.map(|row| {
            let (group_id, group_name) = row?;
            let group_id = PeerId::from_bytes(&group_id).map_err(|_| StoreError::CorruptIndex)?;
            charp2p_core::GroupMetadata::new(&group_name).map_err(|_| StoreError::CorruptIndex)?;
            Ok((group_id, group_name))
        })
        .collect()
    }

    /// Returns the current authenticated group icon for every group with an
    /// applied metadata change carrying one. Version 1 changes without an
    /// icon keep the previously known icon.
    pub fn current_group_icons(&self) -> Result<Vec<(PeerId, u8)>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT g.group_id, g.icon
             FROM applied_group_metadata g
             WHERE g.icon IS NOT NULL
               AND g.author_sequence = (
                   SELECT MAX(latest.author_sequence)
                   FROM applied_group_metadata latest
                   WHERE latest.group_id = g.group_id AND latest.icon IS NOT NULL
               )
             ORDER BY g.group_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?))
        })?;
        rows.map(|row| {
            let (group_id, icon) = row?;
            let group_id = PeerId::from_bytes(&group_id).map_err(|_| StoreError::CorruptIndex)?;
            let icon = u8::try_from(icon)
                .ok()
                .filter(|icon| *icon <= charp2p_core::MAX_GROUP_ICON)
                .ok_or(StoreError::CorruptIndex)?;
            Ok((group_id, icon))
        })
        .collect()
    }

    /// Returns at most `limit` verified message, edit, deletion,
    /// group-metadata, and invite-permission events that
    /// have not been decrypted locally yet. Events are ordered by author and
    /// sequence so each sender ratchet advances consistently.
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
             LEFT JOIN hidden_local_messages h ON h.event_id = e.event_id
             LEFT JOIN applied_group_metadata g ON g.event_id = e.event_id
             LEFT JOIN applied_message_edits x ON x.event_id = e.event_id
             LEFT JOIN applied_invite_permissions p ON p.event_id = e.event_id
             LEFT JOIN applied_message_deletions d ON d.event_id = e.event_id
             WHERE e.group_id = ?1 AND m.event_id IS NULL AND h.event_id IS NULL
               AND g.event_id IS NULL AND x.event_id IS NULL AND p.event_id IS NULL
               AND d.event_id IS NULL
             ORDER BY e.author_id, e.author_sequence",
        )?;
        let rows = statement.query_map([group_id.to_bytes()], |row| row.get::<_, Vec<u8>>(0))?;
        let mut events = Vec::with_capacity(limit);
        for encoded in rows {
            let event = SignedEvent::decode(&encoded?)?;
            if event.group_id() != group_id {
                return Err(StoreError::CorruptIndex);
            }
            if matches!(
                event.kind(),
                charp2p_core::EventKind::MessageCreated
                    | charp2p_core::EventKind::MessageEdited
                    | charp2p_core::EventKind::MessageDeleted
                    | charp2p_core::EventKind::GroupMetadataChanged
                    | charp2p_core::EventKind::InvitePermissionChanged
            ) {
                events.push(event);
                if events.len() == limit {
                    break;
                }
            }
        }
        Ok(events)
    }

    /// Returns verified MLS commits (membership changes and owner key
    /// refreshes) that have not advanced the local provider snapshot yet.
    pub fn unapplied_mls_commit_events(
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
             LEFT JOIN applied_mls_events a ON a.event_id = e.event_id
             WHERE e.group_id = ?1 AND a.event_id IS NULL
             ORDER BY e.author_id, e.author_sequence",
        )?;
        let rows = statement.query_map([group_id.to_bytes()], |row| row.get::<_, Vec<u8>>(0))?;
        let mut events = Vec::with_capacity(limit);
        for encoded in rows {
            let event = SignedEvent::decode(&encoded?)?;
            if event.group_id() != group_id {
                return Err(StoreError::CorruptIndex);
            }
            if is_mls_commit_kind(event.kind()) {
                events.push(event);
                if events.len() == limit {
                    break;
                }
            }
        }
        Ok(events)
    }

    /// Atomically records an applied MLS commit and the resulting encrypted
    /// provider state.
    pub fn put_applied_mls_event_and_encrypted_provider_snapshot(
        &mut self,
        event: &SignedEvent,
        encrypted_snapshot: &[u8],
    ) -> Result<bool, StoreError> {
        if !is_mls_commit_kind(event.kind()) {
            return Err(StoreError::CorruptIndex);
        }
        validate_encrypted_mls_provider_snapshot(encrypted_snapshot)?;
        let transaction = self.connection.transaction()?;
        let stored: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT encoded FROM events WHERE event_id = ?1",
                [event.id().as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        let Some(stored) = stored else {
            return Err(StoreError::CorruptIndex);
        };
        if SignedEvent::decode(&stored)?.id() != event.id() {
            return Err(StoreError::CorruptIndex);
        }
        put_encrypted_mls_provider_snapshot_in_transaction(&transaction, encrypted_snapshot)?;
        let inserted = transaction.execute(
            "INSERT INTO applied_mls_events (event_id, group_id)
             VALUES (?1, ?2)
             ON CONFLICT(event_id) DO NOTHING",
            params![
                event.id().as_bytes().as_slice(),
                event.group_id().to_bytes()
            ],
        )? != 0;
        transaction.commit()?;
        Ok(inserted)
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

    /// Returns the stored membership commit count and newest commit for the
    /// synchronization summary.
    ///
    /// Owner key refreshes count as commits because later messages depend on
    /// their epoch (ADR-045). Commits are owner-authored, so the newest one is
    /// the commit with the highest author sequence.
    pub fn membership_state(&self, group_id: PeerId) -> Result<SyncMembershipState, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT encoded FROM events WHERE group_id = ?1
             ORDER BY author_sequence, event_id",
        )?;
        let encoded = statement.query_map([group_id.to_bytes()], |row| row.get::<_, Vec<u8>>(0))?;
        let mut state = SyncMembershipState::default();
        for bytes in encoded {
            let event = SignedEvent::decode(&bytes?)?;
            if event.group_id() != group_id {
                return Err(StoreError::CorruptIndex);
            }
            if is_mls_commit_kind(event.kind()) {
                state.commits += 1;
                state.latest_commit = Some(event.id());
            }
        }
        Ok(state)
    }

    /// Returns each author's latest signed creation time among stored events.
    ///
    /// The time comes from the author's highest stored sequence and is the
    /// author's own signed claim, not a locally observed clock.
    pub fn latest_author_activity(
        &self,
        group_id: PeerId,
    ) -> Result<Vec<(PeerId, u64)>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT encoded FROM events AS latest
             WHERE group_id = ?1
               AND author_sequence = (
                   SELECT MAX(author_sequence) FROM events
                   WHERE group_id = latest.group_id AND author_id = latest.author_id
               )",
        )?;
        let encoded = statement.query_map([group_id.to_bytes()], |row| row.get::<_, Vec<u8>>(0))?;
        let mut activity = Vec::new();
        for bytes in encoded {
            let event = SignedEvent::decode(&bytes?)?;
            if event.group_id() != group_id {
                return Err(StoreError::CorruptIndex);
            }
            activity.push((event.author_id(), event.created_at_unix_ms()));
        }
        activity.sort_by_key(|(author_id, _)| author_id.to_bytes());
        Ok(activity)
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
            "SELECT group_id, group_name, inviter_name, inviter_device_id, history_policy,
                    last_synchronized_at_unix
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
                row.get::<_, Option<i64>>(5)?,
            ))
        })?;
        let mut groups = Vec::new();
        for row in rows {
            let (
                group_id,
                group_name,
                inviter_name,
                inviter_device_id,
                history_policy,
                last_synchronized_at_unix,
            ) = row?;
            groups.push(JoinedGroupMetadata {
                group_id: PeerId::from_bytes(&group_id).map_err(|_| StoreError::CorruptIndex)?,
                group_name,
                inviter_name,
                inviter_device_id: PeerId::from_bytes(&inviter_device_id)
                    .map_err(|_| StoreError::CorruptIndex)?,
                history_policy: history_policy_from_code(history_policy)?,
                last_synchronized_at_unix: last_synchronized_at_unix
                    .map(|timestamp| u64::try_from(timestamp).map_err(|_| StoreError::CorruptIndex))
                    .transpose()?,
            });
        }
        Ok(groups)
    }

    /// Records the most recent successful peer synchronization for a joined group.
    pub fn record_joined_group_synchronization(
        &mut self,
        group_id: PeerId,
        synchronized_at_unix: u64,
    ) -> Result<bool, StoreError> {
        let synchronized_at_unix = i64::try_from(synchronized_at_unix)
            .map_err(|_| StoreError::TimestampTooLarge(synchronized_at_unix))?;
        Ok(self.connection.execute(
            "UPDATE joined_groups
             SET last_synchronized_at_unix = ?2
             WHERE group_id = ?1",
            params![group_id.to_bytes(), synchronized_at_unix],
        )? > 0)
    }

    /// Remembers that synchronization with a group peer completed through
    /// this address, keeping only the most recent successful addresses.
    pub fn record_peer_address_success(
        &mut self,
        group_id: PeerId,
        peer_id: PeerId,
        address: &[u8],
        succeeded_at_unix: u64,
    ) -> Result<(), StoreError> {
        if address.is_empty() || address.len() > MAX_PEER_ADDRESS_BYTES {
            return Err(StoreError::InvalidPeerAddressSize(address.len()));
        }
        let succeeded_at_unix = i64::try_from(succeeded_at_unix)
            .map_err(|_| StoreError::TimestampTooLarge(succeeded_at_unix))?;
        let limit = i64::try_from(MAX_PEER_ADDRESSES).expect("peer address limit fits in i64");
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO peer_addresses (group_id, peer_id, address, last_success_at_unix)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(group_id, peer_id, address)
             DO UPDATE SET last_success_at_unix = max(last_success_at_unix, excluded.last_success_at_unix)",
            params![
                group_id.to_bytes(),
                peer_id.to_bytes(),
                address,
                succeeded_at_unix
            ],
        )?;
        transaction.execute(
            "DELETE FROM peer_addresses
             WHERE group_id = ?1 AND peer_id = ?2 AND address NOT IN (
                 SELECT address FROM peer_addresses
                 WHERE group_id = ?1 AND peer_id = ?2
                 ORDER BY last_success_at_unix DESC, address
                 LIMIT ?3
             )",
            params![group_id.to_bytes(), peer_id.to_bytes(), limit],
        )?;
        transaction.commit()?;
        Ok(())
    }

    /// Lists the remembered successful addresses of a group peer, most
    /// recent first.
    pub fn peer_addresses(
        &self,
        group_id: PeerId,
        peer_id: PeerId,
    ) -> Result<Vec<PeerAddress>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT address, last_success_at_unix FROM peer_addresses
             WHERE group_id = ?1 AND peer_id = ?2
             ORDER BY last_success_at_unix DESC, address
             LIMIT ?3",
        )?;
        let limit = i64::try_from(MAX_PEER_ADDRESSES).expect("peer address limit fits in i64");
        let rows = statement.query_map(
            params![group_id.to_bytes(), peer_id.to_bytes(), limit],
            |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
        )?;
        rows.map(|row| {
            let (address, last_success_at_unix) = row?;
            Ok(PeerAddress {
                address,
                last_success_at_unix: u64::try_from(last_success_at_unix)
                    .map_err(|_| StoreError::CorruptIndex)?,
            })
        })
        .collect()
    }

    /// Atomically forgets a joined group on this device: its display metadata,
    /// signed events with every dependent local record, peer acknowledgements,
    /// remembered peer addresses and local blocks, together with the provider state that no longer
    /// contains the MLS group.
    pub fn leave_joined_group_and_put_encrypted_mls_provider_snapshot(
        &mut self,
        group_id: PeerId,
        encrypted: &[u8],
    ) -> Result<bool, StoreError> {
        validate_encrypted_mls_provider_snapshot(encrypted)?;
        let transaction = self.connection.transaction()?;
        let group_id = group_id.to_bytes();
        let removed =
            transaction.execute("DELETE FROM joined_groups WHERE group_id = ?1", [&group_id])? != 0;
        if !removed {
            return Ok(false);
        }
        for statement in [
            "DELETE FROM events WHERE group_id = ?1",
            "DELETE FROM peer_acknowledged_author_heads WHERE group_id = ?1",
            "DELETE FROM blocked_local_devices WHERE group_id = ?1",
            "DELETE FROM peer_addresses WHERE group_id = ?1",
            "DELETE FROM sequence_conflicts WHERE group_id = ?1",
        ] {
            transaction.execute(statement, [&group_id])?;
        }
        put_encrypted_mls_provider_snapshot_in_transaction(&transaction, encrypted)?;
        transaction.commit()?;
        Ok(true)
    }

    /// Records an authorized join request for an approval-required group and
    /// reports the owner's decision for that device. Undecided and approved
    /// requests expire with their invitation; declines stay until cleared.
    pub fn record_owner_approval_request(
        &mut self,
        group_id: PeerId,
        device_id: PeerId,
        invitation_id: InvitationId,
        expires_at_unix: u64,
        now_unix: u64,
    ) -> Result<ApprovalRequestOutcome, StoreError> {
        let expires = i64::try_from(expires_at_unix)
            .map_err(|_| StoreError::TimestampTooLarge(expires_at_unix))?;
        let now = i64::try_from(now_unix).map_err(|_| StoreError::TimestampTooLarge(now_unix))?;
        let transaction = self.connection.transaction()?;
        prune_expired_approval_requests(&transaction, group_id, now)?;
        let existing: Option<i64> = transaction
            .query_row(
                "SELECT state FROM owner_approval_requests
                 WHERE group_id = ?1 AND device_id = ?2",
                params![group_id.to_bytes(), device_id.to_bytes()],
                |row| row.get(0),
            )
            .optional()?;
        let outcome = match existing.map(approval_state_from_code).transpose()? {
            Some(ApprovalState::Declined) => ApprovalRequestOutcome::Declined,
            Some(state) => {
                transaction.execute(
                    "UPDATE owner_approval_requests SET last_requested_at_unix = ?3
                     WHERE group_id = ?1 AND device_id = ?2",
                    params![group_id.to_bytes(), device_id.to_bytes(), now],
                )?;
                if state == ApprovalState::Pending {
                    // A newer invitation keeps the request alive as long as it.
                    transaction.execute(
                        "UPDATE owner_approval_requests
                         SET invitation_id = ?3, expires_at_unix = ?4
                         WHERE group_id = ?1 AND device_id = ?2 AND expires_at_unix < ?4",
                        params![
                            group_id.to_bytes(),
                            device_id.to_bytes(),
                            invitation_id.as_bytes().as_slice(),
                            expires,
                        ],
                    )?;
                    ApprovalRequestOutcome::Pending
                } else {
                    ApprovalRequestOutcome::Approved
                }
            }
            None => {
                let pending: i64 = transaction.query_row(
                    "SELECT COUNT(*) FROM owner_approval_requests
                     WHERE group_id = ?1 AND state = ?2",
                    params![
                        group_id.to_bytes(),
                        approval_state_code(ApprovalState::Pending)
                    ],
                    |row| row.get(0),
                )?;
                if usize::try_from(pending).map_err(|_| StoreError::CorruptIndex)?
                    >= MAX_PENDING_APPROVAL_REQUESTS_PER_GROUP
                {
                    ApprovalRequestOutcome::Full
                } else {
                    transaction.execute(
                        "INSERT INTO owner_approval_requests (
                            group_id, device_id, invitation_id, expires_at_unix,
                            first_requested_at_unix, last_requested_at_unix, state
                         ) VALUES (?1, ?2, ?3, ?4, ?5, ?5, ?6)",
                        params![
                            group_id.to_bytes(),
                            device_id.to_bytes(),
                            invitation_id.as_bytes().as_slice(),
                            expires,
                            now,
                            approval_state_code(ApprovalState::Pending),
                        ],
                    )?;
                    ApprovalRequestOutcome::Pending
                }
            }
        };
        transaction.commit()?;
        Ok(outcome)
    }

    /// Approves an undecided request so the device's next retry is admitted.
    /// Returns false when no undecided request exists for the device.
    pub fn approve_owner_approval_request(
        &mut self,
        group_id: PeerId,
        device_id: PeerId,
    ) -> Result<bool, StoreError> {
        self.decide_owner_approval_request(group_id, device_id, ApprovalState::Approved)
    }

    /// Declines an undecided or approved request; later requests from the
    /// device are rejected until the decline is cleared. Returns false when
    /// the device has no such request.
    pub fn decline_owner_approval_request(
        &mut self,
        group_id: PeerId,
        device_id: PeerId,
    ) -> Result<bool, StoreError> {
        self.decide_owner_approval_request(group_id, device_id, ApprovalState::Declined)
    }

    fn decide_owner_approval_request(
        &mut self,
        group_id: PeerId,
        device_id: PeerId,
        state: ApprovalState,
    ) -> Result<bool, StoreError> {
        Ok(self.connection.execute(
            "UPDATE owner_approval_requests SET state = ?3
             WHERE group_id = ?1 AND device_id = ?2 AND state IN (?4, ?5) AND state != ?3",
            params![
                group_id.to_bytes(),
                device_id.to_bytes(),
                approval_state_code(state),
                approval_state_code(ApprovalState::Pending),
                approval_state_code(ApprovalState::Approved),
            ],
        )? > 0)
    }

    /// Clears a declined device so its next request is recorded again.
    /// Returns false when the device was not declined.
    pub fn clear_declined_approval_request(
        &mut self,
        group_id: PeerId,
        device_id: PeerId,
    ) -> Result<bool, StoreError> {
        Ok(self.connection.execute(
            "DELETE FROM owner_approval_requests
             WHERE group_id = ?1 AND device_id = ?2 AND state = ?3",
            params![
                group_id.to_bytes(),
                device_id.to_bytes(),
                approval_state_code(ApprovalState::Declined),
            ],
        )? > 0)
    }

    /// Lists unexpired approval requests and declines for one group, oldest
    /// request first.
    pub fn owner_approval_requests(
        &self,
        group_id: PeerId,
        now_unix: u64,
    ) -> Result<Vec<OwnerApprovalRequest>, StoreError> {
        let now = i64::try_from(now_unix).map_err(|_| StoreError::TimestampTooLarge(now_unix))?;
        let mut statement = self.connection.prepare(
            "SELECT device_id, invitation_id, expires_at_unix, first_requested_at_unix,
                    last_requested_at_unix, state
             FROM owner_approval_requests
             WHERE group_id = ?1 AND (state = ?2 OR expires_at_unix > ?3)
             ORDER BY first_requested_at_unix, device_id",
        )?;
        let rows = statement.query_map(
            params![
                group_id.to_bytes(),
                approval_state_code(ApprovalState::Declined),
                now
            ],
            |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                ))
            },
        )?;
        let mut requests = Vec::new();
        for row in rows {
            let (device_id, invitation_id, expires, first, last, state) = row?;
            let invitation_id: [u8; 16] = invitation_id
                .try_into()
                .map_err(|_| StoreError::CorruptIndex)?;
            let timestamp = |value: i64| u64::try_from(value).map_err(|_| StoreError::CorruptIndex);
            requests.push(OwnerApprovalRequest {
                group_id,
                device_id: PeerId::from_bytes(&device_id).map_err(|_| StoreError::CorruptIndex)?,
                invitation_id: InvitationId::from_bytes(invitation_id),
                expires_at_unix: timestamp(expires)?,
                first_requested_at_unix: timestamp(first)?,
                last_requested_at_unix: timestamp(last)?,
                state: approval_state_from_code(state)?,
            });
        }
        Ok(requests)
    }

    /// Adds the non-secret index for a newly issued bearer invitation.
    pub fn put_issued_invitation(
        &mut self,
        invitation: &IssuedInvitationMetadata,
    ) -> Result<(), StoreError> {
        let expires_at_unix = i64::try_from(invitation.expires_at_unix)
            .map_err(|_| StoreError::TimestampTooLarge(invitation.expires_at_unix))?;
        self.connection.execute(
            "INSERT INTO issued_invitations
                (invitation_id, group_id, expires_at_unix, requested_by_device_id)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                invitation.invitation_id.as_bytes().as_slice(),
                invitation.group_id.to_bytes(),
                expires_at_unix,
                invitation.requested_by.map(|device| device.to_bytes()),
            ],
        )?;
        Ok(())
    }

    /// Lists issued invitation indexes without exposing their bearer secrets.
    pub fn issued_invitations(&self) -> Result<Vec<IssuedInvitationMetadata>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT invitation_id, group_id, expires_at_unix, requested_by_device_id
             FROM issued_invitations
             ORDER BY expires_at_unix DESC, invitation_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<Vec<u8>>>(3)?,
            ))
        })?;
        let mut invitations = Vec::new();
        for row in rows {
            let (invitation_id, group_id, expires_at_unix, requested_by) = row?;
            let invitation_id: [u8; 16] = invitation_id
                .try_into()
                .map_err(|_| StoreError::CorruptIndex)?;
            invitations.push(IssuedInvitationMetadata {
                invitation_id: InvitationId::from_bytes(invitation_id),
                group_id: PeerId::from_bytes(&group_id).map_err(|_| StoreError::CorruptIndex)?,
                expires_at_unix: u64::try_from(expires_at_unix)
                    .map_err(|_| StoreError::CorruptIndex)?,
                requested_by: requested_by
                    .map(|device| PeerId::from_bytes(&device))
                    .transpose()
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

    /// Adds the index for an owner-side rendezvous key kept in protected storage.
    pub fn put_owner_discovery_key(
        &mut self,
        metadata: &OwnerDiscoveryKeyMetadata,
    ) -> Result<(), StoreError> {
        self.connection.execute(
            "INSERT INTO owner_discovery_keys (invitation_id, group_id)
             VALUES (?1, ?2)
             ON CONFLICT(invitation_id) DO NOTHING",
            params![
                metadata.invitation_id.as_bytes().as_slice(),
                metadata.group_id.to_bytes(),
            ],
        )?;
        let stored_group_id: Vec<u8> = self.connection.query_row(
            "SELECT group_id FROM owner_discovery_keys WHERE invitation_id = ?1",
            [metadata.invitation_id.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        if stored_group_id != metadata.group_id.to_bytes() {
            return Err(StoreError::CorruptIndex);
        }
        Ok(())
    }

    /// Lists rendezvous-key indexes for a locally owned group.
    pub fn owner_discovery_keys(
        &self,
        group_id: PeerId,
    ) -> Result<Vec<OwnerDiscoveryKeyMetadata>, StoreError> {
        let mut statement = self.connection.prepare(
            "SELECT invitation_id, group_id
             FROM owner_discovery_keys
             WHERE group_id = ?1
             ORDER BY invitation_id",
        )?;
        let rows = statement.query_map([group_id.to_bytes()], |row| {
            Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
        })?;
        let mut keys = Vec::new();
        for row in rows {
            let (invitation_id, stored_group_id) = row?;
            let invitation_id: [u8; 16] = invitation_id
                .try_into()
                .map_err(|_| StoreError::CorruptIndex)?;
            let stored_group_id =
                PeerId::from_bytes(&stored_group_id).map_err(|_| StoreError::CorruptIndex)?;
            if stored_group_id != group_id {
                return Err(StoreError::CorruptIndex);
            }
            keys.push(OwnerDiscoveryKeyMetadata {
                invitation_id: InvitationId::from_bytes(invitation_id),
                group_id,
            });
        }
        Ok(keys)
    }

    /// Removes a dangling owner rendezvous-key index.
    pub fn remove_owner_discovery_key(
        &mut self,
        invitation_id: InvitationId,
    ) -> Result<bool, StoreError> {
        Ok(self.connection.execute(
            "DELETE FROM owner_discovery_keys WHERE invitation_id = ?1",
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
            6..=27 => {}
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

        if version <= 8 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE applied_mls_events (
                    event_id BLOB PRIMARY KEY NOT NULL
                        CHECK(length(event_id) = 32)
                        REFERENCES events(event_id) ON DELETE CASCADE,
                    group_id BLOB NOT NULL
                 ) STRICT;

                 CREATE INDEX applied_mls_events_by_group
                    ON applied_mls_events(group_id, event_id);",
            )?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.commit()?;
        }

        if version <= 9 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE mls_join_admissions (
                    group_id BLOB NOT NULL,
                    member_id BLOB NOT NULL,
                    request_hash BLOB NOT NULL CHECK(length(request_hash) = 32),
                    encrypted_response BLOB NOT NULL
                        CHECK(length(encrypted_response) BETWEEN 1 AND 131121),
                    event_id BLOB NOT NULL
                        CHECK(length(event_id) = 32)
                        REFERENCES events(event_id) ON DELETE CASCADE,
                    PRIMARY KEY(group_id, member_id)
                 ) STRICT;",
            )?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.commit()?;
        }

        if version <= 10 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS removed_mls_members (
                    group_id BLOB NOT NULL,
                    member_id BLOB NOT NULL,
                    removal_event_id BLOB NOT NULL
                        CHECK(length(removal_event_id) = 32)
                        REFERENCES events(event_id) ON DELETE CASCADE,
                    PRIMARY KEY(group_id, member_id)
                 ) STRICT;",
            )?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.commit()?;
        }

        if version <= 11 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS hidden_local_messages (
                    event_id BLOB PRIMARY KEY NOT NULL
                        CHECK(length(event_id) = 32)
                        REFERENCES events(event_id) ON DELETE CASCADE,
                    group_id BLOB NOT NULL
                 ) STRICT;

                 CREATE INDEX IF NOT EXISTS hidden_local_messages_by_group
                    ON hidden_local_messages(group_id, event_id);",
            )?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.commit()?;
        }

        if version <= 12 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS peer_acknowledged_author_heads (
                    group_id BLOB NOT NULL,
                    peer_id BLOB NOT NULL,
                    author_id BLOB NOT NULL,
                    contiguous_sequence INTEGER NOT NULL
                        CHECK(contiguous_sequence > 0),
                    PRIMARY KEY(group_id, peer_id, author_id)
                 ) STRICT;

                 CREATE INDEX IF NOT EXISTS peer_acknowledged_heads_by_group_author
                    ON peer_acknowledged_author_heads(
                        group_id, author_id, contiguous_sequence
                    );",
            )?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.commit()?;
        }

        if version <= 13 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS owner_discovery_keys (
                    invitation_id BLOB PRIMARY KEY NOT NULL
                        CHECK(length(invitation_id) = 16),
                    group_id BLOB NOT NULL
                 ) STRICT;

                 CREATE INDEX IF NOT EXISTS owner_discovery_keys_by_group
                    ON owner_discovery_keys(group_id, invitation_id);",
            )?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.commit()?;
        }

        if version <= 14 {
            let joined_groups_exists = connection.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM sqlite_schema
                    WHERE type = 'table' AND name = 'joined_groups'
                 )",
                [],
                |row| row.get::<_, bool>(0),
            )?;
            let sync_column_exists = connection.query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM pragma_table_info('joined_groups')
                    WHERE name = 'last_synchronized_at_unix'
                 )",
                [],
                |row| row.get::<_, bool>(0),
            )?;
            let transaction = connection.transaction()?;
            if joined_groups_exists && !sync_column_exists {
                transaction.execute_batch(
                    "ALTER TABLE joined_groups
                     ADD COLUMN last_synchronized_at_unix INTEGER
                        CHECK(last_synchronized_at_unix >= 0);",
                )?;
            }
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.commit()?;
        }

        if version <= 15 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS unread_local_messages (
                    event_id BLOB PRIMARY KEY NOT NULL
                        CHECK(length(event_id) = 32)
                        REFERENCES events(event_id) ON DELETE CASCADE,
                    group_id BLOB NOT NULL
                 ) STRICT;

                 CREATE INDEX IF NOT EXISTS unread_local_messages_by_group
                    ON unread_local_messages(group_id, event_id);",
            )?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.commit()?;
        }

        if version <= 16 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS blocked_local_devices (
                    group_id BLOB NOT NULL,
                    device_id BLOB NOT NULL,
                    PRIMARY KEY(group_id, device_id)
                 ) STRICT;",
            )?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.commit()?;
        }

        if version <= 17 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS applied_group_metadata (
                    event_id BLOB PRIMARY KEY NOT NULL
                        CHECK(length(event_id) = 32)
                        REFERENCES events(event_id) ON DELETE CASCADE,
                    group_id BLOB NOT NULL,
                    author_id BLOB NOT NULL,
                    author_sequence INTEGER NOT NULL CHECK(author_sequence > 0),
                    group_name TEXT NOT NULL
                 ) STRICT;

                 CREATE INDEX IF NOT EXISTS applied_group_metadata_by_group
                    ON applied_group_metadata(group_id, author_sequence);",
            )?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.commit()?;
        }

        if version <= 18 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS applied_message_edits (
                    event_id BLOB PRIMARY KEY NOT NULL
                        CHECK(length(event_id) = 32)
                        REFERENCES events(event_id) ON DELETE CASCADE,
                    group_id BLOB NOT NULL,
                    author_id BLOB NOT NULL,
                    author_sequence INTEGER NOT NULL CHECK(author_sequence > 0),
                    target_event_id BLOB NOT NULL CHECK(length(target_event_id) = 32),
                    encrypted_body BLOB NOT NULL
                        CHECK(length(encrypted_body) BETWEEN 1 AND 16426)
                 ) STRICT;

                 CREATE INDEX IF NOT EXISTS applied_message_edits_by_target
                    ON applied_message_edits(target_event_id, author_sequence);",
            )?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.commit()?;
        }

        if version <= 19 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS message_reply_references (
                    event_id BLOB PRIMARY KEY NOT NULL
                        CHECK(length(event_id) = 32)
                        REFERENCES events(event_id) ON DELETE CASCADE,
                    reply_to_event_id BLOB NOT NULL CHECK(length(reply_to_event_id) = 32)
                 ) STRICT;",
            )?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.commit()?;
        }

        if version <= 20 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS peer_addresses (
                    group_id BLOB NOT NULL,
                    peer_id BLOB NOT NULL,
                    address BLOB NOT NULL CHECK(length(address) BETWEEN 1 AND 512),
                    last_success_at_unix INTEGER NOT NULL CHECK(last_success_at_unix >= 0),
                    PRIMARY KEY(group_id, peer_id, address)
                 ) STRICT;",
            )?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.commit()?;
        }

        if version <= 21 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS sequence_conflicts (
                    group_id BLOB NOT NULL,
                    author_id BLOB NOT NULL,
                    author_sequence INTEGER NOT NULL CHECK(author_sequence > 0),
                    stored_event_id BLOB NOT NULL CHECK(length(stored_event_id) = 32),
                    conflicting_event_id BLOB NOT NULL CHECK(length(conflicting_event_id) = 32),
                    PRIMARY KEY(group_id, author_id, author_sequence)
                 ) STRICT;",
            )?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.commit()?;
        }

        if version <= 22 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS applied_invite_permissions (
                    event_id BLOB PRIMARY KEY NOT NULL
                        CHECK(length(event_id) = 32)
                        REFERENCES events(event_id) ON DELETE CASCADE,
                    group_id BLOB NOT NULL,
                    author_id BLOB NOT NULL,
                    author_sequence INTEGER NOT NULL CHECK(author_sequence > 0),
                    target_device_id BLOB NOT NULL,
                    granted INTEGER NOT NULL CHECK(granted IN (0, 1))
                 ) STRICT;

                 CREATE INDEX IF NOT EXISTS applied_invite_permissions_by_target
                    ON applied_invite_permissions(group_id, target_device_id, author_sequence);",
            )?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.commit()?;
        }

        if version <= 23 {
            let transaction = connection.transaction()?;
            // Older stores that never created the index need no column.
            let (has_index, has_requester): (bool, bool) = transaction.query_row(
                "SELECT COUNT(*) > 0, COALESCE(SUM(name = 'requested_by_device_id'), 0) > 0
                 FROM pragma_table_info('issued_invitations')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if has_index && !has_requester {
                transaction.execute_batch(
                    "ALTER TABLE issued_invitations ADD COLUMN requested_by_device_id BLOB;",
                )?;
            }
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.commit()?;
        }

        if version <= 24 {
            let transaction = connection.transaction()?;
            let has_icon: bool = transaction.query_row(
                "SELECT COUNT(*) > 0 FROM pragma_table_info('applied_group_metadata')
                 WHERE name = 'icon'",
                [],
                |row| row.get(0),
            )?;
            if !has_icon {
                transaction.execute_batch(
                    "ALTER TABLE applied_group_metadata ADD COLUMN icon INTEGER
                        CHECK(icon IS NULL OR icon BETWEEN 0 AND 4);",
                )?;
            }
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.commit()?;
        }

        if version <= 25 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS owner_approval_requests (
                    group_id BLOB NOT NULL,
                    device_id BLOB NOT NULL,
                    invitation_id BLOB NOT NULL CHECK(length(invitation_id) = 16),
                    expires_at_unix INTEGER NOT NULL CHECK(expires_at_unix >= 0),
                    first_requested_at_unix INTEGER NOT NULL
                        CHECK(first_requested_at_unix >= 0),
                    last_requested_at_unix INTEGER NOT NULL
                        CHECK(last_requested_at_unix >= first_requested_at_unix),
                    state INTEGER NOT NULL CHECK(state BETWEEN 0 AND 2),
                    PRIMARY KEY (group_id, device_id)
                 ) STRICT;",
            )?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.commit()?;
        }

        if version <= 26 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS consumed_single_use_invitations (
                    invitation_id BLOB PRIMARY KEY NOT NULL
                        CHECK(length(invitation_id) = 16),
                    group_id BLOB NOT NULL,
                    member_id BLOB NOT NULL,
                    event_id BLOB NOT NULL CHECK(length(event_id) = 32)
                 ) STRICT;",
            )?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.commit()?;
        }

        if version <= 27 {
            let transaction = connection.transaction()?;
            transaction.execute_batch(
                "CREATE TABLE IF NOT EXISTS applied_message_deletions (
                    event_id BLOB PRIMARY KEY NOT NULL
                        CHECK(length(event_id) = 32)
                        REFERENCES events(event_id) ON DELETE CASCADE,
                    group_id BLOB NOT NULL,
                    author_id BLOB NOT NULL,
                    author_sequence INTEGER NOT NULL CHECK(author_sequence > 0),
                    target_event_id BLOB NOT NULL CHECK(length(target_event_id) = 32)
                 ) STRICT;

                 CREATE INDEX IF NOT EXISTS applied_message_deletions_by_target
                    ON applied_message_deletions(target_event_id);",
            )?;
            transaction.pragma_update(None, "user_version", SCHEMA_VERSION)?;
            transaction.commit()?;
        }

        Ok(Self { connection })
    }
}

/// Whether an event kind carries an owner-authored MLS commit that advances
/// the group epoch.
fn is_mls_commit_kind(kind: charp2p_core::EventKind) -> bool {
    matches!(
        kind,
        charp2p_core::EventKind::MemberAdded
            | charp2p_core::EventKind::MemberRemoved
            | charp2p_core::EventKind::KeyEpochAdvanced
    )
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

fn validate_encrypted_join_response(encrypted: &[u8]) -> Result<(), StoreError> {
    if encrypted.is_empty() || encrypted.len() > MAX_ENCRYPTED_JOIN_RESPONSE_BYTES {
        return Err(StoreError::InvalidEncryptedJoinResponseSize(
            encrypted.len(),
        ));
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

fn approval_state_code(state: ApprovalState) -> i64 {
    match state {
        ApprovalState::Pending => 0,
        ApprovalState::Approved => 1,
        ApprovalState::Declined => 2,
    }
}

fn approval_state_from_code(code: i64) -> Result<ApprovalState, StoreError> {
    match code {
        0 => Ok(ApprovalState::Pending),
        1 => Ok(ApprovalState::Approved),
        2 => Ok(ApprovalState::Declined),
        _ => Err(StoreError::CorruptIndex),
    }
}

fn prune_expired_approval_requests(
    transaction: &Transaction<'_>,
    group_id: PeerId,
    now: i64,
) -> Result<(), StoreError> {
    transaction.execute(
        "DELETE FROM owner_approval_requests
         WHERE group_id = ?1 AND state != ?2 AND expires_at_unix <= ?3",
        params![
            group_id.to_bytes(),
            approval_state_code(ApprovalState::Declined),
            now
        ],
    )?;
    Ok(())
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
    /// An encrypted cached join response is empty or above its protocol bound.
    #[error("invalid encrypted join response size {0}")]
    InvalidEncryptedJoinResponseSize(usize),
    /// Only a signed message-creation event can materialize a message body.
    #[error("event is not a message creation")]
    InvalidMessageEvent,
    /// Only a signed message-edit event can replace message text.
    #[error("event is not a message edit")]
    InvalidMessageEditEvent,
    /// Only a signed message-deletion event can hide a message group-wide.
    #[error("event is not a message deletion")]
    InvalidMessageDeletionEvent,
    /// Only a signed metadata-change event can update group metadata.
    #[error("event is not a group metadata change")]
    InvalidGroupMetadataEvent,
    /// Only a signed invite-permission event can change invite permission.
    #[error("event is not an invite permission change")]
    InvalidInvitePermissionEvent,
    /// A remembered peer address is empty or above the local bound.
    #[error("invalid peer address size {0}")]
    InvalidPeerAddressSize(usize),
    /// A single-use invitation already admitted a device.
    #[error("single-use invitation already consumed")]
    InvitationConsumed,
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
        MAX_JOIN_MLS_MESSAGE_BYTES, SignedEvent, SyncMembershipState,
    };
    use rusqlite::{Connection, params};
    use tempfile::NamedTempFile;

    use super::{
        ApprovalRequestOutcome, ApprovalState, AuthorHead, EventStore, IssuedInvitationMetadata,
        JoinedGroupMetadata, LocalGroupMetadata, MAX_ENCRYPTED_JOIN_RESPONSE_BYTES,
        MAX_ENCRYPTED_MESSAGE_BODY_BYTES, MAX_ENCRYPTED_MLS_PROVIDER_SNAPSHOT_BYTES,
        MAX_PEER_ADDRESS_BYTES, MAX_PENDING_APPROVAL_REQUESTS_PER_GROUP,
        MAX_SEQUENCE_CONFLICTS_PER_AUTHOR, MAX_SYNC_BATCH_EVENTS, OwnerApprovalRequest,
        OwnerDiscoveryKeyMetadata, PendingInvitationMetadata, PutEventOutcome,
        SequenceConflictSummary, StoreError,
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
    fn sequence_conflicts_are_recorded_per_author() {
        let mut store = EventStore::in_memory().unwrap();
        let author = DeviceIdentity::generate();
        let honest = DeviceIdentity::generate();
        let group = GroupIdentity::generate();
        let group_id = group.group_id();
        store
            .put_events(&[
                message_event(&author, &group, 1, b"first"),
                message_event(&author, &group, 2, b"second"),
                message_event(&honest, &group, 1, b"honest"),
            ])
            .unwrap();
        assert!(store.sequence_conflicts(group_id).unwrap().is_empty());

        let batch_conflict = message_event(&author, &group, 2, b"other second");
        let unrelated = message_event(&honest, &group, 2, b"honest next");
        let unrelated_id = unrelated.id();
        assert!(matches!(
            store.put_events(&[
                unrelated,
                message_event(&author, &group, 2, b"other second")
            ]),
            Err(StoreError::SequenceConflict { sequence: 2 })
        ));
        assert!(store.get_event(unrelated_id).unwrap().is_none());
        for _ in 0..2 {
            assert!(matches!(
                store.put_event(&message_event(&author, &group, 1, b"other first")),
                Err(StoreError::SequenceConflict { sequence: 1 })
            ));
        }
        assert!(matches!(
            store.put_event(&batch_conflict),
            Err(StoreError::SequenceConflict { sequence: 2 })
        ));

        assert_eq!(
            store.sequence_conflicts(group_id).unwrap(),
            vec![SequenceConflictSummary {
                author_id: author.peer_id(),
                conflicting_sequences: 2,
                first_sequence: 1,
            }]
        );
        assert!(
            store
                .sequence_conflicts(GroupIdentity::generate().group_id())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn sequence_conflicts_are_bounded_per_author() {
        let mut store = EventStore::in_memory().unwrap();
        let author = DeviceIdentity::generate();
        let group = GroupIdentity::generate();
        let limit = u64::try_from(MAX_SEQUENCE_CONFLICTS_PER_AUTHOR).unwrap();
        for sequence in 1..=limit + 2 {
            store
                .put_event(&message_event(&author, &group, sequence, b"stored"))
                .unwrap();
            assert!(
                store
                    .put_event(&message_event(&author, &group, sequence, b"conflict"))
                    .is_err()
            );
        }

        let conflicts = store.sequence_conflicts(group.group_id()).unwrap();
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].conflicting_sequences, limit);
        assert_eq!(conflicts[0].first_sequence, 1);
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
    fn membership_state_counts_commits_and_reports_the_newest() {
        let mut store = EventStore::in_memory().unwrap();
        let group = GroupIdentity::generate();
        let owner = DeviceIdentity::generate();
        let owner_event = |sequence, kind| {
            SignedEvent::create(
                &owner,
                EventSpec {
                    group_id: group.group_id(),
                    author_sequence: sequence,
                    causal_parents: &[],
                    created_at_unix_ms: 1_800_000_000_000,
                    kind,
                    protected_payload: b"membership commit",
                },
            )
            .unwrap()
        };
        assert_eq!(
            store.membership_state(group.group_id()).unwrap(),
            SyncMembershipState::default()
        );

        let added = owner_event(1, EventKind::MemberAdded);
        let removed = owner_event(3, EventKind::MemberRemoved);
        store.put_event(&removed).unwrap();
        store.put_event(&added).unwrap();
        store
            .put_event(&owner_event(2, EventKind::MessageCreated))
            .unwrap();
        store
            .put_event(&message_event(
                &DeviceIdentity::generate(),
                &GroupIdentity::generate(),
                1,
                b"other group",
            ))
            .unwrap();

        assert_eq!(
            store.membership_state(group.group_id()).unwrap(),
            SyncMembershipState {
                commits: 2,
                latest_commit: Some(removed.id()),
            }
        );

        let refresh = owner_event(4, EventKind::KeyEpochAdvanced);
        store.put_event(&refresh).unwrap();
        assert_eq!(
            store.membership_state(group.group_id()).unwrap(),
            SyncMembershipState {
                commits: 3,
                latest_commit: Some(refresh.id()),
            }
        );
    }

    #[test]
    fn key_refresh_is_stored_with_its_snapshot_and_applied_as_a_commit() {
        let mut store = EventStore::in_memory().unwrap();
        let group = GroupIdentity::generate();
        let owner = DeviceIdentity::generate();
        let owner_event = |sequence, kind| {
            SignedEvent::create(
                &owner,
                EventSpec {
                    group_id: group.group_id(),
                    author_sequence: sequence,
                    causal_parents: &[],
                    created_at_unix_ms: 1_800_000_000_000,
                    kind,
                    protected_payload: b"key refresh commit",
                },
            )
            .unwrap()
        };
        let refresh = owner_event(1, EventKind::KeyEpochAdvanced);
        assert!(matches!(
            store.put_mls_key_refresh(&owner_event(1, EventKind::MemberRemoved), b"snapshot"),
            Err(StoreError::CorruptIndex)
        ));
        assert!(store.get_event(refresh.id()).unwrap().is_none());

        store.put_mls_key_refresh(&refresh, b"refreshed").unwrap();
        assert_eq!(
            store.get_event(refresh.id()).unwrap().unwrap().id(),
            refresh.id()
        );
        assert_eq!(
            store.encrypted_mls_provider_snapshot().unwrap().unwrap(),
            b"refreshed"
        );
        assert_eq!(
            store
                .unapplied_mls_commit_events(group.group_id(), 10)
                .unwrap()
                .iter()
                .map(SignedEvent::id)
                .collect::<Vec<_>>(),
            vec![refresh.id()]
        );
        assert!(
            store
                .put_applied_mls_event_and_encrypted_provider_snapshot(&refresh, b"applied")
                .unwrap()
        );
        assert!(
            store
                .unapplied_mls_commit_events(group.group_id(), 10)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn latest_author_activity_uses_each_authors_highest_sequence() {
        let mut store = EventStore::in_memory().unwrap();
        let group = GroupIdentity::generate();
        let other_group = GroupIdentity::generate();
        let first_author = DeviceIdentity::generate();
        let second_author = DeviceIdentity::generate();
        let timed = |author: &DeviceIdentity, group: &GroupIdentity, sequence, created_at| {
            SignedEvent::create(
                author,
                EventSpec {
                    group_id: group.group_id(),
                    author_sequence: sequence,
                    causal_parents: &[],
                    created_at_unix_ms: created_at,
                    kind: EventKind::MessageCreated,
                    protected_payload: b"message",
                },
            )
            .unwrap()
        };

        assert!(
            store
                .latest_author_activity(group.group_id())
                .unwrap()
                .is_empty()
        );
        store
            .put_events(&[
                timed(&first_author, &group, 1, 1_800_000_000_000),
                timed(&first_author, &group, 3, 1_800_000_003_000),
                timed(&second_author, &group, 1, 1_800_000_001_000),
                timed(&second_author, &other_group, 1, 1_900_000_000_000),
            ])
            .unwrap();

        let mut expected = vec![
            (first_author.peer_id(), 1_800_000_003_000),
            (second_author.peer_id(), 1_800_000_001_000),
        ];
        expected.sort_by_key(|(author_id, _)| author_id.to_bytes());
        assert_eq!(
            store.latest_author_activity(group.group_id()).unwrap(),
            expected
        );
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
        assert!(
            store
                .event_ids_after(group.group_id(), author.peer_id(), 1, 1)
                .unwrap()
                .is_empty()
        );
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
        assert!(
            reopened
                .remove_pending_invitation(group.group_id())
                .unwrap()
        );
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

        assert!(
            store
                .promote_pending_invitation_to_joined_group(group_id, inviter_device_id)
                .unwrap()
        );
        assert!(store.pending_invitations().unwrap().is_empty());
        assert_eq!(
            store.joined_groups().unwrap(),
            vec![JoinedGroupMetadata {
                group_id,
                group_name: "Design Crew".to_owned(),
                inviter_name: "Maya".to_owned(),
                inviter_device_id,
                history_policy: HistoryPolicy::FromInvitation,
                last_synchronized_at_unix: None,
            }]
        );
        assert!(
            store
                .promote_pending_invitation_to_joined_group(group_id, inviter_device_id)
                .unwrap()
        );
    }

    #[test]
    fn joined_group_synchronization_time_survives_restart() {
        let file = NamedTempFile::new().unwrap();
        let group_id = GroupIdentity::generate().group_id();
        let inviter_device_id = DeviceIdentity::generate().peer_id();
        let pending = PendingInvitationMetadata {
            group_id,
            group_name: "Design Crew".to_owned(),
            inviter_name: "Maya".to_owned(),
            expires_at_unix: 1_800_003_600,
            history_policy: HistoryPolicy::None,
            reusable: false,
        };
        let mut store = EventStore::open(file.path()).unwrap();
        store.put_pending_invitation(&pending).unwrap();
        assert!(
            store
                .promote_pending_invitation_to_joined_group(group_id, inviter_device_id)
                .unwrap()
        );
        assert!(
            store
                .record_joined_group_synchronization(group_id, 1_800_000_123)
                .unwrap()
        );
        drop(store);

        let restored = EventStore::open(file.path())
            .unwrap()
            .joined_groups()
            .unwrap();
        assert_eq!(restored[0].last_synchronized_at_unix, Some(1_800_000_123));
    }

    #[test]
    fn leaving_a_joined_group_removes_only_its_local_state() {
        let mut store = EventStore::in_memory().unwrap();
        let author = DeviceIdentity::generate();
        let inviter_device_id = DeviceIdentity::generate().peer_id();
        let blocked_device_id = DeviceIdentity::generate().peer_id();
        let left = GroupIdentity::generate();
        let kept = GroupIdentity::generate();
        for group in [&left, &kept] {
            store
                .put_pending_invitation(&PendingInvitationMetadata {
                    group_id: group.group_id(),
                    group_name: "Design Crew".to_owned(),
                    inviter_name: "Maya".to_owned(),
                    expires_at_unix: 1_800_003_600,
                    history_policy: HistoryPolicy::FromInvitation,
                    reusable: false,
                })
                .unwrap();
            store
                .promote_pending_invitation_to_joined_group(group.group_id(), inviter_device_id)
                .unwrap();
            let message = message_event(&author, group, 1, b"protected message");
            store
                .put_received_message_and_encrypted_mls_provider_snapshot(
                    &message,
                    b"snapshot",
                    b"encrypted body",
                )
                .unwrap();
            store
                .acknowledge_author_head(group.group_id(), inviter_device_id, author.peer_id(), 1)
                .unwrap();
            store
                .block_device_locally(group.group_id(), blocked_device_id)
                .unwrap();
            store
                .record_peer_address_success(group.group_id(), inviter_device_id, b"address", 1)
                .unwrap();
        }

        assert!(
            store
                .leave_joined_group_and_put_encrypted_mls_provider_snapshot(
                    left.group_id(),
                    b"snapshot without the group",
                )
                .unwrap()
        );
        assert_eq!(
            store
                .joined_groups()
                .unwrap()
                .into_iter()
                .map(|group| group.group_id)
                .collect::<Vec<_>>(),
            vec![kept.group_id()]
        );
        assert!(
            store
                .synchronization_summary(left.group_id())
                .unwrap()
                .is_empty()
        );
        assert!(
            store
                .encrypted_messages(left.group_id())
                .unwrap()
                .messages
                .is_empty()
        );
        assert!(store.blocked_devices(left.group_id()).unwrap().is_empty());
        assert!(
            store
                .peer_addresses(left.group_id(), inviter_device_id)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store
                .peer_addresses(kept.group_id(), inviter_device_id)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            store
                .max_acknowledged_author_head(left.group_id(), author.peer_id())
                .unwrap(),
            0
        );
        assert_eq!(
            store.unread_message_counts().unwrap(),
            vec![(kept.group_id(), 1)]
        );
        assert_eq!(
            store
                .encrypted_messages(kept.group_id())
                .unwrap()
                .messages
                .len(),
            1
        );
        assert_eq!(
            store.blocked_devices(kept.group_id()).unwrap(),
            vec![blocked_device_id]
        );
        assert_eq!(
            store.encrypted_mls_provider_snapshot().unwrap().unwrap(),
            b"snapshot without the group"
        );
        assert!(
            !store
                .leave_joined_group_and_put_encrypted_mls_provider_snapshot(
                    left.group_id(),
                    b"unchanged snapshot",
                )
                .unwrap()
        );
        assert_eq!(
            store.encrypted_mls_provider_snapshot().unwrap().unwrap(),
            b"snapshot without the group"
        );
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
            requested_by: None,
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
        assert!(
            reopened
                .remove_issued_invitation(invitation.invitation_id)
                .unwrap()
        );
        assert!(reopened.issued_invitations().unwrap().is_empty());
    }

    #[test]
    fn owner_approval_requests_record_decide_and_expire() {
        let mut store = EventStore::in_memory().unwrap();
        let group = GroupIdentity::generate().group_id();
        let device = DeviceIdentity::generate().peer_id();
        let other = DeviceIdentity::generate().peer_id();
        let invitation = InvitationId::from_bytes([3; 16]);
        let later_invitation = InvitationId::from_bytes([4; 16]);

        let record = |store: &mut EventStore, device, invitation, expires, now| {
            store
                .record_owner_approval_request(group, device, invitation, expires, now)
                .unwrap()
        };
        assert_eq!(
            record(&mut store, device, invitation, 2_000, 1_000),
            ApprovalRequestOutcome::Pending
        );
        assert_eq!(
            record(&mut store, device, later_invitation, 3_000, 1_100),
            ApprovalRequestOutcome::Pending
        );
        let requests = store.owner_approval_requests(group, 1_100).unwrap();
        assert_eq!(
            requests,
            vec![OwnerApprovalRequest {
                group_id: group,
                device_id: device,
                invitation_id: later_invitation,
                expires_at_unix: 3_000,
                first_requested_at_unix: 1_000,
                last_requested_at_unix: 1_100,
                state: ApprovalState::Pending,
            }]
        );

        assert!(store.approve_owner_approval_request(group, device).unwrap());
        assert!(!store.approve_owner_approval_request(group, device).unwrap());
        assert_eq!(
            record(&mut store, device, later_invitation, 3_000, 1_200),
            ApprovalRequestOutcome::Approved
        );
        assert!(store.decline_owner_approval_request(group, device).unwrap());
        assert_eq!(
            record(&mut store, device, later_invitation, 3_000, 1_300),
            ApprovalRequestOutcome::Declined
        );
        // Declines outlive the invitation until the owner clears them.
        assert_eq!(
            store.owner_approval_requests(group, 5_000).unwrap()[0].state,
            ApprovalState::Declined
        );
        assert!(
            store
                .clear_declined_approval_request(group, device)
                .unwrap()
        );
        assert!(
            !store
                .clear_declined_approval_request(group, device)
                .unwrap()
        );

        assert_eq!(
            record(&mut store, other, invitation, 2_000, 1_000),
            ApprovalRequestOutcome::Pending
        );
        assert!(
            store
                .owner_approval_requests(group, 2_000)
                .unwrap()
                .is_empty()
        );
        assert!(!store.approve_owner_approval_request(group, device).unwrap());
        assert_eq!(
            record(&mut store, other, invitation, 4_000, 2_500),
            ApprovalRequestOutcome::Pending
        );
        assert_eq!(
            store.owner_approval_requests(group, 2_500).unwrap()[0].first_requested_at_unix,
            2_500
        );
    }

    #[test]
    fn owner_approval_requests_are_bounded_per_group() {
        let mut store = EventStore::in_memory().unwrap();
        let group = GroupIdentity::generate().group_id();
        let invitation = InvitationId::from_bytes([5; 16]);
        let devices: Vec<_> = (0..=MAX_PENDING_APPROVAL_REQUESTS_PER_GROUP)
            .map(|_| DeviceIdentity::generate().peer_id())
            .collect();
        for device in &devices[..MAX_PENDING_APPROVAL_REQUESTS_PER_GROUP] {
            assert_eq!(
                store
                    .record_owner_approval_request(group, *device, invitation, 2_000, 1_000)
                    .unwrap(),
                ApprovalRequestOutcome::Pending
            );
        }
        let extra = devices[MAX_PENDING_APPROVAL_REQUESTS_PER_GROUP];
        assert_eq!(
            store
                .record_owner_approval_request(group, extra, invitation, 2_000, 1_000)
                .unwrap(),
            ApprovalRequestOutcome::Full
        );
        // Deciding a request frees room, and another group is unaffected.
        assert!(
            store
                .approve_owner_approval_request(group, devices[0])
                .unwrap()
        );
        assert_eq!(
            store
                .record_owner_approval_request(group, extra, invitation, 2_000, 1_000)
                .unwrap(),
            ApprovalRequestOutcome::Pending
        );
        assert_eq!(
            store
                .record_owner_approval_request(
                    GroupIdentity::generate().group_id(),
                    devices[1],
                    invitation,
                    2_000,
                    1_000
                )
                .unwrap(),
            ApprovalRequestOutcome::Pending
        );
    }

    #[test]
    fn issued_invitation_index_keeps_requesting_member_device() {
        let file = NamedTempFile::new().unwrap();
        let invitation = IssuedInvitationMetadata {
            invitation_id: InvitationId::from_bytes([9; 16]),
            group_id: GroupIdentity::generate().group_id(),
            expires_at_unix: 1_800_003_600,
            requested_by: Some(DeviceIdentity::generate().peer_id()),
        };
        EventStore::open(file.path())
            .unwrap()
            .put_issued_invitation(&invitation)
            .unwrap();

        let reopened = EventStore::open(file.path()).unwrap();
        assert_eq!(reopened.issued_invitations().unwrap(), vec![invitation]);
    }

    #[test]
    fn version_twenty_three_database_adds_invitation_requesters() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path();
        let group_id = GroupIdentity::generate().group_id();
        {
            let store = EventStore::open(path).unwrap();
            store
                .connection
                .execute_batch(
                    "ALTER TABLE issued_invitations DROP COLUMN requested_by_device_id;
                     PRAGMA user_version = 23;",
                )
                .unwrap();
            store
                .connection
                .execute(
                    "INSERT INTO issued_invitations (invitation_id, group_id, expires_at_unix)
                     VALUES (?1, ?2, 1800003600)",
                    params![[10_u8; 16].as_slice(), group_id.to_bytes()],
                )
                .unwrap();
        }

        let store = EventStore::open(path).unwrap();
        assert_eq!(
            store.issued_invitations().unwrap(),
            vec![IssuedInvitationMetadata {
                invitation_id: InvitationId::from_bytes([10; 16]),
                group_id,
                expires_at_unix: 1_800_003_600,
                requested_by: None,
            }]
        );
        let version: i64 = store
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, super::SCHEMA_VERSION);
    }

    #[test]
    fn owner_discovery_key_indexes_survive_invitation_removal() {
        let file = NamedTempFile::new().unwrap();
        let group_id = GroupIdentity::generate().group_id();
        let invitation_id = InvitationId::from_bytes([8; 16]);
        let mut store = EventStore::open(file.path()).unwrap();
        store
            .put_owner_discovery_key(&OwnerDiscoveryKeyMetadata {
                invitation_id,
                group_id,
            })
            .unwrap();
        store
            .put_issued_invitation(&IssuedInvitationMetadata {
                invitation_id,
                group_id,
                expires_at_unix: 1_800_003_600,
                requested_by: None,
            })
            .unwrap();
        store.remove_issued_invitation(invitation_id).unwrap();
        drop(store);

        let mut reopened = EventStore::open(file.path()).unwrap();
        assert_eq!(
            reopened.owner_discovery_keys(group_id).unwrap(),
            vec![OwnerDiscoveryKeyMetadata {
                invitation_id,
                group_id,
            }]
        );
        assert!(reopened.remove_owner_discovery_key(invitation_id).unwrap());
        assert!(reopened.owner_discovery_keys(group_id).unwrap().is_empty());
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
        assert!(
            store
                .pending_mls_join_key_package(group_id)
                .unwrap()
                .is_none()
        );

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

        assert!(
            store
                .remove_pending_mls_join_and_put_encrypted_mls_provider_snapshot(
                    group_id,
                    b"provider with joined group",
                )
                .unwrap()
        );
        assert!(
            store
                .pending_mls_join_key_package(group_id)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store.encrypted_mls_provider_snapshot().unwrap().unwrap(),
            b"provider with joined group"
        );
        assert!(
            !store
                .remove_pending_mls_join_and_put_encrypted_mls_provider_snapshot(
                    group_id,
                    b"must not replace provider without a pending join",
                )
                .unwrap()
        );
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
    fn member_admission_event_snapshot_and_retry_response_commit_together() {
        let mut store = EventStore::in_memory().unwrap();
        let owner = DeviceIdentity::generate();
        let member_id = DeviceIdentity::generate().peer_id();
        let group = GroupIdentity::generate();
        let event = SignedEvent::create(
            &owner,
            EventSpec {
                group_id: group.group_id(),
                author_sequence: 1,
                causal_parents: &[],
                created_at_unix_ms: 1_800_000_000_000,
                kind: EventKind::MemberAdded,
                protected_payload: b"MLS commit",
            },
        )
        .unwrap();
        let request_hash = [7; 32];

        store
            .put_mls_join_admission(
                &event,
                b"advanced provider snapshot",
                member_id,
                &request_hash,
                b"encrypted accepted response",
                None,
            )
            .unwrap();

        assert!(store.get_event(event.id()).unwrap().is_some());
        assert_eq!(
            store.encrypted_mls_provider_snapshot().unwrap().unwrap(),
            b"advanced provider snapshot"
        );
        let admission = store
            .mls_join_admission(group.group_id(), member_id)
            .unwrap()
            .unwrap();
        assert_eq!(admission.request_hash, request_hash);
        assert_eq!(admission.encrypted_response, b"encrypted accepted response");
        assert!(matches!(
            store.put_mls_join_admission(
                &event,
                b"other snapshot",
                member_id,
                &request_hash,
                &vec![0; MAX_ENCRYPTED_JOIN_RESPONSE_BYTES + 1],
                None,
            ),
            Err(StoreError::InvalidEncryptedJoinResponseSize(_))
        ));
    }

    #[test]
    fn single_use_invitation_is_consumed_with_its_admission() {
        let mut store = EventStore::in_memory().unwrap();
        let owner = DeviceIdentity::generate();
        let group = GroupIdentity::generate();
        let invitation_id = InvitationId::from_bytes([3; 16]);
        let added = |sequence| {
            SignedEvent::create(
                &owner,
                EventSpec {
                    group_id: group.group_id(),
                    author_sequence: sequence,
                    causal_parents: &[],
                    created_at_unix_ms: 1_800_000_000_000,
                    kind: EventKind::MemberAdded,
                    protected_payload: b"MLS commit",
                },
            )
            .unwrap()
        };
        let first = DeviceIdentity::generate().peer_id();
        let second = DeviceIdentity::generate().peer_id();
        assert_eq!(
            store
                .single_use_invitation_consumer(group.group_id(), invitation_id)
                .unwrap(),
            None
        );

        store
            .put_mls_join_admission(
                &added(1),
                b"first snapshot",
                first,
                &[1; 32],
                b"first response",
                Some(invitation_id),
            )
            .unwrap();
        assert_eq!(
            store
                .single_use_invitation_consumer(group.group_id(), invitation_id)
                .unwrap(),
            Some(first)
        );
        assert_eq!(
            store
                .single_use_invitation_consumer(GroupIdentity::generate().group_id(), invitation_id)
                .unwrap(),
            None
        );

        let second_event = added(2);
        assert!(matches!(
            store.put_mls_join_admission(
                &second_event,
                b"second snapshot",
                second,
                &[2; 32],
                b"second response",
                Some(invitation_id),
            ),
            Err(StoreError::InvitationConsumed)
        ));
        assert!(store.get_event(second_event.id()).unwrap().is_none());
        assert!(
            store
                .mls_join_admission(group.group_id(), second)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store.encrypted_mls_provider_snapshot().unwrap().unwrap(),
            b"first snapshot"
        );
    }

    #[test]
    fn member_removal_snapshot_and_readmission_block_commit_together() {
        let mut store = EventStore::in_memory().unwrap();
        let owner = DeviceIdentity::generate();
        let member_id = DeviceIdentity::generate().peer_id();
        let group = GroupIdentity::generate();
        let added = SignedEvent::create(
            &owner,
            EventSpec {
                group_id: group.group_id(),
                author_sequence: 1,
                causal_parents: &[],
                created_at_unix_ms: 1_800_000_000_000,
                kind: EventKind::MemberAdded,
                protected_payload: b"MLS add commit",
            },
        )
        .unwrap();
        store
            .put_mls_join_admission(
                &added,
                b"admitted provider snapshot",
                member_id,
                &[7; 32],
                b"encrypted accepted response",
                None,
            )
            .unwrap();
        let removed = SignedEvent::create(
            &owner,
            EventSpec {
                group_id: group.group_id(),
                author_sequence: 2,
                causal_parents: &[added.id()],
                created_at_unix_ms: 1_800_000_001_000,
                kind: EventKind::MemberRemoved,
                protected_payload: b"MLS remove commit",
            },
        )
        .unwrap();

        store
            .record_owner_approval_request(
                group.group_id(),
                member_id,
                InvitationId::from_bytes([9; 16]),
                2_000_000_000,
                1_800_000_000,
            )
            .unwrap();
        assert!(
            store
                .approve_owner_approval_request(group.group_id(), member_id)
                .unwrap()
        );
        store
            .put_mls_member_removal(&removed, b"removed provider snapshot", member_id)
            .unwrap();
        assert!(
            store
                .owner_approval_requests(group.group_id(), 1_800_000_000)
                .unwrap()
                .is_empty()
        );

        assert!(store.get_event(removed.id()).unwrap().is_some());
        assert_eq!(
            store.encrypted_mls_provider_snapshot().unwrap().unwrap(),
            b"removed provider snapshot"
        );
        assert!(
            store
                .mls_join_admission(group.group_id(), member_id)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .is_removed_mls_member(group.group_id(), member_id)
                .unwrap()
        );
        assert!(
            store
                .unapplied_mls_commit_events(group.group_id(), 2)
                .unwrap()
                .iter()
                .any(|event| event.id() == removed.id())
        );
        assert_eq!(
            store.removed_mls_members(group.group_id()).unwrap(),
            vec![member_id]
        );
        assert!(
            store
                .removed_mls_members(GroupIdentity::generate().group_id())
                .unwrap()
                .is_empty()
        );

        assert!(
            store
                .allow_removed_mls_member_readmission(group.group_id(), member_id)
                .unwrap()
        );
        assert!(
            !store
                .allow_removed_mls_member_readmission(group.group_id(), member_id)
                .unwrap()
        );
        assert!(
            !store
                .is_removed_mls_member(group.group_id(), member_id)
                .unwrap()
        );
        assert!(
            store
                .removed_mls_members(group.group_id())
                .unwrap()
                .is_empty()
        );
        assert!(store.get_event(removed.id()).unwrap().is_some());
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
                    author_sequence: event.author_sequence(),
                    created_at_unix_ms: event.created_at_unix_ms(),
                    encrypted_body: b"encrypted local message".to_vec(),
                    edit: None,
                    reply_to: None,
                }],
                has_earlier: false,
            }
        );
        assert!(
            store
                .unmaterialized_message_events(group.group_id(), 1)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn peer_acknowledged_author_heads_are_monotonic_and_scoped() {
        let mut store = EventStore::in_memory().unwrap();
        let group = GroupIdentity::generate();
        let author = DeviceIdentity::generate();
        let peer = DeviceIdentity::generate();
        let other_peer = DeviceIdentity::generate();

        assert_eq!(
            store
                .max_acknowledged_author_head(group.group_id(), author.peer_id())
                .unwrap(),
            0
        );
        store
            .acknowledge_author_head(group.group_id(), peer.peer_id(), author.peer_id(), 4)
            .unwrap();
        store
            .acknowledge_author_head(group.group_id(), peer.peer_id(), author.peer_id(), 2)
            .unwrap();
        store
            .acknowledge_author_head(group.group_id(), other_peer.peer_id(), author.peer_id(), 6)
            .unwrap();
        store
            .acknowledge_author_head(group.group_id(), peer.peer_id(), author.peer_id(), 0)
            .unwrap();

        assert_eq!(
            store
                .max_acknowledged_author_head(group.group_id(), author.peer_id())
                .unwrap(),
            6
        );
        assert_eq!(
            store
                .max_acknowledged_author_head(
                    GroupIdentity::generate().group_id(),
                    author.peer_id(),
                )
                .unwrap(),
            0
        );
    }

    #[test]
    fn reported_author_heads_are_recorded_per_peer_and_never_move_back() {
        let mut store = EventStore::in_memory().unwrap();
        let group = GroupIdentity::generate();
        let author = DeviceIdentity::generate();
        let other_author = DeviceIdentity::generate();
        let peer = DeviceIdentity::generate();
        let other_peer = DeviceIdentity::generate();
        let head = |author: &DeviceIdentity, sequence| AuthorHead {
            author_id: author.peer_id(),
            contiguous_sequence: sequence,
        };

        store
            .acknowledge_author_heads(
                group.group_id(),
                peer.peer_id(),
                &[head(&author, 5), head(&other_author, 0)],
            )
            .unwrap();
        store
            .acknowledge_author_heads(group.group_id(), peer.peer_id(), &[head(&author, 3)])
            .unwrap();
        store
            .acknowledge_author_head(group.group_id(), other_peer.peer_id(), author.peer_id(), 2)
            .unwrap();

        let heads = store
            .acknowledged_author_heads(group.group_id(), author.peer_id())
            .unwrap();
        assert_eq!(heads.len(), 2);
        assert_eq!(heads[&peer.peer_id()], 5);
        assert_eq!(heads[&other_peer.peer_id()], 2);
        assert!(
            store
                .acknowledged_author_heads(group.group_id(), other_author.peer_id())
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn locally_hidden_message_stays_hidden_without_deleting_its_event() {
        let mut store = EventStore::in_memory().unwrap();
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

        assert!(
            store
                .hide_message_locally(group.group_id(), event.id().as_bytes())
                .unwrap()
        );
        assert!(
            store
                .encrypted_messages(group.group_id())
                .unwrap()
                .messages
                .is_empty()
        );
        assert!(store.get_event(event.id()).unwrap().is_some());
        assert!(
            store
                .unmaterialized_message_events(group.group_id(), 1)
                .unwrap()
                .is_empty()
        );
        assert!(
            !store
                .hide_message_locally(group.group_id(), event.id().as_bytes())
                .unwrap()
        );
    }

    #[test]
    fn retention_hides_only_messages_created_before_the_cutoff() {
        let mut store = EventStore::in_memory().unwrap();
        let author = DeviceIdentity::generate();
        let group = GroupIdentity::generate();
        let other_group = GroupIdentity::generate();
        let timed = |group: &GroupIdentity, sequence, created_at| {
            SignedEvent::create(
                &author,
                EventSpec {
                    group_id: group.group_id(),
                    author_sequence: sequence,
                    causal_parents: &[],
                    created_at_unix_ms: created_at,
                    kind: EventKind::MessageCreated,
                    protected_payload: b"MLS ciphertext",
                },
            )
            .unwrap()
        };
        let old = timed(&group, 1, 1_000);
        let recent = timed(&group, 2, 5_000);
        let other_old = timed(&other_group, 1, 2_000);
        for event in [&old, &recent, &other_old] {
            store
                .put_received_message_and_encrypted_mls_provider_snapshot(
                    event,
                    b"advanced encrypted provider",
                    b"encrypted local message",
                )
                .unwrap();
        }

        assert_eq!(store.hide_messages_created_before(5_000).unwrap(), 2);
        let remaining = store.encrypted_messages(group.group_id()).unwrap().messages;
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].created_at_unix_ms, 5_000);
        assert!(
            store
                .encrypted_messages(other_group.group_id())
                .unwrap()
                .messages
                .is_empty()
        );
        assert_eq!(
            store.unread_message_counts().unwrap(),
            vec![(group.group_id(), 1)]
        );
        for event in [&old, &other_old] {
            assert!(store.get_event(event.id()).unwrap().is_some());
        }
        assert!(
            store
                .unmaterialized_message_events(group.group_id(), 10)
                .unwrap()
                .is_empty()
        );
        assert_eq!(store.hide_messages_created_before(5_000).unwrap(), 0);
    }

    #[test]
    fn received_messages_stay_unread_until_their_group_is_marked_read() {
        let mut store = EventStore::in_memory().unwrap();
        let author = DeviceIdentity::generate();
        let group = GroupIdentity::generate();
        let other_group = GroupIdentity::generate();
        let first = message_event(&author, &group, 1, b"first MLS ciphertext");
        let second = message_event(&author, &group, 2, b"second MLS ciphertext");
        let own = message_event(&author, &other_group, 1, b"own MLS ciphertext");
        for event in [&first, &second] {
            store
                .put_received_message_and_encrypted_mls_provider_snapshot(
                    event,
                    b"advanced encrypted provider",
                    b"encrypted local message",
                )
                .unwrap();
        }
        store
            .put_received_message_and_encrypted_mls_provider_snapshot(
                &first,
                b"advanced encrypted provider",
                b"encrypted local message",
            )
            .unwrap();
        store
            .put_message_and_encrypted_mls_provider_snapshot(
                &own,
                b"advanced encrypted provider",
                b"encrypted local message",
            )
            .unwrap();

        assert_eq!(
            store.unread_message_counts().unwrap(),
            vec![(group.group_id(), 2)]
        );
        assert!(
            store
                .hide_message_locally(group.group_id(), first.id().as_bytes())
                .unwrap()
        );
        assert_eq!(
            store.unread_message_counts().unwrap(),
            vec![(group.group_id(), 1)]
        );
        assert_eq!(store.mark_messages_read(other_group.group_id()).unwrap(), 0);
        assert_eq!(store.mark_messages_read(group.group_id()).unwrap(), 1);
        assert!(store.unread_message_counts().unwrap().is_empty());
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
    fn latest_encrypted_message_skips_blocked_devices() {
        let mut store = EventStore::in_memory().unwrap();
        let earlier_author = DeviceIdentity::generate();
        let later_author = DeviceIdentity::generate();
        let group = GroupIdentity::generate();
        let empty_group = GroupIdentity::generate();
        let message_at = |author: &DeviceIdentity, created_at_unix_ms| {
            SignedEvent::create(
                author,
                EventSpec {
                    group_id: group.group_id(),
                    author_sequence: 1,
                    causal_parents: &[],
                    created_at_unix_ms,
                    kind: EventKind::MessageCreated,
                    protected_payload: b"MLS ciphertext",
                },
            )
            .unwrap()
        };
        let earlier = message_at(&earlier_author, 1_800_000_000_000);
        let later = message_at(&later_author, 1_800_000_001_000);
        for event in [&later, &earlier] {
            store
                .put_received_message_and_encrypted_mls_provider_snapshot(
                    event,
                    b"advanced encrypted provider",
                    b"encrypted local message",
                )
                .unwrap();
        }

        assert!(
            store
                .latest_encrypted_message(empty_group.group_id())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .latest_encrypted_message(group.group_id())
                .unwrap()
                .unwrap()
                .event_id,
            *later.id().as_bytes()
        );
        store
            .block_device_locally(group.group_id(), later_author.peer_id())
            .unwrap();
        assert_eq!(
            store
                .latest_encrypted_message(group.group_id())
                .unwrap()
                .unwrap()
                .event_id,
            *earlier.id().as_bytes()
        );
    }

    #[test]
    fn locally_blocked_device_messages_are_hidden_until_unblocked() {
        let mut store = EventStore::in_memory().unwrap();
        let blocked = DeviceIdentity::generate();
        let other = DeviceIdentity::generate();
        let group = GroupIdentity::generate();
        let other_group = GroupIdentity::generate();
        let first = message_event(&blocked, &group, 1, b"first MLS ciphertext");
        let second = message_event(&blocked, &group, 2, b"second MLS ciphertext");
        let kept = message_event(&other, &group, 1, b"kept MLS ciphertext");
        let elsewhere = message_event(&blocked, &other_group, 1, b"elsewhere ciphertext");
        for event in [&first, &kept, &elsewhere] {
            store
                .put_received_message_and_encrypted_mls_provider_snapshot(
                    event,
                    b"advanced encrypted provider",
                    b"encrypted local message",
                )
                .unwrap();
        }

        assert!(
            store
                .block_device_locally(group.group_id(), blocked.peer_id())
                .unwrap()
        );
        assert!(
            !store
                .block_device_locally(group.group_id(), blocked.peer_id())
                .unwrap()
        );
        store
            .put_received_message_and_encrypted_mls_provider_snapshot(
                &second,
                b"advanced encrypted provider",
                b"encrypted local message",
            )
            .unwrap();

        assert_eq!(
            store.blocked_devices(group.group_id()).unwrap(),
            vec![blocked.peer_id()]
        );
        assert!(
            store
                .blocked_devices(other_group.group_id())
                .unwrap()
                .is_empty()
        );
        let visible = store.encrypted_messages(group.group_id()).unwrap().messages;
        assert_eq!(visible.len(), 1);
        assert_eq!(visible[0].author_id, other.peer_id());
        assert_eq!(
            store.unread_message_counts().unwrap().len(),
            2,
            "the other group keeps its unread message"
        );
        assert!(store.get_event(second.id()).unwrap().is_some());
        assert!(
            store
                .unmaterialized_message_events(group.group_id(), 10)
                .unwrap()
                .is_empty()
        );

        assert!(
            store
                .unblock_device_locally(group.group_id(), blocked.peer_id())
                .unwrap()
        );
        assert!(
            !store
                .unblock_device_locally(group.group_id(), blocked.peer_id())
                .unwrap()
        );
        assert_eq!(
            store
                .encrypted_messages(group.group_id())
                .unwrap()
                .messages
                .len(),
            3
        );
        assert!(
            store
                .unread_message_counts()
                .unwrap()
                .contains(&(group.group_id(), 1)),
            "blocked messages do not become unread after unblocking"
        );
    }

    #[test]
    fn group_metadata_changes_apply_in_author_sequence_order() {
        let mut store = EventStore::in_memory().unwrap();
        let owner = DeviceIdentity::generate();
        let group = GroupIdentity::generate();
        let metadata_event = |sequence| {
            SignedEvent::create(
                &owner,
                EventSpec {
                    group_id: group.group_id(),
                    author_sequence: sequence,
                    causal_parents: &[],
                    created_at_unix_ms: 1_800_000_000_000,
                    kind: EventKind::GroupMetadataChanged,
                    protected_payload: b"protected metadata",
                },
            )
            .unwrap()
        };
        let first = metadata_event(1);
        let message = message_event(&owner, &group, 2, b"protected message");
        let second = metadata_event(3);
        for event in [&first, &message, &second] {
            store.put_event(event).unwrap();
        }

        let pending = store
            .unmaterialized_message_events(group.group_id(), 10)
            .unwrap();
        assert_eq!(
            pending.iter().map(SignedEvent::id).collect::<Vec<_>>(),
            vec![first.id(), message.id(), second.id()]
        );
        assert!(matches!(
            store.put_group_metadata_and_encrypted_mls_provider_snapshot(
                &message,
                b"snapshot",
                &charp2p_core::GroupMetadata::new("Wrong").unwrap(),
            ),
            Err(StoreError::InvalidGroupMetadataEvent)
        ));

        store
            .put_group_metadata_and_encrypted_mls_provider_snapshot(
                &second,
                b"snapshot two",
                &charp2p_core::GroupMetadata::new("Renamed Crew").unwrap(),
            )
            .unwrap();
        store
            .put_group_metadata_and_encrypted_mls_provider_snapshot(
                &first,
                b"snapshot one",
                &charp2p_core::GroupMetadata::new("Old Crew").unwrap(),
            )
            .unwrap();
        assert_eq!(
            store.current_group_names().unwrap(),
            vec![(group.group_id(), "Renamed Crew".to_owned())]
        );
        assert_eq!(
            store
                .unmaterialized_message_events(group.group_id(), 10)
                .unwrap()
                .iter()
                .map(SignedEvent::id)
                .collect::<Vec<_>>(),
            vec![message.id()]
        );
        assert_eq!(
            store.encrypted_mls_provider_snapshot().unwrap().unwrap(),
            b"snapshot one"
        );
    }

    #[test]
    fn version_one_metadata_changes_keep_the_known_group_icon() {
        let mut store = EventStore::in_memory().unwrap();
        let owner = DeviceIdentity::generate();
        let group = GroupIdentity::generate();
        let metadata_event = |sequence| {
            SignedEvent::create(
                &owner,
                EventSpec {
                    group_id: group.group_id(),
                    author_sequence: sequence,
                    causal_parents: &[],
                    created_at_unix_ms: 1_800_000_000_000,
                    kind: EventKind::GroupMetadataChanged,
                    protected_payload: b"protected metadata",
                },
            )
            .unwrap()
        };
        let named = |name: &str| charp2p_core::GroupMetadata::new(name).unwrap();
        let mut put = |sequence, metadata: charp2p_core::GroupMetadata| {
            let event = metadata_event(sequence);
            store.put_event(&event).unwrap();
            store
                .put_group_metadata_and_encrypted_mls_provider_snapshot(
                    &event,
                    b"snapshot",
                    &metadata,
                )
                .unwrap();
        };

        put(1, named("Crew"));
        put(2, named("Crew").with_icon(3).unwrap());
        put(4, named("Renamed Crew"));
        put(3, named("Crew").with_icon(1).unwrap());

        assert_eq!(
            store.current_group_names().unwrap(),
            vec![(group.group_id(), "Renamed Crew".to_owned())]
        );
        assert_eq!(
            store.current_group_icons().unwrap(),
            vec![(group.group_id(), 1)]
        );
    }

    #[test]
    fn version_twenty_six_database_adds_consumed_single_use_invitations() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path();
        {
            let store = EventStore::open(path).unwrap();
            store
                .connection
                .execute_batch(
                    "DROP TABLE consumed_single_use_invitations;
                     PRAGMA user_version = 26;",
                )
                .unwrap();
        }

        let store = EventStore::open(path).unwrap();
        assert_eq!(
            store
                .single_use_invitation_consumer(
                    GroupIdentity::generate().group_id(),
                    InvitationId::from_bytes([1; 16])
                )
                .unwrap(),
            None
        );
        let version: i64 = store
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, super::SCHEMA_VERSION);
    }

    #[test]
    fn version_twenty_five_database_adds_owner_approval_requests() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path();
        {
            let store = EventStore::open(path).unwrap();
            store
                .connection
                .execute_batch(
                    "DROP TABLE owner_approval_requests;
                     PRAGMA user_version = 25;",
                )
                .unwrap();
        }

        let store = EventStore::open(path).unwrap();
        assert!(
            store
                .owner_approval_requests(GroupIdentity::generate().group_id(), 0)
                .unwrap()
                .is_empty()
        );
        let version: i64 = store
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, super::SCHEMA_VERSION);
    }

    #[test]
    fn version_twenty_four_database_adds_group_metadata_icons() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path();
        {
            let store = EventStore::open(path).unwrap();
            store
                .connection
                .execute_batch(
                    "ALTER TABLE applied_group_metadata DROP COLUMN icon;
                     PRAGMA user_version = 24;",
                )
                .unwrap();
        }

        let store = EventStore::open(path).unwrap();
        assert!(store.current_group_icons().unwrap().is_empty());
        let version: i64 = store
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, super::SCHEMA_VERSION);
    }

    #[test]
    fn latest_same_author_edit_replaces_message_text() {
        let mut store = EventStore::in_memory().unwrap();
        let author = DeviceIdentity::generate();
        let other = DeviceIdentity::generate();
        let group = GroupIdentity::generate();
        let edit_event = |device: &DeviceIdentity, sequence| {
            SignedEvent::create(
                device,
                EventSpec {
                    group_id: group.group_id(),
                    author_sequence: sequence,
                    causal_parents: &[],
                    created_at_unix_ms: 1_800_000_000_000,
                    kind: EventKind::MessageEdited,
                    protected_payload: b"protected edit",
                },
            )
            .unwrap()
        };
        let message = message_event(&author, &group, 1, b"protected message");
        let first_edit = edit_event(&author, 2);
        let second_edit = edit_event(&author, 3);
        let foreign_edit = edit_event(&other, 1);
        for event in [&message, &first_edit, &second_edit, &foreign_edit] {
            store.put_event(event).unwrap();
        }
        assert_eq!(
            store
                .unmaterialized_message_events(group.group_id(), 10)
                .unwrap()
                .len(),
            4
        );
        assert!(matches!(
            store.put_message_edit_and_encrypted_mls_provider_snapshot(
                &message,
                b"snapshot",
                message.id().as_bytes(),
                b"edit body",
            ),
            Err(StoreError::InvalidMessageEditEvent)
        ));
        store
            .put_message_and_encrypted_mls_provider_snapshot(&message, b"snapshot", b"original")
            .unwrap();
        let target = *message.id().as_bytes();
        assert_eq!(
            store
                .materialized_message_author(group.group_id(), &target)
                .unwrap(),
            Some(author.peer_id())
        );
        assert_eq!(
            store
                .materialized_message_author(group.group_id(), second_edit.id().as_bytes())
                .unwrap(),
            None
        );
        store
            .put_message_edit_and_encrypted_mls_provider_snapshot(
                &foreign_edit,
                b"snapshot",
                &target,
                b"forged",
            )
            .unwrap();
        let page = store.encrypted_messages(group.group_id()).unwrap();
        assert_eq!(page.messages[0].edit, None, "other devices cannot edit");

        store
            .put_message_edit_and_encrypted_mls_provider_snapshot(
                &second_edit,
                b"snapshot",
                &target,
                b"second",
            )
            .unwrap();
        store
            .put_message_edit_and_encrypted_mls_provider_snapshot(
                &first_edit,
                b"snapshot",
                &target,
                b"first",
            )
            .unwrap();
        let page = store.encrypted_messages(group.group_id()).unwrap();
        assert_eq!(page.messages.len(), 1);
        assert_eq!(page.messages[0].encrypted_body, b"original");
        assert_eq!(
            page.messages[0].edit,
            Some(super::EncryptedMessageEdit {
                event_id: *second_edit.id().as_bytes(),
                encrypted_body: b"second".to_vec(),
            })
        );
        assert!(
            store
                .unmaterialized_message_events(group.group_id(), 10)
                .unwrap()
                .is_empty()
        );
        assert!(store.unread_message_counts().unwrap().is_empty());
    }

    #[test]
    fn same_author_deletion_hides_message_before_or_after_it_arrives() {
        let mut store = EventStore::in_memory().unwrap();
        let author = DeviceIdentity::generate();
        let other = DeviceIdentity::generate();
        let group = GroupIdentity::generate();
        let deletion_event = |device: &DeviceIdentity, sequence| {
            SignedEvent::create(
                device,
                EventSpec {
                    group_id: group.group_id(),
                    author_sequence: sequence,
                    causal_parents: &[],
                    created_at_unix_ms: 1_800_000_000_000,
                    kind: EventKind::MessageDeleted,
                    protected_payload: b"protected deletion",
                },
            )
            .unwrap()
        };
        let first = message_event(&author, &group, 1, b"first message");
        let second = message_event(&author, &group, 2, b"second message");
        let foreign_deletion = deletion_event(&other, 1);
        let first_deletion = deletion_event(&author, 3);
        let second_deletion = deletion_event(&author, 4);
        for event in [&first, &second, &foreign_deletion, &first_deletion] {
            store.put_event(event).unwrap();
        }
        assert_eq!(
            store
                .unmaterialized_message_events(group.group_id(), 10)
                .unwrap()
                .len(),
            4
        );
        assert!(matches!(
            store.put_message_deletion_and_encrypted_mls_provider_snapshot(
                &first,
                b"snapshot",
                first.id().as_bytes(),
            ),
            Err(StoreError::InvalidMessageDeletionEvent)
        ));
        store
            .put_received_message_and_encrypted_mls_provider_snapshot(&first, b"snapshot", b"one")
            .unwrap();
        assert_eq!(
            store.unread_message_counts().unwrap(),
            vec![(group.group_id(), 1)]
        );

        let first_target = *first.id().as_bytes();
        store
            .put_message_deletion_and_encrypted_mls_provider_snapshot(
                &foreign_deletion,
                b"snapshot",
                &first_target,
            )
            .unwrap();
        assert_eq!(
            store
                .encrypted_messages(group.group_id())
                .unwrap()
                .messages
                .len(),
            1,
            "other devices cannot delete"
        );

        store
            .put_message_deletion_and_encrypted_mls_provider_snapshot(
                &first_deletion,
                b"snapshot",
                &first_target,
            )
            .unwrap();
        assert!(
            store
                .encrypted_messages(group.group_id())
                .unwrap()
                .messages
                .is_empty()
        );
        assert!(store.unread_message_counts().unwrap().is_empty());
        assert_eq!(
            store
                .materialized_message_author(group.group_id(), &first_target)
                .unwrap(),
            None
        );

        // A tombstone that arrives before its message still hides it.
        store
            .put_message_deletion_and_encrypted_mls_provider_snapshot(
                &second_deletion,
                b"snapshot",
                second.id().as_bytes(),
            )
            .unwrap();
        store
            .put_received_message_and_encrypted_mls_provider_snapshot(&second, b"snapshot", b"two")
            .unwrap();
        assert!(
            store
                .encrypted_messages(group.group_id())
                .unwrap()
                .messages
                .is_empty()
        );
        assert!(store.unread_message_counts().unwrap().is_empty());
        assert!(
            store
                .unmaterialized_message_events(group.group_id(), 10)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn version_twenty_seven_database_adds_message_deletions() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path();
        {
            let store = EventStore::open(path).unwrap();
            store
                .connection
                .execute_batch(
                    "DROP TABLE applied_message_deletions;
                     PRAGMA user_version = 27;",
                )
                .unwrap();
        }

        let store = EventStore::open(path).unwrap();
        assert!(
            store
                .encrypted_messages(GroupIdentity::generate().group_id())
                .unwrap()
                .messages
                .is_empty()
        );
        let version: i64 = store
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, super::SCHEMA_VERSION);
    }

    #[test]
    fn reply_reference_is_listed_with_its_message() {
        let mut store = EventStore::in_memory().unwrap();
        let author = DeviceIdentity::generate();
        let other = DeviceIdentity::generate();
        let group = GroupIdentity::generate();
        let original = message_event(&author, &group, 1, b"protected original");
        let reply = message_event(&other, &group, 1, b"protected reply");
        assert!(matches!(
            store.put_reply_message_and_encrypted_mls_provider_snapshot(
                &SignedEvent::create(
                    &author,
                    EventSpec {
                        group_id: group.group_id(),
                        author_sequence: 2,
                        causal_parents: &[],
                        created_at_unix_ms: 1_800_000_000_000,
                        kind: EventKind::MessageEdited,
                        protected_payload: b"protected edit",
                    },
                )
                .unwrap(),
                b"snapshot",
                b"body",
                original.id().as_bytes(),
                true,
            ),
            Err(StoreError::InvalidMessageEvent)
        ));
        store
            .put_message_and_encrypted_mls_provider_snapshot(&original, b"snapshot", b"original")
            .unwrap();
        store
            .put_reply_message_and_encrypted_mls_provider_snapshot(
                &reply,
                b"snapshot",
                b"reply",
                original.id().as_bytes(),
                true,
            )
            .unwrap();

        let page = store.encrypted_messages(group.group_id()).unwrap();
        let references = page
            .messages
            .iter()
            .map(|message| (message.event_id, message.reply_to))
            .collect::<Vec<_>>();
        assert!(references.contains(&(*original.id().as_bytes(), None)));
        assert!(references.contains(&(*reply.id().as_bytes(), Some(*original.id().as_bytes()))));
        assert_eq!(
            store.unread_message_counts().unwrap(),
            vec![(group.group_id(), 1)]
        );
    }

    #[test]
    fn peer_addresses_keep_the_most_recent_successes() {
        let mut store = EventStore::in_memory().unwrap();
        let group = GroupIdentity::generate().group_id();
        let other_group = GroupIdentity::generate().group_id();
        let peer = DeviceIdentity::generate().peer_id();
        assert!(store.peer_addresses(group, peer).unwrap().is_empty());

        for (index, at) in [(1_u8, 10), (2, 20), (3, 30), (4, 40), (5, 50)] {
            store
                .record_peer_address_success(group, peer, &[index], at)
                .unwrap();
        }
        // Refreshing an existing address moves it forward; an older report
        // never moves it back.
        store
            .record_peer_address_success(group, peer, &[2], 60)
            .unwrap();
        store
            .record_peer_address_success(group, peer, &[2], 15)
            .unwrap();
        store
            .record_peer_address_success(other_group, peer, &[9], 70)
            .unwrap();

        let addresses = store.peer_addresses(group, peer).unwrap();
        assert_eq!(
            addresses
                .iter()
                .map(|address| (address.address.clone(), address.last_success_at_unix))
                .collect::<Vec<_>>(),
            vec![(vec![2], 60), (vec![5], 50), (vec![4], 40), (vec![3], 30)]
        );
        assert!(matches!(
            store.record_peer_address_success(group, peer, &[], 1),
            Err(StoreError::InvalidPeerAddressSize(0))
        ));
        assert!(matches!(
            store.record_peer_address_success(group, peer, &[0; MAX_PEER_ADDRESS_BYTES + 1], 1),
            Err(StoreError::InvalidPeerAddressSize(_))
        ));
    }

    #[test]
    fn invite_permission_changes_apply_latest_per_device_and_drop_on_removal() {
        let mut store = EventStore::in_memory().unwrap();
        let owner = DeviceIdentity::generate();
        let group = GroupIdentity::generate();
        let member = DeviceIdentity::generate().peer_id();
        let other = DeviceIdentity::generate().peer_id();
        let owner_event = |sequence, kind| {
            SignedEvent::create(
                &owner,
                EventSpec {
                    group_id: group.group_id(),
                    author_sequence: sequence,
                    causal_parents: &[],
                    created_at_unix_ms: 1_800_000_000_000,
                    kind,
                    protected_payload: b"protected permission",
                },
            )
            .unwrap()
        };
        let grant = owner_event(1, EventKind::InvitePermissionChanged);
        let withdraw = owner_event(2, EventKind::InvitePermissionChanged);
        let other_grant = owner_event(3, EventKind::InvitePermissionChanged);
        let regrant = owner_event(4, EventKind::InvitePermissionChanged);
        for event in [&grant, &withdraw, &other_grant, &regrant] {
            store.put_event(event).unwrap();
        }
        assert_eq!(
            store
                .unmaterialized_message_events(group.group_id(), 10)
                .unwrap()
                .len(),
            4,
            "permission changes wait for decryption like metadata"
        );
        let message = message_event(&owner, &group, 5, b"protected message");
        assert!(matches!(
            store.put_invite_permission_and_encrypted_mls_provider_snapshot(
                &message,
                b"snapshot",
                &charp2p_core::InvitePermission::new(member, true),
            ),
            Err(StoreError::InvalidInvitePermissionEvent)
        ));

        // Applied out of order: the withdrawal has the higher sequence.
        store
            .put_invite_permission_and_encrypted_mls_provider_snapshot(
                &withdraw,
                b"snapshot two",
                &charp2p_core::InvitePermission::new(member, false),
            )
            .unwrap();
        store
            .put_invite_permission_and_encrypted_mls_provider_snapshot(
                &grant,
                b"snapshot one",
                &charp2p_core::InvitePermission::new(member, true),
            )
            .unwrap();
        store
            .put_invite_permission_and_encrypted_mls_provider_snapshot(
                &other_grant,
                b"snapshot three",
                &charp2p_core::InvitePermission::new(other, true),
            )
            .unwrap();
        assert!(
            !store
                .has_invite_permission(group.group_id(), member)
                .unwrap()
        );
        assert_eq!(
            store.invite_permitted_devices(group.group_id()).unwrap(),
            vec![other]
        );

        store
            .put_invite_permission_and_encrypted_mls_provider_snapshot(
                &regrant,
                b"snapshot four",
                &charp2p_core::InvitePermission::new(member, true),
            )
            .unwrap();
        assert!(
            store
                .has_invite_permission(group.group_id(), member)
                .unwrap()
        );
        assert!(
            store
                .unmaterialized_message_events(group.group_id(), 10)
                .unwrap()
                .is_empty()
        );

        let removal = owner_event(5, EventKind::MemberRemoved);
        store
            .put_mls_member_removal(&removal, b"snapshot five", member)
            .unwrap();
        assert!(
            !store
                .has_invite_permission(group.group_id(), member)
                .unwrap()
        );
        assert!(
            store
                .allow_removed_mls_member_readmission(group.group_id(), member)
                .unwrap()
        );
        assert!(
            !store
                .has_invite_permission(group.group_id(), member)
                .unwrap(),
            "permission is not restored when a removed device is readmitted"
        );
        assert_eq!(
            store.invite_permitted_devices(group.group_id()).unwrap(),
            vec![other]
        );

        let late = owner_event(6, EventKind::InvitePermissionChanged);
        store.put_event(&late).unwrap();
        store
            .put_mls_member_removal(
                &owner_event(7, EventKind::MemberRemoved),
                b"snapshot",
                other,
            )
            .unwrap();
        store
            .put_invite_permission_and_encrypted_mls_provider_snapshot(
                &late,
                b"snapshot six",
                &charp2p_core::InvitePermission::new(other, true),
            )
            .unwrap();
        store
            .allow_removed_mls_member_readmission(group.group_id(), other)
            .unwrap();
        assert!(
            store
                .invite_permitted_devices(group.group_id())
                .unwrap()
                .is_empty(),
            "a grant applied while the device is removed stays withdrawn"
        );
    }

    #[test]
    fn version_twenty_two_database_adds_invite_permissions() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path();
        {
            let store = EventStore::open(path).unwrap();
            store
                .connection
                .execute_batch(
                    "DROP TABLE applied_invite_permissions;
                     PRAGMA user_version = 22;",
                )
                .unwrap();
        }

        let store = EventStore::open(path).unwrap();
        let group = GroupIdentity::generate();
        assert!(
            store
                .invite_permitted_devices(group.group_id())
                .unwrap()
                .is_empty()
        );
        let version: i64 = store
            .connection
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .unwrap();
        assert_eq!(version, super::SCHEMA_VERSION);
    }

    #[test]
    fn version_twenty_one_database_adds_sequence_conflicts() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path();
        {
            let store = EventStore::open(path).unwrap();
            store
                .connection
                .execute_batch(
                    "DROP TABLE sequence_conflicts;
                     PRAGMA user_version = 21;",
                )
                .unwrap();
        }

        let mut store = EventStore::open(path).unwrap();
        let author = DeviceIdentity::generate();
        let group = GroupIdentity::generate();
        store
            .put_event(&message_event(&author, &group, 1, b"first"))
            .unwrap();
        assert!(
            store
                .put_event(&message_event(&author, &group, 1, b"other"))
                .is_err()
        );
        assert_eq!(store.sequence_conflicts(group.group_id()).unwrap().len(), 1);
    }

    #[test]
    fn version_twenty_database_adds_peer_addresses() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path();
        {
            let store = EventStore::open(path).unwrap();
            store
                .connection
                .execute_batch(
                    "DROP TABLE peer_addresses;
                     PRAGMA user_version = 20;",
                )
                .unwrap();
        }

        let mut store = EventStore::open(path).unwrap();
        let group = GroupIdentity::generate().group_id();
        let peer = DeviceIdentity::generate().peer_id();
        store
            .record_peer_address_success(group, peer, &[1], 1)
            .unwrap();
        assert_eq!(store.peer_addresses(group, peer).unwrap().len(), 1);
    }

    #[test]
    fn version_nineteen_database_adds_reply_references() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path();
        {
            let store = EventStore::open(path).unwrap();
            store
                .connection
                .execute_batch(
                    "DROP TABLE message_reply_references;
                     PRAGMA user_version = 19;",
                )
                .unwrap();
        }

        let store = EventStore::open(path).unwrap();
        let group = GroupIdentity::generate();
        assert!(
            store
                .encrypted_messages(group.group_id())
                .unwrap()
                .messages
                .is_empty()
        );
    }

    #[test]
    fn version_eighteen_database_adds_message_edits() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path();
        {
            let store = EventStore::open(path).unwrap();
            store
                .connection
                .execute_batch(
                    "DROP TABLE applied_message_edits;
                     PRAGMA user_version = 18;",
                )
                .unwrap();
        }

        let store = EventStore::open(path).unwrap();
        let group = GroupIdentity::generate();
        assert!(
            store
                .encrypted_messages(group.group_id())
                .unwrap()
                .messages
                .is_empty()
        );
    }

    #[test]
    fn version_seventeen_database_adds_group_metadata() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path();
        {
            let store = EventStore::open(path).unwrap();
            store
                .connection
                .execute_batch(
                    "DROP TABLE applied_group_metadata;
                     PRAGMA user_version = 17;",
                )
                .unwrap();
        }

        let store = EventStore::open(path).unwrap();
        assert!(store.current_group_names().unwrap().is_empty());
    }

    #[test]
    fn version_sixteen_database_adds_local_device_blocks() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path();
        {
            let store = EventStore::open(path).unwrap();
            store
                .connection
                .execute_batch(
                    "DROP TABLE blocked_local_devices;
                     PRAGMA user_version = 16;",
                )
                .unwrap();
        }

        let mut store = EventStore::open(path).unwrap();
        let device = DeviceIdentity::generate();
        let group = GroupIdentity::generate();
        assert!(
            store
                .block_device_locally(group.group_id(), device.peer_id())
                .unwrap()
        );
    }

    #[test]
    fn version_fifteen_database_adds_unread_message_markers() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path();
        {
            let store = EventStore::open(path).unwrap();
            store
                .connection
                .execute_batch(
                    "DROP TABLE unread_local_messages;
                     PRAGMA user_version = 15;",
                )
                .unwrap();
        }

        let mut store = EventStore::open(path).unwrap();
        let author = DeviceIdentity::generate();
        let group = GroupIdentity::generate();
        let event = message_event(&author, &group, 1, b"MLS ciphertext");
        store
            .put_received_message_and_encrypted_mls_provider_snapshot(
                &event,
                b"advanced encrypted provider",
                b"encrypted local message",
            )
            .unwrap();
        assert_eq!(
            store.unread_message_counts().unwrap(),
            vec![(group.group_id(), 1)]
        );
    }

    #[test]
    fn local_message_hide_rejects_the_wrong_group() {
        let mut store = EventStore::in_memory().unwrap();
        let author = DeviceIdentity::generate();
        let group = GroupIdentity::generate();
        let other_group = GroupIdentity::generate();
        let event = message_event(&author, &group, 1, b"MLS ciphertext");
        store
            .put_message_and_encrypted_mls_provider_snapshot(
                &event,
                b"advanced encrypted provider",
                b"encrypted local message",
            )
            .unwrap();

        assert!(matches!(
            store.hide_message_locally(other_group.group_id(), event.id().as_bytes()),
            Err(StoreError::CorruptIndex)
        ));
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
    fn unmaterialized_message_cannot_be_hidden_before_advancing_mls_state() {
        let mut store = EventStore::in_memory().unwrap();
        let author = DeviceIdentity::generate();
        let group = GroupIdentity::generate();
        let event = message_event(&author, &group, 1, b"MLS ciphertext");
        store.put_event(&event).unwrap();

        assert!(
            !store
                .hide_message_locally(group.group_id(), event.id().as_bytes())
                .unwrap()
        );
        assert_eq!(
            store
                .unmaterialized_message_events(group.group_id(), 1)
                .unwrap()[0]
                .id(),
            event.id()
        );
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
    fn applied_mls_commit_and_provider_snapshot_commit_together() {
        let mut store = EventStore::in_memory().unwrap();
        let author = DeviceIdentity::generate();
        let group = GroupIdentity::generate();
        let event = SignedEvent::create(
            &author,
            EventSpec {
                group_id: group.group_id(),
                author_sequence: 1,
                causal_parents: &[],
                created_at_unix_ms: 1,
                kind: EventKind::MemberAdded,
                protected_payload: b"MLS commit",
            },
        )
        .unwrap();
        store.put_event(&event).unwrap();
        assert_eq!(
            store
                .unapplied_mls_commit_events(group.group_id(), 1)
                .unwrap()[0]
                .id(),
            event.id()
        );

        assert!(
            store
                .put_applied_mls_event_and_encrypted_provider_snapshot(
                    &event,
                    b"advanced encrypted provider",
                )
                .unwrap()
        );
        assert!(
            store
                .unapplied_mls_commit_events(group.group_id(), 1)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store.encrypted_mls_provider_snapshot().unwrap().unwrap(),
            b"advanced encrypted provider"
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
        assert!(
            store
                .promote_pending_invitation_to_joined_group(group_id, inviter_device_id)
                .unwrap()
        );
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
    fn version_eight_database_adds_applied_mls_events() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path();
        {
            let store = EventStore::open(path).unwrap();
            store
                .connection
                .execute_batch(
                    "DROP TABLE mls_join_admissions;
                     DROP TABLE applied_mls_events;
                     PRAGMA user_version = 8;",
                )
                .unwrap();
        }

        let store = EventStore::open(path).unwrap();
        let group = GroupIdentity::generate();
        assert!(
            store
                .unapplied_mls_commit_events(group.group_id(), 1)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn version_nine_database_adds_join_admission_retries() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path();
        {
            let store = EventStore::open(path).unwrap();
            store
                .connection
                .execute_batch(
                    "DROP TABLE mls_join_admissions;
                     PRAGMA user_version = 9;",
                )
                .unwrap();
        }

        let store = EventStore::open(path).unwrap();
        let group_id = GroupIdentity::generate().group_id();
        let member_id = DeviceIdentity::generate().peer_id();
        assert!(
            store
                .mls_join_admission(group_id, member_id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn version_ten_database_adds_removed_member_blocks() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path();
        {
            let store = EventStore::open(path).unwrap();
            store
                .connection
                .execute_batch(
                    "DROP TABLE removed_mls_members;
                     PRAGMA user_version = 10;",
                )
                .unwrap();
        }

        let store = EventStore::open(path).unwrap();
        assert!(
            !store
                .is_removed_mls_member(
                    GroupIdentity::generate().group_id(),
                    DeviceIdentity::generate().peer_id(),
                )
                .unwrap()
        );
    }

    #[test]
    fn version_eleven_database_adds_local_message_hides() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path();
        {
            let store = EventStore::open(path).unwrap();
            store
                .connection
                .execute_batch(
                    "DROP TABLE hidden_local_messages;
                     PRAGMA user_version = 11;",
                )
                .unwrap();
        }

        let mut store = EventStore::open(path).unwrap();
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
        assert!(
            store
                .hide_message_locally(group.group_id(), event.id().as_bytes())
                .unwrap()
        );
    }

    #[test]
    fn version_twelve_database_adds_peer_acknowledgements() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path();
        {
            let store = EventStore::open(path).unwrap();
            store
                .connection
                .execute_batch(
                    "DROP TABLE peer_acknowledged_author_heads;
                     PRAGMA user_version = 12;",
                )
                .unwrap();
        }

        let mut store = EventStore::open(path).unwrap();
        let group_id = GroupIdentity::generate().group_id();
        let author_id = DeviceIdentity::generate().peer_id();
        let peer_id = DeviceIdentity::generate().peer_id();
        store
            .acknowledge_author_head(group_id, peer_id, author_id, 7)
            .unwrap();
        assert_eq!(
            store
                .max_acknowledged_author_head(group_id, author_id)
                .unwrap(),
            7
        );
    }

    #[test]
    fn version_thirteen_database_adds_owner_discovery_keys() {
        let file = NamedTempFile::new().unwrap();
        let path = file.path();
        {
            let store = EventStore::open(path).unwrap();
            store
                .connection
                .execute_batch(
                    "DROP TABLE owner_discovery_keys;
                     PRAGMA user_version = 13;",
                )
                .unwrap();
        }

        let mut store = EventStore::open(path).unwrap();
        let metadata = OwnerDiscoveryKeyMetadata {
            invitation_id: InvitationId::from_bytes([9; 16]),
            group_id: GroupIdentity::generate().group_id(),
        };
        store.put_owner_discovery_key(&metadata).unwrap();
        assert_eq!(
            store.owner_discovery_keys(metadata.group_id).unwrap(),
            vec![metadata]
        );
    }

    #[test]
    fn version_fourteen_database_adds_joined_group_sync_time() {
        let connection = Connection::open_in_memory().unwrap();
        let group_id = GroupIdentity::generate().group_id();
        let inviter_device_id = DeviceIdentity::generate().peer_id();
        connection
            .execute_batch(
                "CREATE TABLE joined_groups (
                    group_id BLOB PRIMARY KEY NOT NULL,
                    group_name TEXT NOT NULL,
                    inviter_name TEXT NOT NULL,
                    inviter_device_id BLOB NOT NULL,
                    history_policy INTEGER NOT NULL CHECK(history_policy BETWEEN 0 AND 2)
                 ) STRICT;
                 PRAGMA user_version = 14;",
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO joined_groups (
                    group_id, group_name, inviter_name, inviter_device_id, history_policy
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    group_id.to_bytes(),
                    "Design Crew",
                    "Maya",
                    inviter_device_id.to_bytes(),
                    0,
                ],
            )
            .unwrap();

        let mut store = EventStore::from_connection(connection).unwrap();
        assert_eq!(
            store.joined_groups().unwrap()[0].last_synchronized_at_unix,
            None
        );
        assert!(
            store
                .record_joined_group_synchronization(group_id, 1_800_000_123)
                .unwrap()
        );
        assert_eq!(
            store.joined_groups().unwrap()[0].last_synchronized_at_unix,
            Some(1_800_000_123)
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
