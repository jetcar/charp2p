#![forbid(unsafe_code)]

//! Shared protocol and domain logic for CharP2P clients and nodes.

mod discovery;
mod event;
mod group_identity;
mod group_metadata;
mod identity;
mod identity_backup;
mod invitation;
mod invite_permission;
mod invite_request;
mod join;
mod message_body;
mod message_edit;
mod sync;

pub use discovery::DiscoveryKey;
pub use event::{EventError, EventId, EventKind, EventSpec, SignedEvent};
pub use group_identity::{GroupIdentity, GroupIdentityError, GroupIdentitySecret};
pub use group_metadata::{GroupMetadata, GroupMetadataError, MAX_GROUP_ICON, MAX_GROUP_NAME_BYTES};
pub use identity::{DeviceIdentity, DeviceIdentityError, DeviceIdentitySecret};
pub use identity_backup::{
    IdentityBackupError, MAX_BACKUP_PASSPHRASE_BYTES, MAX_IDENTITY_BACKUP_BYTES,
    MIN_BACKUP_PASSPHRASE_CHARS, RestoredIdentityBackup, open_identity_backup,
    seal_identity_backup,
};
pub use invitation::{
    HistoryPolicy, Invitation, InvitationError, InvitationId, InvitationSpec,
    MAX_INVITATION_ENCODED_BYTES,
};
pub use invite_permission::{InvitePermission, InvitePermissionError};
pub use invite_request::{
    InviteRejectReason, InviteRequest, InviteRequestError, InviteResponse,
    MAX_INVITE_REQUEST_LIFETIME_SECONDS, MAX_INVITE_REQUEST_WIRE_BYTES,
    MAX_INVITE_RESPONSE_WIRE_BYTES,
};
pub use join::{
    JoinError, JoinRejectReason, JoinRequest, JoinResponse, MAX_JOIN_MLS_MESSAGE_BYTES,
    MAX_JOIN_REQUEST_WIRE_BYTES, MAX_JOIN_RESPONSE_WIRE_BYTES,
};
pub use libp2p_identity::{PeerId, PublicKey, SigningError};
pub use message_body::{
    MAX_MESSAGE_BODY_BYTES, MAX_MESSAGE_TEXT_BYTES, MessageBody, MessageBodyError,
};
pub use message_edit::{MAX_MESSAGE_EDIT_TEXT_BYTES, MessageEdit, MessageEditError};
pub use sync::{
    MAX_SYNC_AUTHORS, MAX_SYNC_BATCH_ITEMS, MAX_SYNC_EVENT_BYTES, MAX_SYNC_RESPONSE_BYTES,
    SyncAuthorHead, SyncError, SyncPeerHead, SyncRejectReason, SyncRequest, SyncResponse,
};
