#![forbid(unsafe_code)]

//! Shared protocol and domain logic for CharP2P clients and nodes.

mod discovery;
mod event;
mod group_identity;
mod group_metadata;
mod identity;
mod invitation;
mod join;
mod sync;

pub use discovery::DiscoveryKey;
pub use event::{EventError, EventId, EventKind, EventSpec, SignedEvent};
pub use group_identity::{GroupIdentity, GroupIdentityError, GroupIdentitySecret};
pub use group_metadata::{GroupMetadata, GroupMetadataError, MAX_GROUP_NAME_BYTES};
pub use identity::{DeviceIdentity, DeviceIdentityError, DeviceIdentitySecret};
pub use invitation::{
    HistoryPolicy, Invitation, InvitationError, InvitationId, InvitationSpec,
    MAX_INVITATION_ENCODED_BYTES,
};
pub use join::{
    JoinError, JoinRejectReason, JoinRequest, JoinResponse, MAX_JOIN_MLS_MESSAGE_BYTES,
    MAX_JOIN_REQUEST_WIRE_BYTES, MAX_JOIN_RESPONSE_WIRE_BYTES,
};
pub use libp2p_identity::{PeerId, PublicKey, SigningError};
pub use sync::{
    MAX_SYNC_AUTHORS, MAX_SYNC_BATCH_ITEMS, MAX_SYNC_EVENT_BYTES, MAX_SYNC_RESPONSE_BYTES,
    SyncAuthorHead, SyncError, SyncRejectReason, SyncRequest, SyncResponse,
};
