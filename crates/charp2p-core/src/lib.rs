#![forbid(unsafe_code)]

//! Shared protocol and domain logic for CharP2P clients and nodes.

mod group_identity;
mod identity;
mod invitation;

pub use group_identity::GroupIdentity;
pub use identity::DeviceIdentity;
pub use invitation::{HistoryPolicy, Invitation, InvitationError, InvitationSpec};
pub use libp2p_identity::{PeerId, PublicKey, SigningError};
