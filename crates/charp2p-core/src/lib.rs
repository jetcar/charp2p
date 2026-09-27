#![forbid(unsafe_code)]

//! Shared protocol and domain logic for CharP2P clients and nodes.

mod identity;

pub use identity::DeviceIdentity;
pub use libp2p_identity::{PeerId, PublicKey, SigningError};
