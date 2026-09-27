use libp2p_identity::{Keypair, PeerId, PublicKey, SigningError};

/// The stable cryptographic root of a group.
///
/// This key is distinct from every member device identity so device revocation
/// and administration-key rotation do not change the group identifier.
pub struct GroupIdentity {
    keypair: Keypair,
}

impl GroupIdentity {
    /// Generates a new Ed25519 group root identity.
    pub fn generate() -> Self {
        Self {
            keypair: Keypair::generate_ed25519(),
        }
    }

    /// Returns the stable identifier derived from the group root public key.
    pub fn group_id(&self) -> PeerId {
        self.keypair.public().to_peer_id()
    }

    /// Returns the group root public key.
    pub fn public_key(&self) -> PublicKey {
        self.keypair.public()
    }

    pub(crate) fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SigningError> {
        self.keypair.sign(payload)
    }
}
