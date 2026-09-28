use libp2p_identity::{DecodingError, Keypair, PeerId, PublicKey, SigningError};
use thiserror::Error;
use zeroize::Zeroizing;

/// Encoded private group-root key for transfer to platform-protected storage.
pub struct GroupIdentitySecret(Zeroizing<Vec<u8>>);

impl GroupIdentitySecret {
    /// Wraps bytes loaded from platform-protected storage.
    pub fn from_protected_bytes(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Accepts bytes already wrapped immediately after protected-store read.
    pub fn from_protected_zeroizing(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }

    /// Exposes the encoded key only to a platform-protected storage adapter.
    pub fn expose_for_protected_storage(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// A failure to encode or decode a persisted group identity.
#[derive(Debug, Error)]
pub enum GroupIdentityError {
    #[error("group identity encoding is invalid")]
    InvalidEncoding(#[source] DecodingError),
}

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

    /// Generates a group root and encoded secret for protected storage.
    pub fn generate_persistable() -> Result<(Self, GroupIdentitySecret), GroupIdentityError> {
        let identity = Self::generate();
        let encoded = identity
            .keypair
            .to_protobuf_encoding()
            .map_err(GroupIdentityError::InvalidEncoding)?;
        Ok((identity, GroupIdentitySecret::from_protected_bytes(encoded)))
    }

    /// Restores a group root loaded from platform-protected storage.
    pub fn from_persisted_secret(secret: &GroupIdentitySecret) -> Result<Self, GroupIdentityError> {
        let keypair = Keypair::from_protobuf_encoding(secret.expose_for_protected_storage())
            .map_err(GroupIdentityError::InvalidEncoding)?;
        Ok(Self { keypair })
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

#[cfg(test)]
mod tests {
    use super::{GroupIdentity, GroupIdentitySecret};

    #[test]
    fn persisted_secret_restores_the_same_group_identity() {
        let (identity, secret) =
            GroupIdentity::generate_persistable().expect("group identity encodes");
        let restored =
            GroupIdentity::from_persisted_secret(&secret).expect("group identity restores");

        assert_eq!(restored.group_id(), identity.group_id());
    }

    #[test]
    fn invalid_persisted_secret_is_rejected() {
        let secret = GroupIdentitySecret::from_protected_bytes(vec![0, 1, 2, 3]);
        assert!(GroupIdentity::from_persisted_secret(&secret).is_err());
    }
}
