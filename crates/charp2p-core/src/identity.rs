use libp2p_identity::{DecodingError, Keypair, PeerId, PublicKey, SigningError};
use thiserror::Error;
use zeroize::Zeroizing;

/// An encoded private device identity for transfer to platform-protected storage.
///
/// The owned bytes are erased when dropped. Callers must never log, serialize to
/// routine application storage, or expose these bytes to the webview.
pub struct DeviceIdentitySecret(Zeroizing<Vec<u8>>);

impl DeviceIdentitySecret {
    /// Wraps bytes loaded from platform-protected storage.
    pub fn from_protected_bytes(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Exposes the encoded key only to a platform-protected storage adapter.
    pub fn expose_for_protected_storage(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// A failure to encode or decode a persisted device identity.
#[derive(Debug, Error)]
pub enum DeviceIdentityError {
    #[error("device identity encoding is invalid")]
    InvalidEncoding(#[source] DecodingError),
}

/// A locally controlled device identity.
///
/// The private key is intentionally not exposed. Persistence will be handled by
/// a platform key-store adapter rather than by the domain API.
pub struct DeviceIdentity {
    keypair: Keypair,
}

impl DeviceIdentity {
    /// Generates a new Ed25519 identity using the operating system random
    /// source through `libp2p-identity`.
    pub fn generate() -> Self {
        Self {
            keypair: Keypair::generate_ed25519(),
        }
    }

    /// Generates an identity and an encoded secret suitable for immediate
    /// transfer to platform-protected storage.
    pub fn generate_persistable() -> Result<(Self, DeviceIdentitySecret), DeviceIdentityError> {
        let identity = Self::generate();
        let encoded = identity
            .keypair
            .to_protobuf_encoding()
            .map_err(DeviceIdentityError::InvalidEncoding)?;

        Ok((
            identity,
            DeviceIdentitySecret::from_protected_bytes(encoded),
        ))
    }

    /// Restores an identity loaded from platform-protected storage.
    pub fn from_persisted_secret(
        secret: &DeviceIdentitySecret,
    ) -> Result<Self, DeviceIdentityError> {
        let keypair = Keypair::from_protobuf_encoding(secret.expose_for_protected_storage())
            .map_err(DeviceIdentityError::InvalidEncoding)?;

        Ok(Self { keypair })
    }

    /// Returns the libp2p peer identifier derived from this device's public
    /// key.
    pub fn peer_id(&self) -> PeerId {
        self.keypair.public().to_peer_id()
    }

    /// Returns the public key that other peers use to verify this device.
    pub fn public_key(&self) -> PublicKey {
        self.keypair.public()
    }

    /// Signs a protocol payload with this device identity.
    pub fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SigningError> {
        self.keypair.sign(payload)
    }

    /// Transfers this identity into the libp2p networking layer without
    /// serializing or copying its private key into application storage.
    pub fn into_network_keypair(self) -> Keypair {
        self.keypair
    }

    /// Verifies a signature from any device public key.
    pub fn verify(public_key: &PublicKey, payload: &[u8], signature: &[u8]) -> bool {
        public_key.verify(payload, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::{DeviceIdentity, DeviceIdentitySecret};

    #[test]
    fn generated_devices_have_distinct_peer_ids() {
        let first = DeviceIdentity::generate();
        let second = DeviceIdentity::generate();

        assert_ne!(first.peer_id(), second.peer_id());
    }

    #[test]
    fn signatures_verify_only_for_the_original_payload_and_device() {
        let signer = DeviceIdentity::generate();
        let other = DeviceIdentity::generate();
        let payload = b"charp2p identity test";
        let signature = signer.sign(payload).expect("Ed25519 signing succeeds");

        assert!(DeviceIdentity::verify(
            &signer.public_key(),
            payload,
            &signature
        ));
        assert!(!DeviceIdentity::verify(
            &signer.public_key(),
            b"tampered payload",
            &signature
        ));
        assert!(!DeviceIdentity::verify(
            &other.public_key(),
            payload,
            &signature
        ));
    }

    #[test]
    fn peer_id_is_derived_from_the_public_key() {
        let identity = DeviceIdentity::generate();

        assert_eq!(identity.peer_id(), identity.public_key().to_peer_id());
    }

    #[test]
    fn network_keypair_preserves_the_device_peer_id() {
        let identity = DeviceIdentity::generate();
        let peer_id = identity.peer_id();

        assert_eq!(
            identity.into_network_keypair().public().to_peer_id(),
            peer_id
        );
    }

    #[test]
    fn persisted_secret_restores_the_same_peer_identity() {
        let (identity, secret) =
            DeviceIdentity::generate_persistable().expect("Ed25519 identity can be encoded");
        let restored = DeviceIdentity::from_persisted_secret(&secret)
            .expect("encoded Ed25519 identity can be restored");

        assert_eq!(restored.peer_id(), identity.peer_id());
    }

    #[test]
    fn invalid_persisted_secret_is_rejected() {
        let secret = DeviceIdentitySecret::from_protected_bytes(vec![0, 1, 2, 3]);

        assert!(DeviceIdentity::from_persisted_secret(&secret).is_err());
    }
}
