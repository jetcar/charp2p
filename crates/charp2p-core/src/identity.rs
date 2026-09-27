use libp2p_identity::{Keypair, PeerId, PublicKey, SigningError};

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

    /// Verifies a signature from any device public key.
    pub fn verify(public_key: &PublicKey, payload: &[u8], signature: &[u8]) -> bool {
        public_key.verify(payload, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::DeviceIdentity;

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
}
