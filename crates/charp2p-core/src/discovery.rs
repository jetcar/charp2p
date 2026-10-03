use libp2p_identity::PeerId;

use crate::Invitation;

const DISCOVERY_KEY_DOMAIN: &[u8] = b"charp2p-rendezvous-v1\0";

/// Opaque DHT key shared only by holders of a group invitation secret.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct DiscoveryKey([u8; 32]);

impl DiscoveryKey {
    /// Restores a previously derived rendezvous key from protected storage.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Derives the rendezvous key carried implicitly by a verified invitation.
    pub fn from_invitation(invitation: &Invitation) -> Self {
        Self::derive(invitation.group_id(), invitation.discovery_secret())
    }

    /// Derives a rendezvous key from a group and its 32-byte discovery secret.
    pub fn derive(group_id: PeerId, discovery_secret: &[u8; 32]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(DISCOVERY_KEY_DOMAIN);
        hasher.update(&group_id.to_bytes());
        hasher.update(discovery_secret);
        Self(*hasher.finalize().as_bytes())
    }

    /// Returns the fixed-size DHT record-key preimage.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use crate::{DeviceIdentity, GroupIdentity, HistoryPolicy, Invitation, InvitationSpec};

    use super::DiscoveryKey;

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn invitation_derives_a_stable_discovery_key() {
        let owner = GroupIdentity::generate();
        let invitation = Invitation::issue(
            &owner,
            DeviceIdentity::generate().peer_id(),
            InvitationSpec {
                group_name: "Design Crew",
                inviter_name: "Maya",
                expires_at_unix: NOW + 3_600,
                history_policy: HistoryPolicy::FromInvitation,
                reusable: false,
            },
            NOW,
        )
        .unwrap();

        assert_eq!(
            DiscoveryKey::from_invitation(&invitation),
            DiscoveryKey::derive(owner.group_id(), invitation.discovery_secret())
        );
    }

    #[test]
    fn group_and_secret_are_both_bound_into_the_key() {
        let first_group = GroupIdentity::generate();
        let second_group = GroupIdentity::generate();
        let first_secret = [1; 32];
        let second_secret = [2; 32];

        assert_ne!(
            DiscoveryKey::derive(first_group.group_id(), &first_secret),
            DiscoveryKey::derive(second_group.group_id(), &first_secret)
        );
        assert_ne!(
            DiscoveryKey::derive(first_group.group_id(), &first_secret),
            DiscoveryKey::derive(first_group.group_id(), &second_secret)
        );
    }

    #[test]
    fn derived_key_round_trips_through_protected_bytes() {
        let key = DiscoveryKey::derive(GroupIdentity::generate().group_id(), &[7; 32]);

        assert_eq!(DiscoveryKey::from_bytes(*key.as_bytes()), key);
    }
}
