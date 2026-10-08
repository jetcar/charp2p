use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::network::parse_bootstrap_peer;
use crate::preference_file::{self, PreferenceReadError};

/// Most community bootstrap nodes one device keeps (ADR-038).
pub const MAX_COMMUNITY_NODES: usize = 8;
/// Longest accepted community node multiaddress, including its peer ID.
pub const MAX_COMMUNITY_NODE_ADDRESS_BYTES: usize = 256;

/// Device-local community bootstrap nodes (ADR-038). Holds no secrets and is
/// never synchronized.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommunityNodesPreference {
    /// Multiaddresses ending in the node's `/p2p/` peer ID.
    pub addresses: Vec<String>,
}

impl CommunityNodesPreference {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.addresses.len() > MAX_COMMUNITY_NODES {
            return Err("community_nodes_limit");
        }
        let mut seen = Vec::with_capacity(self.addresses.len());
        for address in &self.addresses {
            if address.len() > MAX_COMMUNITY_NODE_ADDRESS_BYTES {
                return Err("community_node_invalid");
            }
            let peer = parse_bootstrap_peer(address).map_err(|_| "community_node_invalid")?;
            let key = (peer.peer_id, peer.address);
            if seen.contains(&key) {
                return Err("community_node_duplicate");
            }
            seen.push(key);
        }
        Ok(())
    }
}

/// Stores the community node list in a small file next to the database.
pub struct CommunityNodesService {
    path: PathBuf,
    lock: Mutex<()>,
}

impl CommunityNodesService {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            lock: Mutex::new(()),
        }
    }

    /// Reads the stored list. A missing file means no community nodes; an
    /// unreadable or invalid file is reported instead of being replaced.
    pub fn preference(&self) -> Result<CommunityNodesPreference, &'static str> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| "community_nodes_unavailable")?;
        let preference: CommunityNodesPreference = preference_file::read(&self.path)
            .map_err(|error| match error {
                PreferenceReadError::Unavailable => "community_nodes_unavailable",
                PreferenceReadError::Invalid => "community_nodes_invalid",
            })?
            .unwrap_or_default();
        preference
            .validate()
            .map_err(|_| "community_nodes_invalid")?;
        Ok(preference)
    }

    pub fn set(&self, preference: &CommunityNodesPreference) -> Result<(), &'static str> {
        preference.validate()?;
        let _guard = self
            .lock
            .lock()
            .map_err(|_| "community_nodes_unavailable")?;
        preference_file::write(&self.path, preference).map_err(|_| "community_nodes_unavailable")
    }
}

#[cfg(test)]
mod tests {
    use charp2p_core::DeviceIdentity;

    use super::*;

    fn address() -> String {
        let peer_id = DeviceIdentity::generate().peer_id();
        format!("/ip4/203.0.113.7/udp/4001/quic-v1/p2p/{peer_id}")
    }

    fn service(directory: &tempfile::TempDir) -> CommunityNodesService {
        CommunityNodesService::new(directory.path().join("community-nodes.json"))
    }

    #[test]
    fn no_community_nodes_without_a_stored_list() {
        let directory = tempfile::tempdir().expect("temporary directory is available");

        assert_eq!(
            service(&directory).preference(),
            Ok(CommunityNodesPreference::default())
        );
    }

    #[test]
    fn community_nodes_persist() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let preference = CommunityNodesPreference {
            addresses: vec![address(), address()],
        };

        service(&directory)
            .set(&preference)
            .expect("community nodes are stored");

        assert_eq!(service(&directory).preference(), Ok(preference));
        assert!(!directory.path().join("community-nodes.json.tmp").exists());
    }

    #[test]
    fn community_nodes_are_bounded_valid_and_distinct() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let service = service(&directory);
        let set = |addresses: Vec<String>| service.set(&CommunityNodesPreference { addresses });
        let repeated = address();

        assert_eq!(
            set((0..=MAX_COMMUNITY_NODES).map(|_| address()).collect()),
            Err("community_nodes_limit")
        );
        assert_eq!(
            set(vec!["/ip4/203.0.113.7/udp/4001/quic-v1".to_owned()]),
            Err("community_node_invalid")
        );
        assert_eq!(
            set(vec!["not an address".to_owned()]),
            Err("community_node_invalid")
        );
        assert_eq!(
            set(vec![format!(
                "/dns4/{}.example/udp/4001/quic-v1/p2p/{}",
                "a".repeat(200),
                DeviceIdentity::generate().peer_id()
            )]),
            Err("community_node_invalid")
        );
        assert_eq!(
            set(vec![repeated.clone(), repeated]),
            Err("community_node_duplicate")
        );
        assert_eq!(
            service.preference(),
            Ok(CommunityNodesPreference::default())
        );
    }

    #[test]
    fn an_invalid_stored_list_is_reported() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        std::fs::write(
            directory.path().join("community-nodes.json"),
            r#"{"addresses":["not an address"]}"#,
        )
        .expect("file is written");

        assert_eq!(
            service(&directory).preference(),
            Err("community_nodes_invalid")
        );
    }
}
