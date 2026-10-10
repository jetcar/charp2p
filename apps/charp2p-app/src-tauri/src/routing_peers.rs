use std::path::PathBuf;
use std::sync::Mutex;

use libp2p::{multiaddr::Protocol, Multiaddr, PeerId};
use serde::{Deserialize, Serialize};

use crate::network::parse_bootstrap_peer;
use crate::preference_file;

/// Most routing peers one device remembers (ADR-046).
pub const MAX_REMEMBERED_ROUTING_PEERS: usize = 8;
/// Longest remembered routing peer multiaddress, including its peer ID.
pub const MAX_ROUTING_PEER_ADDRESS_BYTES: usize = 256;

/// Device-local cache of routing peers recently reached (ADR-046). Holds no
/// secrets and is never synchronized, shown as configuration or invited.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RememberedRoutingPeers {
    /// Multiaddresses ending in the peer's `/p2p/` peer ID, most recently
    /// successful first.
    addresses: Vec<String>,
}

impl RememberedRoutingPeers {
    fn is_valid(&self) -> bool {
        if self.addresses.len() > MAX_REMEMBERED_ROUTING_PEERS {
            return false;
        }
        let mut seen = Vec::with_capacity(self.addresses.len());
        for address in &self.addresses {
            let Some(peer_id) = remembered_peer_id(address) else {
                return false;
            };
            if seen.contains(&peer_id) {
                return false;
            }
            seen.push(peer_id);
        }
        true
    }
}

/// Peer ID of a remembered address, or `None` when it is not an acceptable
/// direct routing peer address.
fn remembered_peer_id(address: &str) -> Option<PeerId> {
    if address.len() > MAX_ROUTING_PEER_ADDRESS_BYTES {
        return None;
    }
    let peer = parse_bootstrap_peer(address).ok()?;
    if peer
        .address
        .iter()
        .any(|protocol| matches!(protocol, Protocol::P2p(_) | Protocol::P2pCircuit))
    {
        return None;
    }
    Some(peer.peer_id)
}

/// Stores the remembered routing peer list in a small file next to the
/// database. The list is a cache: an unreadable or invalid file is treated
/// as empty and replaced on the next success.
pub struct RoutingPeersService {
    path: PathBuf,
    lock: Mutex<()>,
}

impl RoutingPeersService {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            lock: Mutex::new(()),
        }
    }

    /// Remembered multiaddresses, most recently successful first.
    pub fn remembered(&self) -> Vec<String> {
        let Ok(_guard) = self.lock.lock() else {
            return Vec::new();
        };
        self.read().addresses
    }

    /// Records a routing peer reached at `address`, moving it to the front
    /// and dropping the oldest entry beyond the limit. Relayed or oversized
    /// addresses are ignored.
    pub fn record(&self, peer_id: PeerId, address: &Multiaddr) -> Result<(), &'static str> {
        let mut address = address.clone();
        if let Some(Protocol::P2p(suffix)) = address.iter().last() {
            if suffix != peer_id {
                return Ok(());
            }
            address.pop();
        }
        let entry = address.with(Protocol::P2p(peer_id)).to_string();
        if remembered_peer_id(&entry) != Some(peer_id) {
            return Ok(());
        }
        let _guard = self.lock.lock().map_err(|_| "routing_peers_unavailable")?;
        let mut peers = self.read();
        if peers.addresses.first() == Some(&entry) {
            return Ok(());
        }
        peers
            .addresses
            .retain(|existing| remembered_peer_id(existing) != Some(peer_id));
        peers.addresses.insert(0, entry);
        peers.addresses.truncate(MAX_REMEMBERED_ROUTING_PEERS);
        preference_file::write(&self.path, &peers).map_err(|_| "routing_peers_unavailable")
    }

    fn read(&self) -> RememberedRoutingPeers {
        preference_file::read::<RememberedRoutingPeers>(&self.path)
            .ok()
            .flatten()
            .filter(RememberedRoutingPeers::is_valid)
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use charp2p_core::DeviceIdentity;

    use super::*;

    const ADDRESS: &str = "/ip4/203.0.113.7/udp/4001/quic-v1";

    fn peer() -> PeerId {
        DeviceIdentity::generate().peer_id()
    }

    fn address() -> Multiaddr {
        ADDRESS.parse().expect("address is valid")
    }

    fn service(directory: &tempfile::TempDir) -> RoutingPeersService {
        RoutingPeersService::new(directory.path().join("routing-peers.json"))
    }

    #[test]
    fn no_routing_peers_without_a_stored_list() {
        let directory = tempfile::tempdir().expect("temporary directory is available");

        assert!(service(&directory).remembered().is_empty());
    }

    #[test]
    fn routing_peers_persist_most_recent_first_once_each() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let (first, second) = (peer(), peer());
        let service = service(&directory);

        service.record(first, &address()).expect("peer is stored");
        service.record(second, &address()).expect("peer is stored");
        let moved: Multiaddr = format!("/ip4/198.51.100.2/tcp/4001/p2p/{first}")
            .parse()
            .expect("address is valid");
        service.record(first, &moved).expect("peer is stored");

        assert_eq!(
            RoutingPeersService::new(directory.path().join("routing-peers.json")).remembered(),
            vec![
                format!("/ip4/198.51.100.2/tcp/4001/p2p/{first}"),
                format!("{ADDRESS}/p2p/{second}"),
            ]
        );
        assert!(!directory.path().join("routing-peers.json.tmp").exists());
    }

    #[test]
    fn routing_peers_are_bounded_to_the_most_recent() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let service = service(&directory);
        let peers: Vec<PeerId> = (0..=MAX_REMEMBERED_ROUTING_PEERS).map(|_| peer()).collect();

        for peer_id in &peers {
            service
                .record(*peer_id, &address())
                .expect("peer is stored");
        }

        let remembered = service.remembered();
        assert_eq!(remembered.len(), MAX_REMEMBERED_ROUTING_PEERS);
        assert_eq!(
            remembered[0],
            format!("{ADDRESS}/p2p/{}", peers[peers.len() - 1])
        );
        assert!(!remembered.contains(&format!("{ADDRESS}/p2p/{}", peers[0])));
    }

    #[test]
    fn relayed_mismatched_and_oversized_addresses_are_ignored() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let service = service(&directory);
        let target = peer();
        let relayed: Multiaddr = format!("{ADDRESS}/p2p/{}/p2p-circuit", peer())
            .parse()
            .expect("address is valid");
        let mismatched: Multiaddr = format!("{ADDRESS}/p2p/{}", peer())
            .parse()
            .expect("address is valid");
        let oversized: Multiaddr = format!("/dns4/{}.example/udp/4001/quic-v1", "a".repeat(200))
            .parse()
            .expect("address is valid");

        for address in [relayed, mismatched, oversized] {
            service
                .record(target, &address)
                .expect("address is skipped");
        }

        assert!(service.remembered().is_empty());
    }

    #[test]
    fn an_invalid_file_is_treated_as_empty_and_replaced() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let path = directory.path().join("routing-peers.json");
        let service = service(&directory);
        let peer_id = peer();

        std::fs::write(&path, b"{\"addresses\":[\"not an address\"]}").expect("file is written");
        assert!(service.remembered().is_empty());

        service.record(peer_id, &address()).expect("peer is stored");
        assert_eq!(
            service.remembered(),
            vec![format!("{ADDRESS}/p2p/{peer_id}")]
        );
    }
}
