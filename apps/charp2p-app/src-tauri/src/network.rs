use std::{collections::BTreeSet, time::Duration};

use charp2p_core::{DeviceIdentity, DiscoveryKey, Invitation};
use charp2p_network::{NetworkEvent, NetworkNode};
use libp2p::{multiaddr::Protocol, Multiaddr, PeerId};
use serde::Serialize;
use tokio::time::timeout;

const BUILT_IN_BOOTSTRAP_ADDRESSES: &[&str] = &[];
const BOOTSTRAP_ENVIRONMENT_VARIABLE: &str = "CHARP2P_BOOTSTRAP_NODES";
const MAX_BOOTSTRAP_PEERS: usize = 16;
const MAX_BOOTSTRAP_ADDRESS_BYTES: usize = 512;
const SEARCH_TIMEOUT: Duration = Duration::from_secs(12);

#[derive(Clone)]
struct BootstrapPeer {
    peer_id: PeerId,
    address: Multiaddr,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerSearchResult {
    pub status: &'static str,
    pub discovered_peers: usize,
}

pub struct NetworkService {
    bootstrap_peers: Vec<BootstrapPeer>,
}

impl NetworkService {
    pub fn from_environment() -> Result<Self, &'static str> {
        let environment = std::env::var(BOOTSTRAP_ENVIRONMENT_VARIABLE).unwrap_or_default();
        Self::from_sources(BUILT_IN_BOOTSTRAP_ADDRESSES, &environment)
    }

    fn from_sources(built_in: &[&str], environment: &str) -> Result<Self, &'static str> {
        let configured = built_in.iter().copied().chain(
            environment
                .split(';')
                .map(str::trim)
                .filter(|item| !item.is_empty()),
        );
        let mut bootstrap_peers = Vec::new();
        for configured_address in configured {
            if bootstrap_peers.len() == MAX_BOOTSTRAP_PEERS
                || configured_address.len() > MAX_BOOTSTRAP_ADDRESS_BYTES
            {
                return Err("network_configuration_invalid");
            }
            bootstrap_peers.push(parse_bootstrap_peer(configured_address)?);
        }
        Ok(Self { bootstrap_peers })
    }

    pub async fn search(
        &self,
        identity: DeviceIdentity,
        invitation: &Invitation,
    ) -> Result<PeerSearchResult, &'static str> {
        if self.bootstrap_peers.is_empty() {
            return Ok(PeerSearchResult {
                status: "bootstrapRequired",
                discovered_peers: 0,
            });
        }

        let key = DiscoveryKey::from_invitation(invitation);
        let mut node = NetworkNode::new(identity.into_network_keypair());
        node.listen_on(
            "/ip4/0.0.0.0/udp/0/quic-v1"
                .parse()
                .map_err(|_| "network_configuration_invalid")?,
        )
        .map_err(|_| "network_unavailable")?;
        for bootstrap in &self.bootstrap_peers {
            node.add_bootstrap_peer(bootstrap.peer_id, bootstrap.address.clone());
        }
        node.bootstrap().map_err(|_| "network_unavailable")?;
        node.find_group_peers(key);

        timeout(SEARCH_TIMEOUT, async {
            let mut discovered = BTreeSet::new();
            loop {
                match node.next_event().await {
                    NetworkEvent::GroupPeersFound {
                        key: found_key,
                        providers,
                    } if found_key == key => {
                        for provider in providers {
                            if provider != node.peer_id() {
                                discovered.insert(provider);
                            }
                        }
                        if !discovered.is_empty() {
                            return PeerSearchResult {
                                status: "peersFound",
                                discovered_peers: discovered.len(),
                            };
                        }
                    }
                    NetworkEvent::GroupPeerSearchFinished { key: found_key }
                        if found_key == key =>
                    {
                        return PeerSearchResult {
                            status: "noPeers",
                            discovered_peers: 0,
                        };
                    }
                    NetworkEvent::DiscoveryFailed {
                        key: failed_key, ..
                    } if failed_key == key => {
                        return PeerSearchResult {
                            status: "unavailable",
                            discovered_peers: 0,
                        };
                    }
                    _ => {}
                }
            }
        })
        .await
        .map_err(|_| "network_search_timed_out")
    }
}

fn parse_bootstrap_peer(input: &str) -> Result<BootstrapPeer, &'static str> {
    let mut address: Multiaddr = input.parse().map_err(|_| "network_configuration_invalid")?;
    let Some(Protocol::P2p(peer_id)) = address.pop() else {
        return Err("network_configuration_invalid");
    };
    if address.is_empty() {
        return Err("network_configuration_invalid");
    }
    Ok(BootstrapPeer { peer_id, address })
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use charp2p_core::{
        DeviceIdentity, DiscoveryKey, GroupIdentity, HistoryPolicy, Invitation, InvitationSpec,
    };
    use charp2p_network::{NetworkEvent, NetworkNode};
    use tokio::time::timeout;

    use super::{parse_bootstrap_peer, NetworkService, PeerSearchResult};

    const NOW: u64 = 1_800_000_000;

    #[test]
    fn bootstrap_address_requires_a_peer_id() {
        assert!(parse_bootstrap_peer("/ip4/127.0.0.1/udp/9000/quic-v1").is_err());

        let peer_id = DeviceIdentity::generate().peer_id();
        let parsed =
            parse_bootstrap_peer(&format!("/ip4/127.0.0.1/udp/9000/quic-v1/p2p/{peer_id}"))
                .unwrap();
        assert_eq!(parsed.peer_id, peer_id);
        assert_eq!(
            parsed.address.to_string(),
            "/ip4/127.0.0.1/udp/9000/quic-v1"
        );
    }

    #[test]
    fn bootstrap_configuration_is_bounded() {
        let peer_id = DeviceIdentity::generate().peer_id();
        let entry = format!("/ip4/127.0.0.1/udp/9000/quic-v1/p2p/{peer_id}");
        let oversized = std::iter::repeat_n(entry, 17).collect::<Vec<_>>().join(";");

        assert!(NetworkService::from_sources(&[], &oversized).is_err());
    }

    #[test]
    fn search_reports_when_no_bootstrap_peer_is_configured() {
        let group = GroupIdentity::generate();
        let invitation = Invitation::issue(
            &group,
            InvitationSpec {
                group_name: "Design Crew",
                inviter_name: "Maya",
                expires_at_unix: NOW + 3_600,
                history_policy: HistoryPolicy::None,
                reusable: false,
            },
            NOW,
        )
        .unwrap();
        let result = tauri::async_runtime::block_on(
            NetworkService::from_sources(&[], "")
                .unwrap()
                .search(DeviceIdentity::generate(), &invitation),
        )
        .unwrap();

        assert_eq!(
            result,
            PeerSearchResult {
                status: "bootstrapRequired",
                discovered_peers: 0,
            }
        );
    }

    #[test]
    fn search_finds_a_provider_through_a_routing_node() {
        let group = GroupIdentity::generate();
        let invitation = Invitation::issue(
            &group,
            InvitationSpec {
                group_name: "Design Crew",
                inviter_name: "Maya",
                expires_at_unix: NOW + 3_600,
                history_policy: HistoryPolicy::None,
                reusable: false,
            },
            NOW,
        )
        .unwrap();
        let result = tauri::async_runtime::block_on(async {
            let mut routing =
                NetworkNode::new_routing(DeviceIdentity::generate().into_network_keypair());
            let routing_id = routing.peer_id();
            routing
                .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
                .unwrap();
            let address = loop {
                if let NetworkEvent::Listening { address } = routing.next_event().await {
                    break address;
                }
            };
            routing
                .announce_group(DiscoveryKey::from_invitation(&invitation))
                .unwrap();
            let service =
                NetworkService::from_sources(&[], &format!("{address}/p2p/{routing_id}")).unwrap();
            let search = service.search(DeviceIdentity::generate(), &invitation);
            tokio::pin!(search);

            timeout(Duration::from_secs(10), async {
                loop {
                    tokio::select! {
                        result = &mut search => break result,
                        _ = routing.next_event() => {}
                    }
                }
            })
            .await
            .expect("provider search should complete")
            .unwrap()
        });

        assert_eq!(result.status, "peersFound");
        assert_eq!(result.discovered_peers, 1);
    }
}
