use std::{
    collections::BTreeSet,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use charp2p_core::{DeviceIdentity, DiscoveryKey, Invitation, SyncRejectReason};
use charp2p_network::{NetworkEvent, NetworkNode};
use libp2p::{multiaddr::Protocol, Multiaddr, PeerId};
use serde::Serialize;
use tokio::{
    sync::Mutex,
    task::JoinHandle,
    time::{interval, interval_at, sleep, timeout, Instant, MissedTickBehavior},
};

const BUILT_IN_BOOTSTRAP_ADDRESSES: &[&str] = &[];
const BOOTSTRAP_ENVIRONMENT_VARIABLE: &str = "CHARP2P_BOOTSTRAP_NODES";
const MAX_BOOTSTRAP_PEERS: usize = 16;
const MAX_BOOTSTRAP_ADDRESS_BYTES: usize = 512;
const MAX_DISCOVERED_PEERS: usize = 32;
const PROVIDER_SEARCH_TIMEOUT: Duration = Duration::from_secs(8);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
const ADVERTISEMENT_REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);
const EXPIRY_CHECK_INTERVAL: Duration = Duration::from_secs(1);

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
    pub reachable_peers: usize,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdvertisementResult {
    pub status: &'static str,
    pub expires_at_unix: u64,
}

struct ActiveAdvertisement {
    key: DiscoveryKey,
    expires_at_unix: u64,
    task: JoinHandle<()>,
}

impl Drop for ActiveAdvertisement {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub struct NetworkService {
    bootstrap_peers: Vec<BootstrapPeer>,
    advertisement: Mutex<Option<ActiveAdvertisement>>,
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
        Ok(Self {
            bootstrap_peers,
            advertisement: Mutex::new(None),
        })
    }

    pub async fn advertise(
        &self,
        identity: DeviceIdentity,
        invitation: &Invitation,
    ) -> Result<AdvertisementResult, &'static str> {
        remaining_until_expiry(invitation.expires_at_unix())?;
        if self.bootstrap_peers.is_empty() {
            return Ok(AdvertisementResult {
                status: "bootstrapRequired",
                expires_at_unix: invitation.expires_at_unix(),
            });
        }

        let key = DiscoveryKey::from_invitation(invitation);
        let mut active = self.advertisement.lock().await;
        if let Some(existing) = active.as_ref() {
            if existing.key == key
                && existing.expires_at_unix == invitation.expires_at_unix()
                && !existing.task.is_finished()
            {
                return Ok(AdvertisementResult {
                    status: "advertising",
                    expires_at_unix: existing.expires_at_unix,
                });
            }
        }
        if let Some(existing) = active.take() {
            existing.task.abort();
        }

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
        node.announce_group(key)
            .map_err(|_| "network_unavailable")?;

        timeout(PROVIDER_SEARCH_TIMEOUT, async {
            loop {
                match node.next_event().await {
                    NetworkEvent::GroupAnnounced { key: announced } if announced == key => {
                        return Ok(());
                    }
                    NetworkEvent::DiscoveryFailed {
                        key: failed,
                        operation: charp2p_network::DiscoveryOperation::Announcement,
                    } if failed == key => return Err("network_unavailable"),
                    NetworkEvent::SyncRequestReceived { request_id, .. } => {
                        let _ =
                            node.reject_sync_request(request_id, SyncRejectReason::Unauthorized);
                    }
                    _ => {}
                }
            }
        })
        .await
        .map_err(|_| "network_advertisement_timed_out")??;

        remaining_until_expiry(invitation.expires_at_unix())?;

        let expires_at_unix = invitation.expires_at_unix();
        let task = tokio::spawn(async move {
            let mut refresh = interval_at(
                Instant::now() + ADVERTISEMENT_REFRESH_INTERVAL,
                ADVERTISEMENT_REFRESH_INTERVAL,
            );
            refresh.set_missed_tick_behavior(MissedTickBehavior::Skip);
            let mut expiry_check = interval(EXPIRY_CHECK_INTERVAL);
            expiry_check.set_missed_tick_behavior(MissedTickBehavior::Skip);
            while let Ok(remaining) = remaining_until_expiry(expires_at_unix) {
                tokio::select! {
                    _ = sleep(remaining) => {}
                    _ = expiry_check.tick() => {}
                    _ = refresh.tick() => {
                        if node.announce_group(key).is_err() {
                            break;
                        }
                    }
                    event = node.next_event() => {
                        match event {
                            NetworkEvent::DiscoveryFailed {
                                key: failed,
                                operation: charp2p_network::DiscoveryOperation::Announcement,
                            } if failed == key => break,
                            NetworkEvent::SyncRequestReceived { request_id, .. } => {
                                let _ = node.reject_sync_request(
                                    request_id,
                                    SyncRejectReason::Unauthorized,
                                );
                            }
                            _ => {}
                        }
                    }
                }
            }
        });
        *active = Some(ActiveAdvertisement {
            key,
            expires_at_unix: invitation.expires_at_unix(),
            task,
        });
        Ok(AdvertisementResult {
            status: "advertising",
            expires_at_unix: invitation.expires_at_unix(),
        })
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
                reachable_peers: 0,
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

        let discovery = timeout(PROVIDER_SEARCH_TIMEOUT, async {
            let mut discovered = BTreeSet::new();
            let mut connected = BTreeSet::new();
            loop {
                match node.next_event().await {
                    NetworkEvent::PeerConnected { peer_id } => {
                        connected.insert(peer_id);
                    }
                    NetworkEvent::GroupPeersFound {
                        key: found_key,
                        providers,
                    } if found_key == key => {
                        for provider in providers.into_iter().take(MAX_DISCOVERED_PEERS) {
                            if provider != node.peer_id() {
                                discovered.insert(provider);
                            }
                        }
                        if !discovered.is_empty() {
                            return Ok((discovered, connected));
                        }
                    }
                    NetworkEvent::GroupPeerSearchFinished { key: found_key }
                        if found_key == key =>
                    {
                        return Err(PeerSearchResult {
                            status: "noPeers",
                            discovered_peers: 0,
                            reachable_peers: 0,
                        });
                    }
                    NetworkEvent::DiscoveryFailed {
                        key: failed_key, ..
                    } if failed_key == key => {
                        return Err(PeerSearchResult {
                            status: "unavailable",
                            discovered_peers: 0,
                            reachable_peers: 0,
                        });
                    }
                    _ => {}
                }
            }
        })
        .await
        .map_err(|_| "network_search_timed_out")?;
        let (discovered, connected) = match discovery {
            Ok(found) => found,
            Err(result) => return Ok(result),
        };

        if discovered.iter().any(|peer| connected.contains(peer)) {
            return Ok(PeerSearchResult {
                status: "peerReachable",
                discovered_peers: discovered.len(),
                reachable_peers: 1,
            });
        }

        for peer_id in discovered.iter().copied() {
            let _ = node.dial_peer(peer_id);
        }
        let reachable = timeout(CONNECT_TIMEOUT, async {
            loop {
                if let NetworkEvent::PeerConnected { peer_id } = node.next_event().await {
                    if discovered.contains(&peer_id) {
                        return peer_id;
                    }
                }
            }
        })
        .await
        .is_ok();

        Ok(PeerSearchResult {
            status: if reachable {
                "peerReachable"
            } else {
                "peersFound"
            },
            discovered_peers: discovered.len(),
            reachable_peers: usize::from(reachable),
        })
    }
}

fn remaining_until_expiry(expires_at_unix: u64) -> Result<Duration, &'static str> {
    let expiry = UNIX_EPOCH
        .checked_add(Duration::from_secs(expires_at_unix))
        .ok_or("invitation_expired")?;
    expiry
        .duration_since(SystemTime::now())
        .map_err(|_| "invitation_expired")
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
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use charp2p_core::{
        DeviceIdentity, DiscoveryKey, GroupIdentity, HistoryPolicy, Invitation, InvitationSpec,
        SyncRejectReason, SyncRequest, SyncResponse,
    };
    use charp2p_network::{NetworkEvent, NetworkNode};
    use tokio::time::timeout;

    use super::{parse_bootstrap_peer, AdvertisementResult, NetworkService, PeerSearchResult};

    const NOW: u64 = 1_800_000_000;

    fn unix_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

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
                reachable_peers: 0,
            }
        );
    }

    #[test]
    fn advertise_reports_when_no_bootstrap_peer_is_configured() {
        let now = unix_now();
        let group = GroupIdentity::generate();
        let invitation = Invitation::issue(
            &group,
            InvitationSpec {
                group_name: "Design Crew",
                inviter_name: "Maya",
                expires_at_unix: now + 3_600,
                history_policy: HistoryPolicy::None,
                reusable: false,
            },
            now,
        )
        .unwrap();
        let result = tauri::async_runtime::block_on(
            NetworkService::from_sources(&[], "")
                .unwrap()
                .advertise(DeviceIdentity::generate(), &invitation),
        )
        .unwrap();

        assert_eq!(
            result,
            AdvertisementResult {
                status: "bootstrapRequired",
                expires_at_unix: now + 3_600,
            }
        );
    }

    #[test]
    fn advertise_rejects_an_expired_invitation() {
        let expires_at_unix = unix_now().saturating_sub(1);
        let group = GroupIdentity::generate();
        let invitation = Invitation::issue(
            &group,
            InvitationSpec {
                group_name: "Design Crew",
                inviter_name: "Maya",
                expires_at_unix,
                history_policy: HistoryPolicy::None,
                reusable: false,
            },
            expires_at_unix.saturating_sub(1),
        )
        .unwrap();
        let result = tauri::async_runtime::block_on(
            NetworkService::from_sources(&[], "")
                .unwrap()
                .advertise(DeviceIdentity::generate(), &invitation),
        );

        assert!(matches!(result, Err("invitation_expired")));
    }

    #[test]
    fn advertised_invitation_is_discoverable_through_a_routing_node() {
        let now = unix_now();
        let group = GroupIdentity::generate();
        let invitation = Invitation::issue(
            &group,
            InvitationSpec {
                group_name: "Design Crew",
                inviter_name: "Maya",
                expires_at_unix: now + 3_600,
                history_policy: HistoryPolicy::None,
                reusable: false,
            },
            now,
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
            let service =
                NetworkService::from_sources(&[], &format!("{address}/p2p/{routing_id}")).unwrap();
            let (_, advertiser_secret) = DeviceIdentity::generate_persistable().unwrap();
            let advertise = service.advertise(
                DeviceIdentity::from_persisted_secret(&advertiser_secret).unwrap(),
                &invitation,
            );
            tokio::pin!(advertise);
            let advertised = timeout(Duration::from_secs(10), async {
                loop {
                    tokio::select! {
                        result = &mut advertise => break result,
                        _ = routing.next_event() => {}
                    }
                }
            })
            .await
            .expect("advertisement should complete")
            .unwrap();
            assert_eq!(advertised.status, "advertising");
            let first_task_id = service
                .advertisement
                .lock()
                .await
                .as_ref()
                .expect("advertisement should be active")
                .task
                .id();
            let repeated = service
                .advertise(
                    DeviceIdentity::from_persisted_secret(&advertiser_secret).unwrap(),
                    &invitation,
                )
                .await
                .unwrap();
            let repeated_task_id = service
                .advertisement
                .lock()
                .await
                .as_ref()
                .expect("advertisement should remain active")
                .task
                .id();
            assert_eq!(repeated.status, "advertising");
            assert_eq!(repeated_task_id, first_task_id);

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

        assert_eq!(result.status, "peerReachable");
        assert_eq!(result.discovered_peers, 1);
        assert_eq!(result.reachable_peers, 1);
    }

    #[test]
    fn active_advertisement_stops_at_signed_expiry() {
        let now = unix_now();
        let group = GroupIdentity::generate();
        let invitation = Invitation::issue(
            &group,
            InvitationSpec {
                group_name: "Design Crew",
                inviter_name: "Maya",
                expires_at_unix: now + 3,
                history_policy: HistoryPolicy::None,
                reusable: false,
            },
            now,
        )
        .unwrap();
        tauri::async_runtime::block_on(async {
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
            let service =
                NetworkService::from_sources(&[], &format!("{address}/p2p/{routing_id}")).unwrap();
            let advertise = service.advertise(DeviceIdentity::generate(), &invitation);
            tokio::pin!(advertise);
            timeout(Duration::from_secs(2), async {
                loop {
                    tokio::select! {
                        result = &mut advertise => break result,
                        _ = routing.next_event() => {}
                    }
                }
            })
            .await
            .expect("advertisement should publish before expiry")
            .unwrap();
            assert!(!service
                .advertisement
                .lock()
                .await
                .as_ref()
                .expect("advertisement should be active")
                .task
                .is_finished());

            timeout(Duration::from_secs(4), async {
                loop {
                    if service
                        .advertisement
                        .lock()
                        .await
                        .as_ref()
                        .expect("advertisement should remain recorded")
                        .task
                        .is_finished()
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            })
            .await
            .expect("advertisement should stop at signed expiry");
            assert!(unix_now() >= invitation.expires_at_unix());
        });
    }

    #[test]
    fn advertisement_rejects_unauthorized_sync_requests() {
        let now = unix_now();
        let group = GroupIdentity::generate();
        let invitation = Invitation::issue(
            &group,
            InvitationSpec {
                group_name: "Design Crew",
                inviter_name: "Maya",
                expires_at_unix: now + 3_600,
                history_policy: HistoryPolicy::None,
                reusable: false,
            },
            now,
        )
        .unwrap();
        tauri::async_runtime::block_on(async {
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
            let bootstrap = format!("{address}/p2p/{routing_id}");
            let service = NetworkService::from_sources(&[], &bootstrap).unwrap();
            let owner = DeviceIdentity::generate();
            let owner_id = owner.peer_id();
            {
                let advertise = service.advertise(owner, &invitation);
                tokio::pin!(advertise);
                timeout(Duration::from_secs(10), async {
                    loop {
                        tokio::select! {
                            result = &mut advertise => break result,
                            _ = routing.next_event() => {}
                        }
                    }
                })
                .await
                .expect("advertisement should complete")
                .unwrap();
            }

            let mut requester = NetworkNode::new(DeviceIdentity::generate().into_network_keypair());
            requester
                .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
                .unwrap();
            requester.add_bootstrap_peer(routing_id, address);
            requester.bootstrap().unwrap();
            requester.find_group_peers(DiscoveryKey::from_invitation(&invitation));

            let response = timeout(Duration::from_secs(10), async {
                let mut request_sent = false;
                loop {
                    tokio::select! {
                        event = requester.next_event() => match event {
                            NetworkEvent::GroupPeersFound { providers, .. }
                                if providers.contains(&owner_id) && !request_sent =>
                            {
                                requester
                                    .send_sync_request(
                                        owner_id,
                                        SyncRequest::Summary {
                                            group_id: invitation.group_id(),
                                        },
                                    )
                                    .unwrap();
                                request_sent = true;
                            }
                            NetworkEvent::SyncResponseReceived {
                                peer_id,
                                response,
                                ..
                            } if peer_id == owner_id => break response,
                            _ => {}
                        },
                        _ = routing.next_event() => {}
                    }
                }
            })
            .await
            .expect("unauthorized sync request should receive a response");

            assert_eq!(
                response,
                SyncResponse::Rejected {
                    reason: SyncRejectReason::Unauthorized,
                }
            );
            let advertiser_task = service
                .advertisement
                .lock()
                .await
                .as_ref()
                .expect("advertisement should remain active")
                .task
                .abort_handle();
            drop(service);
            timeout(Duration::from_secs(1), async {
                while !advertiser_task.is_finished() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("dropping the service should stop its advertiser");
        });
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

        assert_eq!(result.status, "peerReachable");
        assert_eq!(result.discovered_peers, 1);
        assert_eq!(result.reachable_peers, 1);
    }
}
