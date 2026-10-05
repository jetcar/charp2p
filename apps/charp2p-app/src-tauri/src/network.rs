use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use charp2p_core::{
    DeviceIdentity, DiscoveryKey, Invitation, JoinRejectReason, JoinRequest, JoinResponse,
    SyncRejectReason, SyncRequest, SyncResponse,
};
use charp2p_mls::{validate_profile_key_package, ProfileKeyPackageError, ProfileProvider};
use charp2p_network::{ConnectionPath, NetworkEvent, NetworkNode};
use charp2p_sync::{PullSession, SessionProgress};
use libp2p::{multiaddr::Protocol, Multiaddr, PeerId};
use serde::Serialize;
use tokio::{
    sync::Mutex,
    task::JoinHandle,
    time::{interval, interval_at, timeout, Instant, MissedTickBehavior},
};

use crate::mls_storage::{MemberAdmissionError, MlsProviderService};

const BUILT_IN_BOOTSTRAP_ADDRESSES: &[&str] = &[];
const BOOTSTRAP_ENVIRONMENT_VARIABLE: &str = "CHARP2P_BOOTSTRAP_NODES";
const MAX_BOOTSTRAP_PEERS: usize = 16;
const MAX_BOOTSTRAP_ADDRESS_BYTES: usize = 512;
const MAX_DISCOVERED_PEERS: usize = 32;
const MAX_OWNER_DISCOVERY_KEYS: usize = crate::groups::MAX_ADVERTISED_DISCOVERY_KEYS;
const PROVIDER_SEARCH_TIMEOUT: Duration = Duration::from_secs(8);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
const JOIN_RESPONSE_TIMEOUT: Duration = Duration::from_secs(35);
const SYNC_RESPONSE_TIMEOUT: Duration = Duration::from_secs(35);
const MAX_SYNC_EXCHANGES: usize = 4_096;
const ADVERTISEMENT_REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);
const EXPIRY_CHECK_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JoinRequestAuthorization {
    Authorized,
    Unauthorized,
    Unavailable,
}

pub(crate) trait JoinRequestAuthorizer: Send + Sync {
    fn authorize_join_request(&self, request: &JoinRequest) -> JoinRequestAuthorization;
}

trait MemberAdmissionService: Send + Sync {
    fn admit_member(
        &self,
        group_id: PeerId,
        owner_identity: &DeviceIdentity,
        authenticated_peer: PeerId,
        encoded_key_package: &[u8],
    ) -> Result<JoinResponse, MemberAdmissionError>;
}

trait PendingJoinService: Send + Sync {
    fn prepare_join_request(
        &self,
        device_id: PeerId,
        invitation: &Invitation,
    ) -> Result<JoinRequest, &'static str>;

    fn complete_join(&self, group_id: PeerId, encoded_welcome: &[u8]) -> Result<(), &'static str>;
}

trait SynchronizationService: Send + Sync {
    fn answer_sync_request(
        &self,
        authenticated_peer: PeerId,
        request: &SyncRequest,
    ) -> SyncResponse;

    fn advance_pull_session(
        &self,
        session: &mut PullSession,
        response: &SyncResponse,
    ) -> Result<SessionProgress, &'static str>;

    fn next_push_request(
        &self,
        group_id: PeerId,
        author_id: PeerId,
        after_sequence: u64,
    ) -> Result<Option<(SyncRequest, u64)>, &'static str>;

    fn acknowledge_messages_shared(
        &self,
        group_id: PeerId,
        peer_id: PeerId,
        author_id: PeerId,
        sequence: u64,
    ) -> Result<(), &'static str>;
}

impl MemberAdmissionService for MlsProviderService {
    fn admit_member(
        &self,
        group_id: PeerId,
        owner_identity: &DeviceIdentity,
        authenticated_peer: PeerId,
        encoded_key_package: &[u8],
    ) -> Result<JoinResponse, MemberAdmissionError> {
        MlsProviderService::admit_member(
            self,
            group_id,
            owner_identity,
            authenticated_peer,
            encoded_key_package,
        )
    }
}

impl PendingJoinService for MlsProviderService {
    fn prepare_join_request(
        &self,
        device_id: PeerId,
        invitation: &Invitation,
    ) -> Result<JoinRequest, &'static str> {
        MlsProviderService::prepare_join_request(self, device_id, invitation)
    }

    fn complete_join(&self, group_id: PeerId, encoded_welcome: &[u8]) -> Result<(), &'static str> {
        MlsProviderService::complete_join(self, group_id, encoded_welcome)
    }
}

impl SynchronizationService for MlsProviderService {
    fn answer_sync_request(
        &self,
        authenticated_peer: PeerId,
        request: &SyncRequest,
    ) -> SyncResponse {
        MlsProviderService::answer_sync_request(self, authenticated_peer, request)
    }

    fn advance_pull_session(
        &self,
        session: &mut PullSession,
        response: &SyncResponse,
    ) -> Result<SessionProgress, &'static str> {
        MlsProviderService::advance_pull_session(self, session, response)
    }

    fn next_push_request(
        &self,
        group_id: PeerId,
        author_id: PeerId,
        after_sequence: u64,
    ) -> Result<Option<(SyncRequest, u64)>, &'static str> {
        MlsProviderService::next_push_request(self, group_id, author_id, after_sequence)
    }

    fn acknowledge_messages_shared(
        &self,
        group_id: PeerId,
        peer_id: PeerId,
        author_id: PeerId,
        sequence: u64,
    ) -> Result<(), &'static str> {
        MlsProviderService::acknowledge_messages_shared(
            self, group_id, peer_id, author_id, sequence,
        )
    }
}

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
    pub connection_type: Option<&'static str>,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AdvertisementResult {
    pub status: &'static str,
    pub expires_at_unix: u64,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct JoinGroupResult {
    pub status: &'static str,
    pub group_id: String,
    pub synchronized_events: usize,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SynchronizeGroupResult {
    pub status: &'static str,
    pub group_id: String,
    pub synchronized_events: usize,
    pub uploaded_events: usize,
    pub synchronized_at_unix: u64,
    pub connection_type: &'static str,
}

struct ActiveAdvertisement {
    keys: Vec<DiscoveryKey>,
    expires_at_unix: Option<u64>,
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
    join_authorizer: Arc<dyn JoinRequestAuthorizer>,
    member_admission: Arc<dyn MemberAdmissionService>,
    pending_join: Arc<dyn PendingJoinService>,
    synchronization: Arc<dyn SynchronizationService>,
}

impl NetworkService {
    pub fn from_environment(
        join_authorizer: Arc<dyn JoinRequestAuthorizer>,
        member_admission: Arc<MlsProviderService>,
    ) -> Result<Self, &'static str> {
        let environment = std::env::var(BOOTSTRAP_ENVIRONMENT_VARIABLE).unwrap_or_default();
        Self::from_sources_with_authorizer(
            BUILT_IN_BOOTSTRAP_ADDRESSES,
            &environment,
            join_authorizer,
            member_admission.clone(),
            member_admission.clone(),
            member_admission,
        )
    }

    #[cfg(test)]
    fn from_sources(built_in: &[&str], environment: &str) -> Result<Self, &'static str> {
        Self::from_sources_with_authorizer(
            built_in,
            environment,
            Arc::new(UnavailableJoinRequestAuthorizer),
            Arc::new(UnavailableMemberAdmissionService),
            Arc::new(UnavailablePendingJoinService),
            Arc::new(UnavailableSynchronizationService),
        )
    }

    fn from_sources_with_authorizer(
        built_in: &[&str],
        environment: &str,
        join_authorizer: Arc<dyn JoinRequestAuthorizer>,
        member_admission: Arc<dyn MemberAdmissionService>,
        pending_join: Arc<dyn PendingJoinService>,
        synchronization: Arc<dyn SynchronizationService>,
    ) -> Result<Self, &'static str> {
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
            join_authorizer,
            member_admission,
            pending_join,
            synchronization,
        })
    }

    #[cfg(test)]
    pub async fn advertise(
        &self,
        network_identity: DeviceIdentity,
        owner_identity: DeviceIdentity,
        invitation: &Invitation,
    ) -> Result<AdvertisementResult, &'static str> {
        if network_identity.peer_id() != invitation.inviter_device_id()
            || owner_identity.peer_id() != network_identity.peer_id()
        {
            return Err("invitation_inviter_mismatch");
        }
        remaining_until_expiry(invitation.expires_at_unix())?;
        self.advertise_keys(
            network_identity,
            owner_identity,
            vec![DiscoveryKey::from_invitation(invitation)],
            Some(invitation.expires_at_unix()),
        )
        .await
    }

    /// Advertises retained rendezvous keys of all owned groups for existing
    /// members without tying synchronization availability to bearer-invitation
    /// expiry.
    pub async fn advertise_owner_group(
        &self,
        network_identity: DeviceIdentity,
        owner_identity: DeviceIdentity,
        keys: Vec<DiscoveryKey>,
    ) -> Result<AdvertisementResult, &'static str> {
        if network_identity.peer_id() != owner_identity.peer_id() {
            return Err("invitation_inviter_mismatch");
        }
        if keys.is_empty() {
            return Ok(AdvertisementResult {
                status: "inactive",
                expires_at_unix: 0,
            });
        }
        self.advertise_keys(network_identity, owner_identity, keys, None)
            .await
    }

    async fn advertise_keys(
        &self,
        network_identity: DeviceIdentity,
        owner_identity: DeviceIdentity,
        mut keys: Vec<DiscoveryKey>,
        expires_at_unix: Option<u64>,
    ) -> Result<AdvertisementResult, &'static str> {
        keys.dedup();
        if keys.is_empty() {
            return Err("owner_discovery_key_missing");
        }
        if keys.len() > MAX_OWNER_DISCOVERY_KEYS {
            return Err("owner_discovery_record_invalid");
        }
        if let Some(expiry) = expires_at_unix {
            remaining_until_expiry(expiry)?;
        }
        let reported_expiry = expires_at_unix.unwrap_or(0);
        if self.bootstrap_peers.is_empty() {
            return Ok(AdvertisementResult {
                status: "bootstrapRequired",
                expires_at_unix: reported_expiry,
            });
        }

        let mut active = self.advertisement.lock().await;
        if let Some(existing) = active.as_ref() {
            if existing.keys == keys
                && existing.expires_at_unix == expires_at_unix
                && !existing.task.is_finished()
            {
                return Ok(AdvertisementResult {
                    status: "advertising",
                    expires_at_unix: existing.expires_at_unix.unwrap_or(0),
                });
            }
        }
        if let Some(existing) = active.take() {
            existing.task.abort();
        }

        let mut node = NetworkNode::new(network_identity.into_network_keypair());
        node.listen_on(
            "/ip4/0.0.0.0/udp/0/quic-v1"
                .parse()
                .map_err(|_| "network_configuration_invalid")?,
        )
        .map_err(|_| "network_unavailable")?;
        for bootstrap in &self.bootstrap_peers {
            node.add_bootstrap_peer(bootstrap.peer_id, bootstrap.address.clone());
            node.reserve_relay(bootstrap.peer_id, bootstrap.address.clone())
                .map_err(|_| "network_unavailable")?;
        }
        node.bootstrap().map_err(|_| "network_unavailable")?;
        for key in &keys {
            node.announce_group(*key)
                .map_err(|_| "network_unavailable")?;
        }

        timeout(PROVIDER_SEARCH_TIMEOUT, async {
            let mut pending = keys.clone();
            loop {
                match node.next_event().await {
                    NetworkEvent::GroupAnnounced { key: announced }
                        if pending.contains(&announced) =>
                    {
                        pending.retain(|key| *key != announced);
                        if pending.is_empty() {
                            return Ok(());
                        }
                    }
                    NetworkEvent::DiscoveryFailed {
                        key: failed,
                        operation: charp2p_network::DiscoveryOperation::Announcement,
                    } if keys.contains(&failed) => return Err("network_unavailable"),
                    NetworkEvent::SyncRequestReceived {
                        peer_id,
                        request_id,
                        request,
                    } => {
                        let response = self.synchronization.answer_sync_request(peer_id, &request);
                        let _ = node.send_sync_response(request_id, response);
                    }
                    NetworkEvent::JoinRequestReceived {
                        peer_id,
                        request_id,
                        request,
                    } => {
                        let response = join_response(
                            self.join_authorizer.authorize_join_request(&request),
                            self.member_admission.as_ref(),
                            &owner_identity,
                            &request,
                            peer_id,
                        );
                        let _ = node.send_join_response(request_id, response);
                    }
                    _ => {}
                }
            }
        })
        .await
        .map_err(|_| "network_advertisement_timed_out")??;

        if let Some(expiry) = expires_at_unix {
            remaining_until_expiry(expiry)?;
        }

        let join_authorizer = Arc::clone(&self.join_authorizer);
        let member_admission = Arc::clone(&self.member_admission);
        let synchronization = Arc::clone(&self.synchronization);
        let task_keys = keys.clone();
        let task = tokio::spawn(async move {
            let mut refresh = interval_at(
                Instant::now() + ADVERTISEMENT_REFRESH_INTERVAL,
                ADVERTISEMENT_REFRESH_INTERVAL,
            );
            refresh.set_missed_tick_behavior(MissedTickBehavior::Skip);
            let mut expiry_check = interval(EXPIRY_CHECK_INTERVAL);
            expiry_check.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                if expires_at_unix.is_some_and(|expiry| remaining_until_expiry(expiry).is_err()) {
                    break;
                }
                tokio::select! {
                    _ = expiry_check.tick() => {}
                    _ = refresh.tick() => {
                        if task_keys.iter().any(|key| node.announce_group(*key).is_err()) {
                            break;
                        }
                    }
                    event = node.next_event() => {
                        match event {
                            NetworkEvent::DiscoveryFailed {
                                key: failed,
                                operation: charp2p_network::DiscoveryOperation::Announcement,
                            } if task_keys.contains(&failed) => break,
                            NetworkEvent::SyncRequestReceived {
                                peer_id,
                                request_id,
                                request,
                            } => {
                                let response = synchronization
                                    .answer_sync_request(peer_id, &request);
                                let _ = node.send_sync_response(request_id, response);
                            }
                            NetworkEvent::JoinRequestReceived {
                                peer_id,
                                request_id,
                                request,
                            } => {
                                let response = join_response(
                                    join_authorizer.authorize_join_request(&request),
                                    member_admission.as_ref(),
                                    &owner_identity,
                                    &request,
                                    peer_id,
                                );
                                let _ = node.send_join_response(request_id, response);
                            }
                            _ => {}
                        }
                    }
                }
            }
        });
        *active = Some(ActiveAdvertisement {
            keys,
            expires_at_unix,
            task,
        });
        Ok(AdvertisementResult {
            status: "advertising",
            expires_at_unix: reported_expiry,
        })
    }

    /// Stops the local provider and request listener for the active invitation.
    #[cfg(test)]
    pub async fn stop_advertising(&self) {
        self.advertisement.lock().await.take();
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
                connection_type: None,
            });
        }

        let key = DiscoveryKey::from_invitation(invitation);
        let expected_inviter = invitation.inviter_device_id();
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
            let mut connected = BTreeMap::new();
            loop {
                match node.next_event().await {
                    NetworkEvent::PeerConnected { peer_id, path } => {
                        connected.insert(peer_id, path);
                    }
                    NetworkEvent::GroupPeersFound {
                        key: found_key,
                        providers,
                    } if found_key == key => {
                        for provider in providers.into_iter().take(MAX_DISCOVERED_PEERS) {
                            if provider == expected_inviter && provider != node.peer_id() {
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
                            connection_type: None,
                        });
                    }
                    NetworkEvent::DiscoveryFailed {
                        key: failed_key, ..
                    } if failed_key == key => {
                        return Err(PeerSearchResult {
                            status: "unavailable",
                            discovered_peers: 0,
                            reachable_peers: 0,
                            connection_type: None,
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

        if let Some(path) = discovered.iter().find_map(|peer| connected.get(peer)) {
            return Ok(PeerSearchResult {
                status: "peerReachable",
                discovered_peers: discovered.len(),
                reachable_peers: 1,
                connection_type: Some(connection_type_name(*path)),
            });
        }

        for peer_id in discovered.iter().copied() {
            let _ = node.dial_peer(peer_id);
        }
        let reachable = timeout(CONNECT_TIMEOUT, async {
            loop {
                if let NetworkEvent::PeerConnected { peer_id, path } = node.next_event().await {
                    if discovered.contains(&peer_id) {
                        return path;
                    }
                }
            }
        })
        .await
        .ok();

        Ok(PeerSearchResult {
            status: if reachable.is_some() {
                "peerReachable"
            } else {
                "peersFound"
            },
            discovered_peers: discovered.len(),
            reachable_peers: usize::from(reachable.is_some()),
            connection_type: reachable.map(connection_type_name),
        })
    }

    pub async fn join(
        &self,
        identity: DeviceIdentity,
        invitation: &Invitation,
    ) -> Result<JoinGroupResult, &'static str> {
        if self.bootstrap_peers.is_empty() {
            return Err("network_bootstrap_required");
        }
        let local_peer = identity.peer_id();
        let expected_inviter = invitation.inviter_device_id();
        if expected_inviter == local_peer {
            return Err("invitation_inviter_mismatch");
        }
        let request = self
            .pending_join
            .prepare_join_request(local_peer, invitation)?;
        let key = DiscoveryKey::from_invitation(invitation);
        let (mut node, _) = self
            .connect_to_group_provider(identity, key, expected_inviter)
            .await?;

        let request_id = node.send_join_request(expected_inviter, request);
        let response = timeout(JOIN_RESPONSE_TIMEOUT, async {
            loop {
                match node.next_event().await {
                    NetworkEvent::JoinResponseReceived {
                        peer_id,
                        request_id: received_id,
                        response,
                    } if peer_id == expected_inviter && received_id == request_id => {
                        return Ok(response);
                    }
                    NetworkEvent::JoinRequestFailed {
                        peer_id,
                        request_id: failed_id,
                        ..
                    } if peer_id == expected_inviter && failed_id == request_id => {
                        return Err("network_join_failed");
                    }
                    _ => {}
                }
            }
        })
        .await
        .map_err(|_| "network_join_timed_out")??;
        if let Some(reason) = response.rejection() {
            return Err(match reason {
                JoinRejectReason::Unauthorized => "join_unauthorized",
                JoinRejectReason::Busy => "join_busy",
                JoinRejectReason::UnsupportedProfile => "join_unsupported_profile",
            });
        }
        let welcome = response.welcome().ok_or("network_join_failed")?;
        self.pending_join
            .complete_join(invitation.group_id(), welcome)?;
        let synchronized_events = self
            .pull_from_connected_peer(&mut node, expected_inviter, invitation.group_id())
            .await
            .unwrap_or(0);
        Ok(JoinGroupResult {
            status: "joined",
            group_id: invitation.group_id().to_string(),
            synchronized_events,
        })
    }

    pub async fn synchronize(
        &self,
        identity: DeviceIdentity,
        key: DiscoveryKey,
        group_id: PeerId,
        expected_peer: PeerId,
    ) -> Result<SynchronizeGroupResult, &'static str> {
        let local_peer = identity.peer_id();
        if local_peer == expected_peer {
            return Err("synchronization_peer_invalid");
        }
        let (mut node, connection_path) = self
            .connect_to_group_provider(identity, key, expected_peer)
            .await?;
        let synchronized_events = self
            .pull_from_connected_peer(&mut node, expected_peer, group_id)
            .await?;
        let uploaded_events = self
            .push_to_connected_peer(&mut node, expected_peer, group_id, local_peer)
            .await?;
        Ok(SynchronizeGroupResult {
            status: "synchronized",
            group_id: group_id.to_string(),
            synchronized_events,
            uploaded_events,
            synchronized_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| "system_clock_invalid")?
                .as_secs(),
            connection_type: connection_type_name(connection_path),
        })
    }

    async fn connect_to_group_provider(
        &self,
        identity: DeviceIdentity,
        key: DiscoveryKey,
        expected_peer: PeerId,
    ) -> Result<(NetworkNode, ConnectionPath), &'static str> {
        if self.bootstrap_peers.is_empty() {
            return Err("network_bootstrap_required");
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
        node.find_group_peers(key);

        let already_connected = timeout(PROVIDER_SEARCH_TIMEOUT, async {
            let mut connected = None;
            loop {
                match node.next_event().await {
                    NetworkEvent::PeerConnected { peer_id, path } if peer_id == expected_peer => {
                        connected = Some(path);
                    }
                    NetworkEvent::GroupPeersFound {
                        key: found_key,
                        providers,
                    } if found_key == key && providers.contains(&expected_peer) => {
                        return Ok(connected);
                    }
                    NetworkEvent::GroupPeerSearchFinished { key: found_key }
                        if found_key == key =>
                    {
                        return Err("network_peer_not_found");
                    }
                    NetworkEvent::DiscoveryFailed {
                        key: failed_key, ..
                    } if failed_key == key => return Err("network_unavailable"),
                    _ => {}
                }
            }
        })
        .await
        .map_err(|_| "network_search_timed_out")??;

        let connection_path = if let Some(path) = already_connected {
            path
        } else {
            node.dial_peer(expected_peer)
                .map_err(|_| "network_peer_unreachable")?;
            timeout(CONNECT_TIMEOUT, async {
                loop {
                    if let NetworkEvent::PeerConnected { peer_id, path } = node.next_event().await {
                        if peer_id == expected_peer {
                            break path;
                        }
                    }
                }
            })
            .await
            .map_err(|_| "network_peer_unreachable")?
        };
        Ok((node, connection_path))
    }

    async fn pull_from_connected_peer(
        &self,
        node: &mut NetworkNode,
        peer_id: PeerId,
        group_id: PeerId,
    ) -> Result<usize, &'static str> {
        let (mut session, mut request) = PullSession::start(group_id);
        let mut inserted = 0_usize;
        for _ in 0..MAX_SYNC_EXCHANGES {
            let request_id = node
                .send_sync_request(peer_id, request)
                .map_err(|_| "synchronization_failed")?;
            let response = timeout(SYNC_RESPONSE_TIMEOUT, async {
                loop {
                    match node.next_event().await {
                        NetworkEvent::SyncResponseReceived {
                            peer_id: response_peer,
                            request_id: response_id,
                            response,
                        } if response_peer == peer_id && response_id == request_id => {
                            return Ok(response);
                        }
                        NetworkEvent::SyncRequestFailed {
                            peer_id: failed_peer,
                            request_id: failed_id,
                            ..
                        } if failed_peer == peer_id && failed_id == request_id => {
                            return Err("synchronization_failed");
                        }
                        _ => {}
                    }
                }
            })
            .await
            .map_err(|_| "synchronization_timed_out")??;
            if let SyncResponse::Rejected { reason } = response {
                return Err(match reason {
                    SyncRejectReason::Unauthorized => "synchronization_unauthorized",
                    SyncRejectReason::InvalidRequest => "synchronization_failed",
                    SyncRejectReason::Busy => "synchronization_busy",
                });
            }
            let progress = self
                .synchronization
                .advance_pull_session(&mut session, &response)?;
            inserted = inserted.saturating_add(progress.applied.inserted);
            if progress.complete {
                return Ok(inserted);
            }
            request = progress.next_request.ok_or("synchronization_failed")?;
        }
        Err("synchronization_limit_exceeded")
    }

    async fn push_to_connected_peer(
        &self,
        node: &mut NetworkNode,
        peer_id: PeerId,
        group_id: PeerId,
        author_id: PeerId,
    ) -> Result<usize, &'static str> {
        let mut after_sequence = 0_u64;
        let mut inserted = 0_usize;
        for _ in 0..MAX_SYNC_EXCHANGES {
            let Some((request, last_sequence)) =
                self.synchronization
                    .next_push_request(group_id, author_id, after_sequence)?
            else {
                self.synchronization.acknowledge_messages_shared(
                    group_id,
                    peer_id,
                    author_id,
                    after_sequence,
                )?;
                return Ok(inserted);
            };
            if last_sequence <= after_sequence {
                return Err("synchronization_failed");
            }
            let request_id = node
                .send_sync_request(peer_id, request)
                .map_err(|_| "synchronization_failed")?;
            let response = timeout(SYNC_RESPONSE_TIMEOUT, async {
                loop {
                    match node.next_event().await {
                        NetworkEvent::SyncResponseReceived {
                            peer_id: response_peer,
                            request_id: response_id,
                            response,
                        } if response_peer == peer_id && response_id == request_id => {
                            return Ok(response);
                        }
                        NetworkEvent::SyncRequestFailed {
                            peer_id: failed_peer,
                            request_id: failed_id,
                            ..
                        } if failed_peer == peer_id && failed_id == request_id => {
                            return Err("synchronization_failed");
                        }
                        _ => {}
                    }
                }
            })
            .await
            .map_err(|_| "synchronization_timed_out")??;
            match response {
                SyncResponse::EventsAccepted {
                    group_id: response_group,
                    inserted: accepted,
                } if response_group == group_id => {
                    inserted = inserted.saturating_add(usize::from(accepted));
                    after_sequence = last_sequence;
                }
                SyncResponse::Rejected { reason } => {
                    return Err(match reason {
                        SyncRejectReason::Unauthorized => "synchronization_unauthorized",
                        SyncRejectReason::InvalidRequest => "synchronization_failed",
                        SyncRejectReason::Busy => "synchronization_busy",
                    });
                }
                _ => return Err("synchronization_failed"),
            }
        }
        Err("synchronization_limit_exceeded")
    }
}

fn join_response(
    authorization: JoinRequestAuthorization,
    member_admission: &dyn MemberAdmissionService,
    owner_identity: &DeviceIdentity,
    request: &JoinRequest,
    authenticated_peer: PeerId,
) -> JoinResponse {
    match authorization {
        JoinRequestAuthorization::Unauthorized => {
            JoinResponse::rejected(JoinRejectReason::Unauthorized)
        }
        JoinRequestAuthorization::Unavailable => JoinResponse::rejected(JoinRejectReason::Busy),
        JoinRequestAuthorization::Authorized => match validate_profile_key_package(
            &ProfileProvider::default(),
            request.key_package(),
            authenticated_peer,
        ) {
            Ok(_) => match member_admission.admit_member(
                request.group_id(),
                owner_identity,
                authenticated_peer,
                request.key_package(),
            ) {
                Ok(response) => response,
                Err(MemberAdmissionError::Unauthorized) => {
                    JoinResponse::rejected(JoinRejectReason::Unauthorized)
                }
                Err(MemberAdmissionError::UnsupportedProfile) => {
                    JoinResponse::rejected(JoinRejectReason::UnsupportedProfile)
                }
                Err(MemberAdmissionError::Unavailable) => {
                    JoinResponse::rejected(JoinRejectReason::Busy)
                }
            },
            Err(
                ProfileKeyPackageError::UnsupportedCiphersuite
                | ProfileKeyPackageError::UnsupportedCapabilities,
            ) => JoinResponse::rejected(JoinRejectReason::UnsupportedProfile),
            Err(_) => JoinResponse::rejected(JoinRejectReason::Unauthorized),
        },
    }
}

#[cfg(test)]
struct UnavailableJoinRequestAuthorizer;

#[cfg(test)]
impl JoinRequestAuthorizer for UnavailableJoinRequestAuthorizer {
    fn authorize_join_request(&self, _request: &JoinRequest) -> JoinRequestAuthorization {
        JoinRequestAuthorization::Unavailable
    }
}

#[cfg(test)]
struct UnavailableMemberAdmissionService;

#[cfg(test)]
impl MemberAdmissionService for UnavailableMemberAdmissionService {
    fn admit_member(
        &self,
        _group_id: PeerId,
        _owner_identity: &DeviceIdentity,
        _authenticated_peer: PeerId,
        _encoded_key_package: &[u8],
    ) -> Result<JoinResponse, MemberAdmissionError> {
        Err(MemberAdmissionError::Unavailable)
    }
}

#[cfg(test)]
struct UnavailablePendingJoinService;

#[cfg(test)]
impl PendingJoinService for UnavailablePendingJoinService {
    fn prepare_join_request(
        &self,
        _device_id: PeerId,
        _invitation: &Invitation,
    ) -> Result<JoinRequest, &'static str> {
        Err("mls_provider_service_unavailable")
    }

    fn complete_join(
        &self,
        _group_id: PeerId,
        _encoded_welcome: &[u8],
    ) -> Result<(), &'static str> {
        Err("mls_provider_service_unavailable")
    }
}

#[cfg(test)]
struct UnavailableSynchronizationService;

#[cfg(test)]
impl SynchronizationService for UnavailableSynchronizationService {
    fn answer_sync_request(
        &self,
        _authenticated_peer: PeerId,
        _request: &SyncRequest,
    ) -> SyncResponse {
        SyncResponse::Rejected {
            reason: charp2p_core::SyncRejectReason::Unauthorized,
        }
    }

    fn advance_pull_session(
        &self,
        _session: &mut PullSession,
        _response: &SyncResponse,
    ) -> Result<SessionProgress, &'static str> {
        Err("synchronization_unavailable")
    }

    fn next_push_request(
        &self,
        _group_id: PeerId,
        _author_id: PeerId,
        _after_sequence: u64,
    ) -> Result<Option<(SyncRequest, u64)>, &'static str> {
        Err("synchronization_unavailable")
    }

    fn acknowledge_messages_shared(
        &self,
        _group_id: PeerId,
        _peer_id: PeerId,
        _author_id: PeerId,
        _sequence: u64,
    ) -> Result<(), &'static str> {
        Err("synchronization_unavailable")
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

fn connection_type_name(path: ConnectionPath) -> &'static str {
    match path {
        ConnectionPath::Direct => "direct",
        ConnectionPath::Lan => "lan",
        ConnectionPath::Relayed => "relayed",
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
    use std::{
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use charp2p_core::{
        DeviceIdentity, DiscoveryKey, GroupIdentity, HistoryPolicy, Invitation, InvitationSpec,
        JoinRejectReason, JoinRequest, JoinResponse, PeerId, SyncRejectReason, SyncRequest,
        SyncResponse,
    };
    use charp2p_mls::{
        device_credential, prepare_profile_key_package, ProfileProvider, CIPHERSUITE,
    };
    use charp2p_network::{NetworkEvent, NetworkNode};
    use openmls::prelude::{tls_codec::Serialize, CredentialWithKey, KeyPackage, OpenMlsProvider};
    use openmls_basic_credential::SignatureKeyPair;
    use tokio::time::timeout;

    use super::{
        join_response, parse_bootstrap_peer, AdvertisementResult, JoinRequestAuthorization,
        JoinRequestAuthorizer, MemberAdmissionService, NetworkService, PeerSearchResult,
        PendingJoinService, PullSession, SessionProgress, SynchronizationService,
        UnavailableJoinRequestAuthorizer, UnavailableMemberAdmissionService,
        UnavailablePendingJoinService,
    };
    use crate::mls_storage::MemberAdmissionError;

    const NOW: u64 = 1_800_000_000;

    struct StaticJoinRequestAuthorizer(JoinRequestAuthorization);

    impl JoinRequestAuthorizer for StaticJoinRequestAuthorizer {
        fn authorize_join_request(&self, _request: &JoinRequest) -> JoinRequestAuthorization {
            self.0
        }
    }

    struct AcceptingMemberAdmissionService;

    impl MemberAdmissionService for AcceptingMemberAdmissionService {
        fn admit_member(
            &self,
            _group_id: PeerId,
            _owner_identity: &DeviceIdentity,
            _authenticated_peer: PeerId,
            _encoded_key_package: &[u8],
        ) -> Result<JoinResponse, MemberAdmissionError> {
            JoinResponse::accepted(vec![4, 5, 6]).map_err(|_| MemberAdmissionError::Unavailable)
        }
    }

    struct MemberSynchronizationService {
        expected_peer: PeerId,
        group_id: PeerId,
    }

    impl SynchronizationService for MemberSynchronizationService {
        fn answer_sync_request(
            &self,
            authenticated_peer: PeerId,
            request: &SyncRequest,
        ) -> SyncResponse {
            if authenticated_peer == self.expected_peer
                && matches!(
                    request,
                    SyncRequest::Summary { group_id } if *group_id == self.group_id
                )
            {
                SyncResponse::Summary {
                    group_id: self.group_id,
                    heads: Vec::new(),
                }
            } else {
                SyncResponse::Rejected {
                    reason: SyncRejectReason::Unauthorized,
                }
            }
        }

        fn advance_pull_session(
            &self,
            _session: &mut PullSession,
            _response: &SyncResponse,
        ) -> Result<SessionProgress, &'static str> {
            Ok(SessionProgress {
                next_request: None,
                applied: charp2p_sync::ApplyOutcome {
                    inserted: 3,
                    already_present: 0,
                },
                complete: true,
            })
        }

        fn next_push_request(
            &self,
            _group_id: PeerId,
            _author_id: PeerId,
            _after_sequence: u64,
        ) -> Result<Option<(SyncRequest, u64)>, &'static str> {
            Ok(None)
        }

        fn acknowledge_messages_shared(
            &self,
            _group_id: PeerId,
            _peer_id: PeerId,
            _author_id: PeerId,
            _sequence: u64,
        ) -> Result<(), &'static str> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingPendingJoinService {
        completed: AtomicBool,
    }

    impl PendingJoinService for RecordingPendingJoinService {
        fn prepare_join_request(
            &self,
            device_id: PeerId,
            invitation: &Invitation,
        ) -> Result<JoinRequest, &'static str> {
            let provider = ProfileProvider::default();
            let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
                .map_err(|_| "test_key_package_failed")?;
            signer
                .store(provider.storage())
                .map_err(|_| "test_key_package_failed")?;
            let credential = CredentialWithKey {
                credential: device_credential(device_id).into(),
                signature_key: signer.public().into(),
            };
            prepare_profile_key_package(&provider, &signer, credential, device_id)
                .map_err(|_| "test_key_package_failed")?
                .into_join_request(invitation)
                .map_err(|_| "test_key_package_failed")
        }

        fn complete_join(
            &self,
            _group_id: PeerId,
            encoded_welcome: &[u8],
        ) -> Result<(), &'static str> {
            if encoded_welcome != [4, 5, 6] {
                return Err("unexpected_test_welcome");
            }
            self.completed.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    fn unix_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn identity_pair() -> (DeviceIdentity, DeviceIdentity) {
        let (_, secret) = DeviceIdentity::generate_persistable().unwrap();
        (
            DeviceIdentity::from_persisted_secret(&secret).unwrap(),
            DeviceIdentity::from_persisted_secret(&secret).unwrap(),
        )
    }

    fn profile_join_request(device_id: PeerId) -> JoinRequest {
        let provider = ProfileProvider::default();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).unwrap();
        signer.store(provider.storage()).unwrap();
        let credential = CredentialWithKey {
            credential: device_credential(device_id).into(),
            signature_key: signer.public().into(),
        };
        let prepared =
            prepare_profile_key_package(&provider, &signer, credential, device_id).unwrap();
        prepared.into_join_request(&join_invitation()).unwrap()
    }

    fn unsupported_profile_join_request(device_id: PeerId) -> JoinRequest {
        let provider = ProfileProvider::default();
        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm()).unwrap();
        signer.store(provider.storage()).unwrap();
        let credential = CredentialWithKey {
            credential: device_credential(device_id).into(),
            signature_key: signer.public().into(),
        };
        let key_package = KeyPackage::builder()
            .build(CIPHERSUITE, &provider, &signer, credential)
            .unwrap();
        let encoded = key_package.key_package().tls_serialize_detached().unwrap();
        JoinRequest::from_invitation(&join_invitation(), encoded).unwrap()
    }

    fn join_invitation() -> Invitation {
        let group = GroupIdentity::generate();
        Invitation::issue(
            &group,
            DeviceIdentity::generate().peer_id(),
            InvitationSpec {
                group_name: "Design Crew",
                inviter_name: "Maya",
                expires_at_unix: NOW + 3_600,
                history_policy: HistoryPolicy::None,
                reusable: false,
            },
            NOW,
        )
        .unwrap()
    }

    #[test]
    fn join_authorization_uses_stable_public_rejections() {
        let peer_id = DeviceIdentity::generate().peer_id();
        let owner = DeviceIdentity::generate();
        let admission = UnavailableMemberAdmissionService;
        let request = profile_join_request(peer_id);
        assert_eq!(
            join_response(
                JoinRequestAuthorization::Authorized,
                &admission,
                &owner,
                &request,
                peer_id,
            )
            .rejection(),
            Some(JoinRejectReason::Busy)
        );
        assert_eq!(
            join_response(
                JoinRequestAuthorization::Unauthorized,
                &admission,
                &owner,
                &request,
                peer_id,
            )
            .rejection(),
            Some(JoinRejectReason::Unauthorized)
        );
        assert_eq!(
            join_response(
                JoinRequestAuthorization::Unavailable,
                &admission,
                &owner,
                &request,
                peer_id,
            )
            .rejection(),
            Some(JoinRejectReason::Busy)
        );
        assert_eq!(
            join_response(
                JoinRequestAuthorization::Authorized,
                &admission,
                &owner,
                &request,
                DeviceIdentity::generate().peer_id(),
            )
            .rejection(),
            Some(JoinRejectReason::Unauthorized)
        );
        let unsupported = unsupported_profile_join_request(peer_id);
        assert_eq!(
            join_response(
                JoinRequestAuthorization::Authorized,
                &admission,
                &owner,
                &unsupported,
                peer_id,
            )
            .rejection(),
            Some(JoinRejectReason::UnsupportedProfile)
        );

        let accepted = join_response(
            JoinRequestAuthorization::Authorized,
            &AcceptingMemberAdmissionService,
            &owner,
            &request,
            peer_id,
        );
        assert_eq!(accepted.welcome(), Some([4, 5, 6].as_slice()));
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
            DeviceIdentity::generate().peer_id(),
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
                connection_type: None,
            }
        );
    }

    #[test]
    fn join_requires_a_bootstrap_peer_before_preparing_mls_state() {
        let invitation = Invitation::issue(
            &GroupIdentity::generate(),
            DeviceIdentity::generate().peer_id(),
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
                .join(DeviceIdentity::generate(), &invitation),
        );

        assert!(matches!(result, Err("network_bootstrap_required")));
    }

    #[test]
    fn join_discovers_the_pinned_owner_and_completes_the_exchange() {
        let now = unix_now();
        let group = GroupIdentity::generate();
        let (owner, owner_signer) = identity_pair();
        let owner_id = owner.peer_id();
        let invitation = Invitation::issue(
            &group,
            owner_id,
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
            let joiner_identity = DeviceIdentity::generate();
            let joiner_id = joiner_identity.peer_id();
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
            let owner_service = NetworkService::from_sources_with_authorizer(
                &[],
                &bootstrap,
                Arc::new(StaticJoinRequestAuthorizer(
                    JoinRequestAuthorization::Authorized,
                )),
                Arc::new(AcceptingMemberAdmissionService),
                Arc::new(UnavailablePendingJoinService),
                Arc::new(MemberSynchronizationService {
                    expected_peer: joiner_id,
                    group_id: invitation.group_id(),
                }),
            )
            .unwrap();
            let advertise = owner_service.advertise(owner, owner_signer, &invitation);
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

            let pending_join = Arc::new(RecordingPendingJoinService::default());
            let joiner_service = NetworkService::from_sources_with_authorizer(
                &[],
                &bootstrap,
                Arc::new(UnavailableJoinRequestAuthorizer),
                Arc::new(UnavailableMemberAdmissionService),
                pending_join.clone(),
                Arc::new(MemberSynchronizationService {
                    expected_peer: owner_id,
                    group_id: invitation.group_id(),
                }),
            )
            .unwrap();
            let join = joiner_service.join(joiner_identity, &invitation);
            tokio::pin!(join);
            let result = timeout(Duration::from_secs(15), async {
                loop {
                    tokio::select! {
                        result = &mut join => break result,
                        _ = routing.next_event() => {}
                    }
                }
            })
            .await
            .expect("join exchange should complete")
            .unwrap();

            assert_eq!(result.status, "joined");
            assert_eq!(result.group_id, invitation.group_id().to_string());
            assert_eq!(result.synchronized_events, 3);
            assert!(pending_join.completed.load(Ordering::SeqCst));
        });
    }

    #[test]
    fn joined_member_rediscovers_the_owner_and_synchronizes() {
        let now = unix_now();
        let group = GroupIdentity::generate();
        let (owner, owner_signer) = identity_pair();
        let owner_id = owner.peer_id();
        let invitation = Invitation::issue(
            &group,
            owner_id,
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
        let discovery_key = DiscoveryKey::from_invitation(&invitation);

        tauri::async_runtime::block_on(async {
            let member_identity = DeviceIdentity::generate();
            let member_id = member_identity.peer_id();
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
            let owner_service = NetworkService::from_sources_with_authorizer(
                &[],
                &bootstrap,
                Arc::new(UnavailableJoinRequestAuthorizer),
                Arc::new(UnavailableMemberAdmissionService),
                Arc::new(UnavailablePendingJoinService),
                Arc::new(MemberSynchronizationService {
                    expected_peer: member_id,
                    group_id: invitation.group_id(),
                }),
            )
            .unwrap();
            let advertise = owner_service.advertise(owner, owner_signer, &invitation);
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

            let member_service = NetworkService::from_sources_with_authorizer(
                &[],
                &bootstrap,
                Arc::new(UnavailableJoinRequestAuthorizer),
                Arc::new(UnavailableMemberAdmissionService),
                Arc::new(UnavailablePendingJoinService),
                Arc::new(MemberSynchronizationService {
                    expected_peer: owner_id,
                    group_id: invitation.group_id(),
                }),
            )
            .unwrap();
            let synchronize = member_service.synchronize(
                member_identity,
                discovery_key,
                invitation.group_id(),
                owner_id,
            );
            tokio::pin!(synchronize);
            let result = timeout(Duration::from_secs(15), async {
                loop {
                    tokio::select! {
                        result = &mut synchronize => break result,
                        _ = routing.next_event() => {}
                    }
                }
            })
            .await
            .expect("synchronization should complete")
            .unwrap();

            assert_eq!(result.status, "synchronized");
            assert_eq!(result.group_id, invitation.group_id().to_string());
            assert_eq!(result.synchronized_events, 3);
            assert_eq!(result.uploaded_events, 0);
            assert!(result.synchronized_at_unix >= now);
            assert_eq!(result.connection_type, "lan");
        });
    }

    #[test]
    fn advertise_reports_when_no_bootstrap_peer_is_configured() {
        let now = unix_now();
        let group = GroupIdentity::generate();
        let (owner, owner_signer) = identity_pair();
        let invitation = Invitation::issue(
            &group,
            owner.peer_id(),
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
            NetworkService::from_sources(&[], "").unwrap().advertise(
                owner,
                owner_signer,
                &invitation,
            ),
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
    fn advertise_rejects_a_device_not_authorized_by_the_invitation() {
        let now = unix_now();
        let invitation = Invitation::issue(
            &GroupIdentity::generate(),
            DeviceIdentity::generate().peer_id(),
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
            NetworkService::from_sources(&[], "").unwrap().advertise(
                DeviceIdentity::generate(),
                DeviceIdentity::generate(),
                &invitation,
            ),
        );

        assert!(matches!(result, Err("invitation_inviter_mismatch")));
    }

    #[test]
    fn advertise_rejects_an_expired_invitation() {
        let expires_at_unix = unix_now().saturating_sub(1);
        let group = GroupIdentity::generate();
        let (owner, owner_signer) = identity_pair();
        let invitation = Invitation::issue(
            &group,
            owner.peer_id(),
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
            NetworkService::from_sources(&[], "").unwrap().advertise(
                owner,
                owner_signer,
                &invitation,
            ),
        );

        assert!(matches!(result, Err("invitation_expired")));
    }

    #[test]
    fn advertised_invitation_is_discoverable_through_a_routing_node() {
        let now = unix_now();
        let group = GroupIdentity::generate();
        let (_, advertiser_secret) = DeviceIdentity::generate_persistable().unwrap();
        let advertiser_id = DeviceIdentity::from_persisted_secret(&advertiser_secret)
            .unwrap()
            .peer_id();
        let invitation = Invitation::issue(
            &group,
            advertiser_id,
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
            let advertise = service.advertise(
                DeviceIdentity::from_persisted_secret(&advertiser_secret).unwrap(),
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
            let result = timeout(Duration::from_secs(10), async {
                loop {
                    tokio::select! {
                        result = &mut search => break result,
                        _ = routing.next_event() => {}
                    }
                }
            })
            .await
            .expect("provider search should complete")
            .unwrap();
            service.stop_advertising().await;
            assert!(service.advertisement.lock().await.is_none());
            result
        });

        assert_eq!(result.status, "peerReachable");
        assert_eq!(result.discovered_peers, 1);
        assert_eq!(result.reachable_peers, 1);
        assert_eq!(result.connection_type, Some("lan"));
    }

    #[test]
    fn active_advertisement_stops_at_signed_expiry() {
        let now = unix_now();
        let group = GroupIdentity::generate();
        let (owner, owner_signer) = identity_pair();
        let invitation = Invitation::issue(
            &group,
            owner.peer_id(),
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
            let advertise = service.advertise(owner, owner_signer, &invitation);
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
    fn owner_group_advertisement_survives_invitation_expiry() {
        let now = unix_now();
        let group = GroupIdentity::generate();
        let (owner, owner_signer) = identity_pair();
        let invitation = Invitation::issue(
            &group,
            owner.peer_id(),
            InvitationSpec {
                group_name: "Design Crew",
                inviter_name: "Maya",
                expires_at_unix: now + 2,
                history_policy: HistoryPolicy::None,
                reusable: true,
            },
            now,
        )
        .unwrap();
        let key = DiscoveryKey::from_invitation(&invitation);

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
            let advertise = service.advertise_owner_group(owner, owner_signer, vec![key]);
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
            .expect("advertisement should publish before invitation expiry")
            .unwrap();

            while unix_now() <= invitation.expires_at_unix() {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            assert!(!service
                .advertisement
                .lock()
                .await
                .as_ref()
                .expect("owner advertisement should remain active")
                .task
                .is_finished());
        });
    }

    #[test]
    fn advertisement_serves_member_sync_but_rejects_unauthorized_join() {
        let now = unix_now();
        let group = GroupIdentity::generate();
        let (owner, owner_signer) = identity_pair();
        let owner_id = owner.peer_id();
        let invitation = Invitation::issue(
            &group,
            owner_id,
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
            let requester_identity = DeviceIdentity::generate();
            let requester_id = requester_identity.peer_id();
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
            let service = NetworkService::from_sources_with_authorizer(
                &[],
                &bootstrap,
                Arc::new(StaticJoinRequestAuthorizer(
                    JoinRequestAuthorization::Unauthorized,
                )),
                Arc::new(UnavailableMemberAdmissionService),
                Arc::new(UnavailablePendingJoinService),
                Arc::new(MemberSynchronizationService {
                    expected_peer: requester_id,
                    group_id: invitation.group_id(),
                }),
            )
            .unwrap();
            {
                let advertise = service.advertise(owner, owner_signer, &invitation);
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

            let mut requester = NetworkNode::new(requester_identity.into_network_keypair());
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
            .expect("member sync request should receive a response");

            assert_eq!(
                response,
                SyncResponse::Summary {
                    group_id: invitation.group_id(),
                    heads: Vec::new(),
                }
            );

            requester.send_join_request(
                owner_id,
                JoinRequest::from_invitation(&invitation, vec![1]).unwrap(),
            );
            let join_response = timeout(Duration::from_secs(10), async {
                loop {
                    tokio::select! {
                        event = requester.next_event() => {
                            if let NetworkEvent::JoinResponseReceived {
                                peer_id,
                                response,
                                ..
                            } = event
                            {
                                if peer_id == owner_id {
                                    break response;
                                }
                            }
                        },
                        _ = routing.next_event() => {}
                    }
                }
            })
            .await
            .expect("unauthorized join request should receive a response");
            assert_eq!(
                join_response.rejection(),
                Some(JoinRejectReason::Unauthorized)
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
        let routing_identity = DeviceIdentity::generate();
        let expected_inviter = routing_identity.peer_id();
        let invitation = Invitation::issue(
            &group,
            expected_inviter,
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
            let mut routing = NetworkNode::new_routing(routing_identity.into_network_keypair());
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
        assert_eq!(result.connection_type, Some("lan"));
    }

    #[test]
    fn search_ignores_a_provider_not_authorized_by_the_invitation() {
        let invitation = Invitation::issue(
            &GroupIdentity::generate(),
            DeviceIdentity::generate().peer_id(),
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

        assert_eq!(result.status, "noPeers");
        assert_eq!(result.discovered_peers, 0);
        assert_eq!(result.reachable_peers, 0);
        assert_eq!(result.connection_type, None);
    }
}
