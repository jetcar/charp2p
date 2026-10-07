use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use charp2p_core::{
    DeviceIdentity, DiscoveryKey, Invitation, JoinRejectReason, JoinRequest, JoinResponse,
    SyncPeerHead, SyncRejectReason, SyncRequest, SyncResponse,
};
use charp2p_mls::{validate_profile_key_package, ProfileKeyPackageError, ProfileProvider};
use charp2p_network::{ConnectionPath, NetworkEvent, NetworkNode, RelayLimits};
use charp2p_sync::{PullSession, SessionProgress};
use libp2p::{multiaddr::Protocol, Multiaddr, PeerId};
use serde::Serialize;
use tokio::{
    sync::Mutex,
    task::JoinHandle,
    time::{interval, interval_at, sleep_until, timeout, Instant, MissedTickBehavior},
};

use crate::bandwidth::BandwidthService;
use crate::mls_storage::{MemberAdmissionError, MlsProviderService};

const BUILT_IN_BOOTSTRAP_ADDRESSES: &[&str] = &[];
const BOOTSTRAP_ENVIRONMENT_VARIABLE: &str = "CHARP2P_BOOTSTRAP_NODES";
const MAX_BOOTSTRAP_PEERS: usize = 16;
const MAX_BOOTSTRAP_ADDRESS_BYTES: usize = 512;
const MAX_DISCOVERED_PEERS: usize = 32;
const MAX_OWNER_DISCOVERY_KEYS: usize = crate::groups::MAX_ADVERTISED_DISCOVERY_KEYS;
const PROVIDER_SEARCH_TIMEOUT: Duration = Duration::from_secs(8);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
const KNOWN_ADDRESS_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Time after a client node starts during which mDNS may still find the
/// provider on the local network although the DHT lookup found no record.
const LAN_DISCOVERY_WINDOW: Duration = Duration::from_secs(2);
const JOIN_RESPONSE_TIMEOUT: Duration = Duration::from_secs(35);
const SYNC_RESPONSE_TIMEOUT: Duration = Duration::from_secs(35);
const MAX_SYNC_EXCHANGES: usize = 4_096;
const ADVERTISEMENT_REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);
const EXPIRY_CHECK_INTERVAL: Duration = Duration::from_secs(1);
const CONTRIBUTION_BOOTSTRAP_INTERVAL: Duration = Duration::from_secs(5 * 60);

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

    fn report_heads_request(&self, group_id: PeerId) -> Result<SyncRequest, &'static str>;

    fn record_observed_heads(
        &self,
        group_id: PeerId,
        author_id: PeerId,
        peers: &[SyncPeerHead],
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

    fn report_heads_request(&self, group_id: PeerId) -> Result<SyncRequest, &'static str> {
        MlsProviderService::report_heads_request(self, group_id)
    }

    fn record_observed_heads(
        &self,
        group_id: PeerId,
        author_id: PeerId,
        peers: &[SyncPeerHead],
    ) -> Result<(), &'static str> {
        MlsProviderService::record_observed_heads(self, group_id, author_id, peers)
    }
}

#[derive(Clone)]
struct BootstrapPeer {
    peer_id: PeerId,
    address: Multiaddr,
    source: &'static str,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapNodeStatus {
    pub peer_id: String,
    pub address: String,
    pub source: &'static str,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkStatus {
    pub connection_type: Option<&'static str>,
    pub connection_observed_at_unix: u64,
    pub bootstrap_nodes: Vec<BootstrapNodeStatus>,
    pub advertising_status: &'static str,
    pub advertised_discovery_keys: usize,
    pub contribution_status: &'static str,
}

/// Diagnostic report a user can export from the Network page. It is built
/// only from non-secret state: no identity keys, own peer id, group ids or
/// names, invitations, discovery keys or message content.
#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkDiagnostics {
    pub format: &'static str,
    pub app_version: &'static str,
    pub os: &'static str,
    pub arch: &'static str,
    pub generated_at_unix: u64,
    pub network: NetworkStatus,
    pub owned_groups: usize,
    pub joined_groups: usize,
}

pub const DIAGNOSTICS_FORMAT: &str = "charp2p-diagnostics-v1";

/// Upper bound on remembered per-group synchronization outcomes; older
/// entries are dropped first so the in-memory map stays bounded.
const MAX_GROUP_CONNECTION_STATES: usize = 256;

/// Connection state of one group shown on the Groups page, derived from the
/// latest synchronization attempt made by this device in this session.
#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GroupConnectionState {
    pub group_id: String,
    pub state: &'static str,
    /// Whether the latest discovery lookup found the group provider's record
    /// ("found") or not ("missing"); absent until a lookup completed.
    pub discovery: Option<&'static str>,
    pub observed_at_unix: u64,
}

/// Background advertising state of one owned group's retained rendezvous
/// keys, shown in its group details.
#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnedGroupDiscoveryStatus {
    pub status: &'static str,
    pub discovery_keys: usize,
}

#[derive(Clone, Copy)]
struct ObservedGroupSynchronization {
    state: &'static str,
    discovery: Option<&'static str>,
    observed_at_unix: u64,
}

#[derive(Clone, Copy)]
struct ObservedConnection {
    connection_type: &'static str,
    observed_at_unix: u64,
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
    /// Address that reached the group provider, remembered for the next
    /// synchronization; never sent to the frontend.
    #[serde(skip)]
    pub peer_address: Multiaddr,
}

/// Authenticated connection to a group provider and how it was reached.
struct ProviderConnection {
    node: NetworkNode,
    path: ConnectionPath,
    address: Multiaddr,
    /// Whether the provider was found through a DHT lookup rather than a
    /// remembered or LAN-announced address.
    looked_up: bool,
}

/// How a provider search ended successfully.
enum ProviderFound {
    /// The DHT record names the provider, possibly already connected.
    Dht(Option<(ConnectionPath, Multiaddr)>),
    /// The provider was reached at an address announced over mDNS.
    Lan(ConnectionPath, Multiaddr),
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

/// Running opted-in contribution node (ADR-031) and the relay limits it was
/// started with.
struct ActiveContribution {
    relay: Option<RelayLimits>,
    task: JoinHandle<()>,
}

impl Drop for ActiveContribution {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub struct NetworkService {
    bootstrap_peers: Vec<BootstrapPeer>,
    advertisement: Mutex<Option<ActiveAdvertisement>>,
    contribution: Mutex<Option<ActiveContribution>>,
    last_connection: std::sync::Mutex<Option<ObservedConnection>>,
    group_connections: std::sync::Mutex<BTreeMap<PeerId, ObservedGroupSynchronization>>,
    join_authorizer: Arc<dyn JoinRequestAuthorizer>,
    member_admission: Arc<dyn MemberAdmissionService>,
    pending_join: Arc<dyn PendingJoinService>,
    synchronization: Arc<dyn SynchronizationService>,
    /// Whether owner and member nodes also use mDNS on the local network.
    lan_discovery: bool,
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
        let configured = built_in.iter().map(|address| (*address, "builtIn")).chain(
            environment
                .split(';')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(|address| (address, "configured")),
        );
        let mut bootstrap_peers = Vec::new();
        for (configured_address, source) in configured {
            if bootstrap_peers.len() == MAX_BOOTSTRAP_PEERS
                || configured_address.len() > MAX_BOOTSTRAP_ADDRESS_BYTES
            {
                return Err("network_configuration_invalid");
            }
            let mut peer = parse_bootstrap_peer(configured_address)?;
            peer.source = source;
            bootstrap_peers.push(peer);
        }
        Ok(Self {
            bootstrap_peers,
            advertisement: Mutex::new(None),
            contribution: Mutex::new(None),
            last_connection: std::sync::Mutex::new(None),
            group_connections: std::sync::Mutex::new(BTreeMap::new()),
            join_authorizer,
            member_admission,
            pending_join,
            synchronization,
            lan_discovery: true,
        })
    }

    /// Builds the short-lived client node used to advertise or reach a group
    /// provider.
    fn group_client_node(&self, identity: DeviceIdentity) -> NetworkNode {
        let keypair = identity.into_network_keypair();
        if self.lan_discovery {
            NetworkNode::new_with_lan_discovery(keypair)
        } else {
            NetworkNode::new(keypair)
        }
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
    /// Reports the network state shown on the Network page: the most recent
    /// observed connection path, the configured bootstrap nodes and whether
    /// the background provider is currently advertising.
    pub async fn status(&self) -> NetworkStatus {
        let observed = *self
            .last_connection
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (advertising_status, advertised_discovery_keys) = if self.bootstrap_peers.is_empty() {
            ("bootstrapRequired", 0)
        } else {
            match self.advertisement.lock().await.as_ref() {
                Some(active) if !active.task.is_finished() => ("advertising", active.keys.len()),
                _ => ("inactive", 0),
            }
        };
        let contribution_status = match self.contribution.lock().await.as_ref() {
            Some(active) if !active.task.is_finished() => {
                if active.relay.is_some() {
                    "routingAndRelay"
                } else {
                    "routing"
                }
            }
            _ => "inactive",
        };
        NetworkStatus {
            connection_type: observed.map(|connection| connection.connection_type),
            connection_observed_at_unix: observed
                .map_or(0, |connection| connection.observed_at_unix),
            bootstrap_nodes: self
                .bootstrap_peers
                .iter()
                .map(|peer| BootstrapNodeStatus {
                    peer_id: peer.peer_id.to_string(),
                    address: peer.address.to_string(),
                    source: peer.source,
                })
                .collect(),
            advertising_status,
            advertised_discovery_keys,
            contribution_status,
        }
    }

    /// Builds the secret-free diagnostic report; callers pass only group
    /// counts so identifiers never reach it.
    pub async fn diagnostics(
        &self,
        owned_groups: usize,
        joined_groups: usize,
    ) -> NetworkDiagnostics {
        NetworkDiagnostics {
            format: DIAGNOSTICS_FORMAT,
            app_version: env!("CARGO_PKG_VERSION"),
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            generated_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs()),
            network: self.status().await,
            owned_groups,
            joined_groups,
        }
    }

    /// Remembers the outcome of the latest peer connection attempt; network
    /// failures are reported as offline, other failures leave it unchanged.
    fn observe_connection<T>(
        &self,
        result: Result<T, &'static str>,
        connection_type: impl FnOnce(&T) -> Option<&'static str>,
    ) -> Result<T, &'static str> {
        let connection_type = match &result {
            Ok(value) => connection_type(value),
            Err("network_unavailable") => Some("offline"),
            Err(_) => None,
        };
        if let Some(connection_type) = connection_type {
            let observed_at_unix = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |elapsed| elapsed.as_secs());
            *self
                .last_connection
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(ObservedConnection {
                connection_type,
                observed_at_unix,
            });
        }
        result
    }

    /// Remembers the outcome of the latest synchronization attempt for a
    /// group: online (direct or LAN), relayed, offline when the network is
    /// unavailable, and waiting when the group peer could not be reached yet.
    fn observe_group_synchronization<T>(
        &self,
        group_id: PeerId,
        result: Result<T, &'static str>,
        discovery: Option<&'static str>,
        connection_type: impl FnOnce(&T) -> &'static str,
    ) -> Result<T, &'static str> {
        let state = match &result {
            Ok(value) => match connection_type(value) {
                "relayed" => "relayed",
                _ => "online",
            },
            Err("network_unavailable") => "offline",
            Err(_) => "waiting",
        };
        let observed_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        let mut states = self
            .group_connections
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !states.contains_key(&group_id) && states.len() >= MAX_GROUP_CONNECTION_STATES {
            if let Some(oldest) = states
                .iter()
                .min_by_key(|(_, observed)| observed.observed_at_unix)
                .map(|(group, _)| *group)
            {
                states.remove(&oldest);
            }
        }
        // An attempt that stopped before the lookup completed keeps the
        // previously observed discovery outcome.
        let discovery = discovery.or_else(|| {
            states
                .get(&group_id)
                .and_then(|observed| observed.discovery)
        });
        states.insert(
            group_id,
            ObservedGroupSynchronization {
                state,
                discovery,
                observed_at_unix,
            },
        );
        result
    }

    /// Reports the remembered connection state of each requested group;
    /// groups without a synchronization attempt in this session are omitted.
    pub fn group_connection_states(&self, group_ids: &[PeerId]) -> Vec<GroupConnectionState> {
        let states = self
            .group_connections
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        group_ids
            .iter()
            .filter_map(|group_id| {
                states.get(group_id).map(|observed| GroupConnectionState {
                    group_id: group_id.to_string(),
                    state: observed.state,
                    discovery: observed.discovery,
                    observed_at_unix: observed.observed_at_unix,
                })
            })
            .collect()
    }

    /// Reports whether the background provider currently advertises every
    /// retained rendezvous key of one owned group.
    pub async fn owned_group_discovery_status(
        &self,
        keys: &[DiscoveryKey],
    ) -> OwnedGroupDiscoveryStatus {
        let status = if keys.is_empty() {
            "noInvitation"
        } else if self.bootstrap_peers.is_empty() {
            "bootstrapRequired"
        } else {
            match self.advertisement.lock().await.as_ref() {
                Some(active)
                    if !active.task.is_finished()
                        && keys.iter().all(|key| active.keys.contains(key)) =>
                {
                    "advertising"
                }
                _ => "inactive",
            }
        };
        OwnedGroupDiscoveryStatus {
            status,
            discovery_keys: keys.len(),
        }
    }

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

        // The owner device also answers mDNS so members on the same local
        // network can reach it without a relay.
        let mut node = self.group_client_node(network_identity);
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

    /// Runs the opted-in contribution node (ADR-031) in Kademlia server mode
    /// with the given relay limits, restarting it only when the limits
    /// change. Application join and synchronization requests reaching it are
    /// rejected, as routing nodes do.
    pub async fn start_contribution(
        &self,
        network_identity: DeviceIdentity,
        relay: Option<RelayLimits>,
    ) -> Result<&'static str, &'static str> {
        let status = if relay.is_some() {
            "routingAndRelay"
        } else {
            "routing"
        };
        let mut active = self.contribution.lock().await;
        if self.bootstrap_peers.is_empty() {
            active.take();
            return Ok("bootstrapRequired");
        }
        if let Some(existing) = active.as_ref() {
            if existing.relay == relay && !existing.task.is_finished() {
                return Ok(status);
            }
        }
        active.take();

        let mut node =
            NetworkNode::new_contributing(network_identity.into_network_keypair(), relay);
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

        let task = tokio::spawn(async move {
            let mut refresh = interval_at(
                Instant::now() + CONTRIBUTION_BOOTSTRAP_INTERVAL,
                CONTRIBUTION_BOOTSTRAP_INTERVAL,
            );
            refresh.set_missed_tick_behavior(MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = refresh.tick() => {
                        let _ = node.bootstrap();
                    }
                    event = node.next_event() => match event {
                        NetworkEvent::SyncRequestReceived { request_id, .. } => {
                            let _ = node.reject_sync_request(
                                request_id,
                                SyncRejectReason::Unauthorized,
                            );
                        }
                        NetworkEvent::JoinRequestReceived { request_id, .. } => {
                            let _ = node.reject_join_request(
                                request_id,
                                JoinRejectReason::Unauthorized,
                            );
                        }
                        _ => {}
                    },
                }
            }
        });
        *active = Some(ActiveContribution { relay, task });
        Ok(status)
    }

    /// Stops the contribution node, if one is running.
    pub async fn stop_contribution(&self) {
        self.contribution.lock().await.take();
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
        let result = self.search_providers(identity, invitation).await;
        self.observe_connection(result, |found| found.connection_type)
    }

    async fn search_providers(
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
                    NetworkEvent::PeerConnected { peer_id, path, .. } => {
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
                if let NetworkEvent::PeerConnected { peer_id, path, .. } = node.next_event().await {
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
        let ProviderConnection { mut node, .. } = self
            .connect_to_group_provider(identity, key, expected_inviter, &[])
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
            .pull_from_connected_peer(&mut node, expected_inviter, invitation.group_id(), None)
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
        known_addresses: &[Multiaddr],
        bandwidth: &BandwidthService,
    ) -> Result<SynchronizeGroupResult, &'static str> {
        let mut discovery = None;
        let result = self
            .synchronize_with_peer(
                identity,
                key,
                group_id,
                expected_peer,
                known_addresses,
                bandwidth,
                &mut discovery,
            )
            .await;
        self.observe_group_synchronization(group_id, result, discovery, |synchronized| {
            synchronized.connection_type
        })
    }

    #[allow(clippy::too_many_arguments)]
    async fn synchronize_with_peer(
        &self,
        identity: DeviceIdentity,
        key: DiscoveryKey,
        group_id: PeerId,
        expected_peer: PeerId,
        known_addresses: &[Multiaddr],
        bandwidth: &BandwidthService,
        discovery: &mut Option<&'static str>,
    ) -> Result<SynchronizeGroupResult, &'static str> {
        let local_peer = identity.peer_id();
        if local_peer == expected_peer {
            return Err("synchronization_peer_invalid");
        }
        // Skip discovery while the synchronization data limit is spent
        // (ADR-033).
        bandwidth.ensure_sync_budget()?;
        let connected = self
            .connect_to_group_provider(identity, key, expected_peer, known_addresses)
            .await;
        // A remembered address says nothing about the discovery record.
        *discovery = match &connected {
            Ok(connection) if !connection.looked_up => None,
            _ => discovery_outcome(&connected),
        };
        let ProviderConnection {
            mut node,
            path: connection_path,
            address: peer_address,
            ..
        } = connected?;
        let synchronized_events = self
            .pull_from_connected_peer(&mut node, expected_peer, group_id, Some(bandwidth))
            .await?;
        let uploaded_events = self
            .push_to_connected_peer(&mut node, expected_peer, group_id, local_peer, bandwidth)
            .await?;
        self.exchange_observed_heads(&mut node, expected_peer, group_id, local_peer)
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
            peer_address,
        })
    }

    async fn connect_to_group_provider(
        &self,
        identity: DeviceIdentity,
        key: DiscoveryKey,
        expected_peer: PeerId,
        known_addresses: &[Multiaddr],
    ) -> Result<ProviderConnection, &'static str> {
        let result = self
            .dial_group_provider(identity, key, expected_peer, known_addresses)
            .await;
        self.observe_connection(result, |connection| {
            Some(connection_type_name(connection.path))
        })
    }

    async fn dial_group_provider(
        &self,
        identity: DeviceIdentity,
        key: DiscoveryKey,
        expected_peer: PeerId,
        known_addresses: &[Multiaddr],
    ) -> Result<ProviderConnection, &'static str> {
        if self.bootstrap_peers.is_empty() && known_addresses.is_empty() {
            return Err("network_bootstrap_required");
        }
        let lan_deadline = Instant::now() + LAN_DISCOVERY_WINDOW;
        let mut node = self.group_client_node(identity);
        node.listen_on(
            "/ip4/0.0.0.0/udp/0/quic-v1"
                .parse()
                .map_err(|_| "network_configuration_invalid")?,
        )
        .map_err(|_| "network_unavailable")?;
        // Remembered addresses of the last successful synchronizations are
        // tried before a DHT lookup; the transport still authenticates the
        // provider as `expected_peer`.
        if !known_addresses.is_empty()
            && node
                .dial_peer_at(expected_peer, known_addresses.to_vec())
                .is_ok()
        {
            let connected = timeout(KNOWN_ADDRESS_CONNECT_TIMEOUT, async {
                loop {
                    if let NetworkEvent::PeerConnected {
                        peer_id,
                        path,
                        remote_address,
                    } = node.next_event().await
                    {
                        if peer_id == expected_peer {
                            break (path, remote_address);
                        }
                    }
                }
            })
            .await;
            if let Ok((path, address)) = connected {
                return Ok(ProviderConnection {
                    node,
                    path,
                    address,
                    looked_up: false,
                });
            }
        }
        if self.bootstrap_peers.is_empty() {
            return Err("network_bootstrap_required");
        }
        for bootstrap in &self.bootstrap_peers {
            node.add_bootstrap_peer(bootstrap.peer_id, bootstrap.address.clone());
        }
        node.bootstrap().map_err(|_| "network_unavailable")?;
        node.find_group_peers(key);

        let search = timeout(PROVIDER_SEARCH_TIMEOUT, async {
            let mut connected = None;
            // Deadline of a dial to the provider at an mDNS-announced address.
            let mut lan_dial_deadline = None;
            let mut search_error = None;
            loop {
                let event = match search_error {
                    // The DHT has no usable record, but the provider may
                    // still be announced on, or being dialed over, the LAN.
                    Some(error) => {
                        tokio::select! {
                            event = node.next_event() => event,
                            _ = sleep_until(lan_dial_deadline.unwrap_or(lan_deadline)) => {
                                return Err(error);
                            }
                        }
                    }
                    None => node.next_event().await,
                };
                match event {
                    NetworkEvent::PeerConnected {
                        peer_id,
                        path,
                        remote_address,
                    } if peer_id == expected_peer => {
                        if lan_dial_deadline.is_some() {
                            return Ok(ProviderFound::Lan(path, remote_address));
                        }
                        connected = Some((path, remote_address));
                    }
                    NetworkEvent::LanPeersDiscovered { peers }
                        if lan_dial_deadline.is_none()
                            && connected.is_none()
                            && peers.iter().any(|(peer_id, _)| *peer_id == expected_peer) =>
                    {
                        // The transport still authenticates the provider as
                        // `expected_peer`; mDNS only supplied its address.
                        if node.dial_peer(expected_peer).is_ok() {
                            lan_dial_deadline = Some(Instant::now() + CONNECT_TIMEOUT);
                        }
                    }
                    NetworkEvent::GroupPeersFound {
                        key: found_key,
                        providers,
                    } if found_key == key && providers.contains(&expected_peer) => {
                        return Ok(ProviderFound::Dht(connected));
                    }
                    NetworkEvent::GroupPeerSearchFinished { key: found_key }
                        if found_key == key =>
                    {
                        search_error.get_or_insert("network_peer_not_found");
                    }
                    NetworkEvent::DiscoveryFailed {
                        key: failed_key, ..
                    } if failed_key == key => {
                        search_error.get_or_insert("network_unavailable");
                    }
                    _ => {}
                }
            }
        })
        .await
        .map_err(|_| "network_search_timed_out")??;

        let already_connected = match search {
            ProviderFound::Lan(path, address) => {
                return Ok(ProviderConnection {
                    node,
                    path,
                    address,
                    looked_up: false,
                });
            }
            ProviderFound::Dht(connected) => connected,
        };
        let (path, address) = if let Some(connected) = already_connected {
            connected
        } else {
            node.dial_peer(expected_peer)
                .map_err(|_| "network_peer_unreachable")?;
            timeout(CONNECT_TIMEOUT, async {
                loop {
                    if let NetworkEvent::PeerConnected {
                        peer_id,
                        path,
                        remote_address,
                    } = node.next_event().await
                    {
                        if peer_id == expected_peer {
                            break (path, remote_address);
                        }
                    }
                }
            })
            .await
            .map_err(|_| "network_peer_unreachable")?
        };
        Ok(ProviderConnection {
            node,
            path,
            address,
            looked_up: true,
        })
    }

    async fn pull_from_connected_peer(
        &self,
        node: &mut NetworkNode,
        peer_id: PeerId,
        group_id: PeerId,
        bandwidth: Option<&BandwidthService>,
    ) -> Result<usize, &'static str> {
        let (mut session, mut request) = PullSession::start(group_id);
        let mut inserted = 0_usize;
        for _ in 0..MAX_SYNC_EXCHANGES {
            if let Some(bandwidth) = bandwidth {
                bandwidth.ensure_sync_budget()?;
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
            if let Some(bandwidth) = bandwidth {
                bandwidth.charge_sync_bytes(response_event_bytes(&response));
            }
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
        bandwidth: &BandwidthService,
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
            bandwidth.ensure_sync_budget()?;
            // Pushed events are charged once sent, whatever the answer.
            let pushed_bytes = request_event_bytes(&request);
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
            bandwidth.charge_sync_bytes(pushed_bytes);
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

    /// Reports this device's stored heads to the peer and records which of
    /// its own events every other member the peer knows has stored (ADR-030).
    async fn exchange_observed_heads(
        &self,
        node: &mut NetworkNode,
        peer_id: PeerId,
        group_id: PeerId,
        author_id: PeerId,
    ) -> Result<(), &'static str> {
        let request = self.synchronization.report_heads_request(group_id)?;
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
            SyncResponse::ObservedHeads {
                group_id: response_group,
                peers,
            } if response_group == group_id => self
                .synchronization
                .record_observed_heads(group_id, author_id, &peers),
            SyncResponse::Rejected { reason } => Err(match reason {
                SyncRejectReason::Unauthorized => "synchronization_unauthorized",
                SyncRejectReason::InvalidRequest => "synchronization_failed",
                SyncRejectReason::Busy => "synchronization_busy",
            }),
            _ => Err("synchronization_failed"),
        }
    }
}

/// Signed event bytes a synchronization request pushes (ADR-033).
fn request_event_bytes(request: &SyncRequest) -> u64 {
    match request {
        SyncRequest::PushEvents { encoded_events, .. } => encoded_bytes(encoded_events),
        _ => 0,
    }
}

/// Signed event bytes a synchronization response delivers (ADR-033).
fn response_event_bytes(response: &SyncResponse) -> u64 {
    match response {
        SyncResponse::Events { encoded_events, .. } => encoded_bytes(encoded_events),
        _ => 0,
    }
}

fn encoded_bytes(encoded_events: &[Vec<u8>]) -> u64 {
    encoded_events.iter().map(|event| event.len() as u64).sum()
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

    fn report_heads_request(&self, _group_id: PeerId) -> Result<SyncRequest, &'static str> {
        Err("synchronization_unavailable")
    }

    fn record_observed_heads(
        &self,
        _group_id: PeerId,
        _author_id: PeerId,
        _peers: &[SyncPeerHead],
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

/// Classifies a group provider lookup by what it shows about the provider's
/// discovery record: a dial failure after the record was found still implies
/// "found", and failures before the lookup completed say nothing.
fn discovery_outcome<T>(result: &Result<T, &'static str>) -> Option<&'static str> {
    match result {
        Ok(_) | Err("network_peer_unreachable") => Some("found"),
        Err("network_peer_not_found" | "network_search_timed_out") => Some("missing"),
        Err(_) => None,
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
    Ok(BootstrapPeer {
        peer_id,
        address,
        source: "configured",
    })
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
        JoinRejectReason, JoinRequest, JoinResponse, PeerId, SyncPeerHead, SyncRejectReason,
        SyncRequest, SyncResponse,
    };
    use charp2p_mls::{
        device_credential, prepare_profile_key_package, ProfileProvider, CIPHERSUITE,
    };
    use charp2p_network::{NetworkEvent, NetworkNode};
    use openmls::prelude::{tls_codec::Serialize, CredentialWithKey, KeyPackage, OpenMlsProvider};
    use openmls_basic_credential::SignatureKeyPair;
    use tokio::time::timeout;

    use crate::bandwidth::{BandwidthPreference, BandwidthService};

    use super::{
        discovery_outcome, join_response, parse_bootstrap_peer, AdvertisementResult,
        BootstrapNodeStatus, JoinRequestAuthorization, JoinRequestAuthorizer,
        MemberAdmissionService, NetworkService, NetworkStatus, PeerSearchResult,
        PendingJoinService, PullSession, SessionProgress, SynchronizationService,
        UnavailableJoinRequestAuthorizer, UnavailableMemberAdmissionService,
        UnavailablePendingJoinService, DIAGNOSTICS_FORMAT, MAX_GROUP_CONNECTION_STATES,
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
            if authenticated_peer != self.expected_peer {
                return SyncResponse::Rejected {
                    reason: SyncRejectReason::Unauthorized,
                };
            }
            match request {
                SyncRequest::Summary { group_id } if *group_id == self.group_id => {
                    SyncResponse::Summary {
                        group_id: self.group_id,
                        heads: Vec::new(),
                    }
                }
                SyncRequest::ReportHeads { group_id, .. } if *group_id == self.group_id => {
                    SyncResponse::ObservedHeads {
                        group_id: self.group_id,
                        peers: Vec::new(),
                    }
                }
                _ => SyncResponse::Rejected {
                    reason: SyncRejectReason::Unauthorized,
                },
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

        fn report_heads_request(&self, group_id: PeerId) -> Result<SyncRequest, &'static str> {
            Ok(SyncRequest::ReportHeads {
                group_id,
                heads: Vec::new(),
            })
        }

        fn record_observed_heads(
            &self,
            _group_id: PeerId,
            _author_id: PeerId,
            _peers: &[SyncPeerHead],
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

    impl NetworkService {
        /// Keeps tests of DHT discovery independent of mDNS on the host.
        fn without_lan_discovery(mut self) -> Self {
            self.lan_discovery = false;
            self
        }
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
    fn status_lists_bootstrap_nodes_with_their_source() {
        let built_in_peer = DeviceIdentity::generate().peer_id();
        let configured_peer = DeviceIdentity::generate().peer_id();
        let built_in = format!("/ip4/127.0.0.1/udp/9000/quic-v1/p2p/{built_in_peer}");
        let configured = format!(" /ip4/10.0.0.2/udp/9001/quic-v1/p2p/{configured_peer} ;");
        let service = NetworkService::from_sources(&[built_in.as_str()], &configured).unwrap();

        let status = tauri::async_runtime::block_on(service.status());

        assert_eq!(
            status,
            NetworkStatus {
                connection_type: None,
                connection_observed_at_unix: 0,
                bootstrap_nodes: vec![
                    BootstrapNodeStatus {
                        peer_id: built_in_peer.to_string(),
                        address: "/ip4/127.0.0.1/udp/9000/quic-v1".to_owned(),
                        source: "builtIn",
                    },
                    BootstrapNodeStatus {
                        peer_id: configured_peer.to_string(),
                        address: "/ip4/10.0.0.2/udp/9001/quic-v1".to_owned(),
                        source: "configured",
                    },
                ],
                advertising_status: "inactive",
                advertised_discovery_keys: 0,
                contribution_status: "inactive",
            }
        );
    }

    #[test]
    fn status_requires_a_bootstrap_node_to_advertise() {
        let status =
            tauri::async_runtime::block_on(NetworkService::from_sources(&[], "").unwrap().status());

        assert!(status.bootstrap_nodes.is_empty());
        assert_eq!(status.advertising_status, "bootstrapRequired");
        assert_eq!(status.connection_type, None);
    }

    #[test]
    fn contribution_requires_a_bootstrap_node() {
        let service = NetworkService::from_sources(&[], "").unwrap();

        let started = tauri::async_runtime::block_on(
            service.start_contribution(DeviceIdentity::generate(), None),
        );

        assert_eq!(started, Ok("bootstrapRequired"));
        assert_eq!(
            tauri::async_runtime::block_on(service.status()).contribution_status,
            "inactive"
        );
    }

    #[test]
    fn contribution_follows_the_preference_until_stopped() {
        let bootstrap_peer = DeviceIdentity::generate().peer_id();
        let configured = format!("/ip4/127.0.0.1/udp/9/quic-v1/p2p/{bootstrap_peer}");
        let service = NetworkService::from_sources(&[], &configured).unwrap();
        let relay = charp2p_network::RelayLimits::new(2, 1).unwrap();

        tauri::async_runtime::block_on(async {
            assert_eq!(
                service
                    .start_contribution(DeviceIdentity::generate(), None)
                    .await,
                Ok("routing")
            );
            assert_eq!(service.status().await.contribution_status, "routing");
            assert_eq!(
                service
                    .start_contribution(DeviceIdentity::generate(), Some(relay))
                    .await,
                Ok("routingAndRelay")
            );
            assert_eq!(
                service.status().await.contribution_status,
                "routingAndRelay"
            );
            assert_eq!(
                service
                    .start_contribution(DeviceIdentity::generate(), Some(relay))
                    .await,
                Ok("routingAndRelay")
            );
            service.stop_contribution().await;
            assert_eq!(service.status().await.contribution_status, "inactive");
        });
    }

    #[test]
    fn status_reports_the_latest_observed_connection() {
        let service = NetworkService::from_sources(&[], "").unwrap();

        let _ = service.observe_connection(Ok("lan"), |path| Some(*path));
        assert_eq!(
            tauri::async_runtime::block_on(service.status()).connection_type,
            Some("lan")
        );
        let _ = service.observe_connection::<&str>(Err("network_peer_not_found"), |_| None);
        assert_eq!(
            tauri::async_runtime::block_on(service.status()).connection_type,
            Some("lan")
        );
        let _ = service.observe_connection::<&str>(Err("network_unavailable"), |_| None);
        let status = tauri::async_runtime::block_on(service.status());
        assert_eq!(status.connection_type, Some("offline"));
        assert!(status.connection_observed_at_unix > 0);
    }

    #[test]
    fn spent_synchronization_budget_skips_discovery_and_waits() {
        let directory = tempfile::tempdir().unwrap();
        let bandwidth = BandwidthService::new(directory.path().join("bandwidth.json"));
        bandwidth
            .set(BandwidthPreference {
                sync_limit_mib_per_hour: Some(1),
            })
            .unwrap();
        bandwidth.charge_sync_bytes(2 * 1024 * 1024);
        let service = NetworkService::from_sources(&[], "").unwrap();
        let group_id = DeviceIdentity::generate().peer_id();

        let result = tauri::async_runtime::block_on(service.synchronize(
            DeviceIdentity::generate(),
            DiscoveryKey::from_bytes([7; 32]),
            group_id,
            DeviceIdentity::generate().peer_id(),
            &[],
            &bandwidth,
        ));

        assert_eq!(result.unwrap_err(), "synchronization_bandwidth_limited");
        assert_eq!(
            service.group_connection_states(&[group_id])[0].state,
            "waiting"
        );
    }

    #[test]
    fn group_discovery_outcome_keeps_the_last_completed_lookup() {
        let service = NetworkService::from_sources(&[], "").unwrap();
        let group = DeviceIdentity::generate().peer_id();
        let discovery = || service.group_connection_states(&[group])[0].discovery;

        let not_found = Err::<&str, _>("network_peer_not_found");
        let _ = service.observe_group_synchronization(
            group,
            not_found,
            discovery_outcome(&not_found),
            |path| path,
        );
        assert_eq!(discovery(), Some("missing"));
        let unreachable = Err::<&str, _>("network_peer_unreachable");
        let _ = service.observe_group_synchronization(
            group,
            unreachable,
            discovery_outcome(&unreachable),
            |path| path,
        );
        assert_eq!(discovery(), Some("found"));
        let offline = Err::<&str, _>("network_unavailable");
        let _ = service.observe_group_synchronization(
            group,
            offline,
            discovery_outcome(&offline),
            |path| path,
        );
        assert_eq!(
            service.group_connection_states(&[group])[0].state,
            "offline"
        );
        assert_eq!(discovery(), Some("found"));
        let timed_out = Err::<&str, _>("network_search_timed_out");
        assert_eq!(discovery_outcome(&timed_out), Some("missing"));
        assert_eq!(discovery_outcome(&Ok::<_, &str>(())), Some("found"));
        assert_eq!(
            discovery_outcome(&Err::<(), _>("synchronization_bandwidth_limited")),
            None
        );
    }

    #[test]
    fn owned_group_discovery_status_reports_background_advertising() {
        let without_bootstrap = NetworkService::from_sources(&[], "").unwrap();
        let key = DiscoveryKey::from_bytes([3; 32]);
        let status =
            tauri::async_runtime::block_on(without_bootstrap.owned_group_discovery_status(&[]));
        assert_eq!(status.status, "noInvitation");
        assert_eq!(status.discovery_keys, 0);
        let status =
            tauri::async_runtime::block_on(without_bootstrap.owned_group_discovery_status(&[key]));
        assert_eq!(status.status, "bootstrapRequired");
        assert_eq!(status.discovery_keys, 1);

        let bootstrap_peer = DeviceIdentity::generate().peer_id();
        let configured = format!("/ip4/127.0.0.1/udp/9/quic-v1/p2p/{bootstrap_peer}");
        let service = NetworkService::from_sources(&[], &configured).unwrap();
        let status = tauri::async_runtime::block_on(service.owned_group_discovery_status(&[key]));
        assert_eq!(status.status, "inactive");
    }

    #[test]
    fn group_connection_states_follow_the_latest_synchronization_attempt() {
        let service = NetworkService::from_sources(&[], "").unwrap();
        let first = DeviceIdentity::generate().peer_id();
        let second = DeviceIdentity::generate().peer_id();
        let unknown = DeviceIdentity::generate().peer_id();
        let state = |group: PeerId| {
            service
                .group_connection_states(&[group])
                .pop()
                .map(|observed| observed.state)
        };

        let _ = service.observe_group_synchronization(first, Ok("direct"), None, |path| path);
        let _ = service.observe_group_synchronization(second, Ok("relayed"), None, |path| path);
        assert_eq!(state(first), Some("online"));
        assert_eq!(state(second), Some("relayed"));
        let _ = service.observe_group_synchronization(first, Ok("lan"), None, |path| path);
        assert_eq!(state(first), Some("online"));
        let _ = service.observe_group_synchronization::<&str>(
            first,
            Err("network_unavailable"),
            None,
            |p| p,
        );
        assert_eq!(state(first), Some("offline"));
        let _ = service.observe_group_synchronization::<&str>(
            second,
            Err("network_peer_not_found"),
            None,
            |path| path,
        );
        assert_eq!(state(second), Some("waiting"));
        assert_eq!(state(unknown), None);

        let states = service.group_connection_states(&[second, unknown, first]);
        assert_eq!(
            states
                .iter()
                .map(|observed| observed.group_id.clone())
                .collect::<Vec<_>>(),
            vec![second.to_string(), first.to_string()]
        );
        assert!(states.iter().all(|observed| observed.observed_at_unix > 0));
    }

    #[test]
    fn group_connection_states_stay_bounded() {
        let service = NetworkService::from_sources(&[], "").unwrap();
        let groups = (0..=MAX_GROUP_CONNECTION_STATES)
            .map(|_| DeviceIdentity::generate().peer_id())
            .collect::<Vec<_>>();
        for group in &groups {
            let _ = service.observe_group_synchronization(*group, Ok("direct"), None, |path| path);
        }

        assert_eq!(
            service.group_connection_states(&groups).len(),
            MAX_GROUP_CONNECTION_STATES
        );
        assert_eq!(
            service
                .group_connection_states(&groups[MAX_GROUP_CONNECTION_STATES..])
                .len(),
            1
        );
    }

    #[test]
    fn diagnostics_contain_counts_and_status_but_no_identifiers() {
        let bootstrap_peer = DeviceIdentity::generate().peer_id();
        let configured = format!("/ip4/10.0.0.2/udp/9001/quic-v1/p2p/{bootstrap_peer}");
        let service = NetworkService::from_sources(&[], &configured).unwrap();
        let _ = service.observe_connection(Ok("relayed"), |path| Some(*path));

        let diagnostics = tauri::async_runtime::block_on(service.diagnostics(2, 3));

        assert_eq!(diagnostics.format, DIAGNOSTICS_FORMAT);
        assert_eq!(diagnostics.app_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(diagnostics.os, std::env::consts::OS);
        assert!(diagnostics.generated_at_unix > 0);
        assert_eq!(diagnostics.network.connection_type, Some("relayed"));
        assert_eq!(diagnostics.network.bootstrap_nodes.len(), 1);
        assert_eq!(
            (diagnostics.owned_groups, diagnostics.joined_groups),
            (2, 3)
        );
        let json = serde_json::to_value(&diagnostics).unwrap();
        let keys = json
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            [
                "appVersion",
                "arch",
                "format",
                "generatedAtUnix",
                "joinedGroups",
                "network",
                "os",
                "ownedGroups",
            ]
        );
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
            let (member_identity, remembering_member_identity) = identity_pair();
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
            .unwrap()
            .without_lan_discovery();
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

            let bandwidth_directory = tempfile::tempdir().unwrap();
            let bandwidth =
                BandwidthService::new(bandwidth_directory.path().join("bandwidth.json"));
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
            .unwrap()
            .without_lan_discovery();
            let synchronize = member_service.synchronize(
                member_identity,
                discovery_key,
                invitation.group_id(),
                owner_id,
                &[],
                &bandwidth,
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
            // The owner listens on every interface; on hosts with a
            // non-private interface address that address may win the dial.
            assert!(matches!(result.connection_type, "lan" | "direct"));
            assert_eq!(
                member_service.group_connection_states(&[invitation.group_id()])[0].discovery,
                Some("found")
            );

            // Without any bootstrap node, the remembered address alone
            // reaches the owner again and no lookup outcome is reported.
            let offline_member_service = NetworkService::from_sources_with_authorizer(
                &[],
                "",
                Arc::new(UnavailableJoinRequestAuthorizer),
                Arc::new(UnavailableMemberAdmissionService),
                Arc::new(UnavailablePendingJoinService),
                Arc::new(MemberSynchronizationService {
                    expected_peer: owner_id,
                    group_id: invitation.group_id(),
                }),
            )
            .unwrap()
            .without_lan_discovery();
            let remembered = timeout(
                Duration::from_secs(15),
                offline_member_service.synchronize(
                    remembering_member_identity,
                    discovery_key,
                    invitation.group_id(),
                    owner_id,
                    std::slice::from_ref(&result.peer_address),
                    &bandwidth,
                ),
            )
            .await
            .expect("remembered address synchronization should complete")
            .unwrap();
            assert_eq!(remembered.status, "synchronized");
            assert_eq!(remembered.peer_address, result.peer_address);
            assert_eq!(
                offline_member_service.group_connection_states(&[invitation.group_id()])[0]
                    .discovery,
                None
            );
        });
    }

    #[test]
    fn member_reaches_the_owner_over_lan_when_the_dht_has_no_record() {
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
            // Owner and member use separate routing nodes, so the member's
            // DHT lookup cannot find the owner's provider record.
            let mut owner_routing =
                NetworkNode::new_routing(DeviceIdentity::generate().into_network_keypair());
            let mut member_routing =
                NetworkNode::new_routing(DeviceIdentity::generate().into_network_keypair());
            let mut bootstraps = Vec::new();
            for routing in [&mut owner_routing, &mut member_routing] {
                routing
                    .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
                    .unwrap();
                let address = loop {
                    if let NetworkEvent::Listening { address } = routing.next_event().await {
                        break address;
                    }
                };
                bootstraps.push(format!("{address}/p2p/{}", routing.peer_id()));
            }
            let owner_service = NetworkService::from_sources_with_authorizer(
                &[],
                &bootstraps[0],
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
                        _ = owner_routing.next_event() => {}
                    }
                }
            })
            .await
            .expect("advertisement should complete")
            .unwrap();

            let bandwidth_directory = tempfile::tempdir().unwrap();
            let bandwidth =
                BandwidthService::new(bandwidth_directory.path().join("bandwidth.json"));
            let member_service = NetworkService::from_sources_with_authorizer(
                &[],
                &bootstraps[1],
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
                &[],
                &bandwidth,
            );
            tokio::pin!(synchronize);
            let result = timeout(Duration::from_secs(15), async {
                loop {
                    tokio::select! {
                        result = &mut synchronize => break result,
                        _ = owner_routing.next_event() => {}
                        _ = member_routing.next_event() => {}
                    }
                }
            })
            .await
            .expect("LAN synchronization should complete")
            .unwrap();

            assert_eq!(result.status, "synchronized");
            assert_eq!(result.synchronized_events, 3);
            assert_eq!(result.connection_type, "lan");
            // mDNS says nothing about the discovery record.
            assert_eq!(
                member_service.group_connection_states(&[invitation.group_id()])[0].discovery,
                None
            );
        });
    }

    #[test]
    fn synchronization_without_bootstrap_or_remembered_address_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let bandwidth = BandwidthService::new(directory.path().join("bandwidth.json"));
        let service = NetworkService::from_sources(&[], "").unwrap();

        let result = tauri::async_runtime::block_on(service.synchronize(
            DeviceIdentity::generate(),
            DiscoveryKey::from_bytes([7; 32]),
            DeviceIdentity::generate().peer_id(),
            DeviceIdentity::generate().peer_id(),
            &[],
            &bandwidth,
        ));

        assert_eq!(result.unwrap_err(), "network_bootstrap_required");
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
            let service = NetworkService::from_sources(&[], &format!("{address}/p2p/{routing_id}"))
                .unwrap()
                .without_lan_discovery();
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
        // The advertiser listens on every interface; on hosts with a
        // non-private interface address that address may win the dial.
        assert!(matches!(result.connection_type, Some("lan" | "direct")));
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
