use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use charp2p_core::{
    DeviceIdentity, DiscoveryKey, Invitation, InviteRejectReason, InviteRequest, InviteResponse,
    JoinRejectReason, JoinRequest, JoinResponse, SyncPeerHead, SyncRejectReason, SyncRequest,
    SyncResponse, MAX_ADDRESS_HINTS,
};
use charp2p_mls::{validate_profile_key_package, ProfileKeyPackageError, ProfileProvider};
use charp2p_network::{
    ConnectionPath, InboundInviteRequestId, InboundJoinRequestId, InboundSyncRequestId,
    NetworkEvent, NetworkNode, OutboundSyncRequestId, RelayLimits,
};
use charp2p_sync::{MembershipComparison, PullSession, SessionProgress};
use libp2p::{multiaddr::Protocol, Multiaddr, PeerId};
use serde::Serialize;
use tokio::{
    sync::{broadcast, mpsc, oneshot, Mutex},
    task::JoinHandle,
    time::{interval, interval_at, sleep_until, timeout, Instant, MissedTickBehavior},
};

use crate::bandwidth::BandwidthService;
use crate::groups::{requested_invitation, IssuedInvitation};
use crate::mls_storage::{sync_request_group_id, MemberAdmissionError, MlsProviderService};
use crate::routing_peers::RoutingPeersService;

const BUILT_IN_BOOTSTRAP_ADDRESSES: &[&str] = &[];
const BOOTSTRAP_ENVIRONMENT_VARIABLE: &str = "CHARP2P_BOOTSTRAP_NODES";
const MAX_BOOTSTRAP_PEERS: usize = 16;
const MAX_BOOTSTRAP_ADDRESS_BYTES: usize = 512;
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
/// Member providers tried by one member-served pull (ADR-040).
const MAX_MEMBER_PROVIDERS: usize = 4;
/// How long issuing an invitation waits for a freshly started owner
/// advertising node to obtain a relay circuit address as a hint.
const OWNER_HINT_WAIT: Duration = Duration::from_secs(3);
const ADVERTISEMENT_REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);
const EXPIRY_CHECK_INTERVAL: Duration = Duration::from_secs(1);
const CONTRIBUTION_BOOTSTRAP_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// How often a member serving node redials the pinned owner after its
/// connection closed, so the owner can send new-event notices (ADR-049).
const OWNER_REDIAL_INTERVAL: Duration = Duration::from_secs(20);
/// Acknowledged new-event notices buffered for slow subscribers; a lagging
/// subscriber only misses an immediate pull, never data.
const EVENT_NOTICE_CAPACITY: usize = 16;
/// Most listen addresses of the owner advertising node kept as invitation
/// hint candidates.
const MAX_OWNER_LISTEN_ADDRESSES: usize = 16;
/// Connected peers the owner advertising node tracks for owned group states.
const MAX_OWNER_PEERS: usize = 1024;
/// Largest binary multiaddress an invitation accepts as a hint (ADR-037).
const MAX_ADDRESS_HINT_BYTES: usize = 256;

/// Current members found as providers of a member rendezvous key, in the
/// order the DHT search reported them (ADR-040).
struct MemberCandidates<'a> {
    local_peer: PeerId,
    members: &'a [PeerId],
    found: Vec<PeerId>,
}

impl<'a> MemberCandidates<'a> {
    fn new(local_peer: PeerId, members: &'a [PeerId]) -> Self {
        Self {
            local_peer,
            members,
            found: Vec::new(),
        }
    }

    /// Adds the listed current members among `providers` other than this
    /// device, and returns whether the provider limit is reached.
    fn add(&mut self, providers: Vec<PeerId>) -> bool {
        for provider in providers {
            if self.found.len() == MAX_MEMBER_PROVIDERS {
                break;
            }
            if provider != self.local_peer
                && self.members.contains(&provider)
                && !self.found.contains(&provider)
            {
                self.found.push(provider);
            }
        }
        self.found.len() == MAX_MEMBER_PROVIDERS
    }

    /// Returns the collected candidates once the search stopped, or the
    /// reason it stopped when it found none.
    fn finish(self, stopped: Option<&'static str>) -> Result<Vec<PeerId>, &'static str> {
        if self.found.is_empty() {
            Err(stopped.unwrap_or("network_peer_not_found"))
        } else {
            Ok(self.found)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JoinRequestAuthorization {
    Authorized,
    Unauthorized,
    Unavailable,
}

pub(crate) trait JoinRequestAuthorizer: Send + Sync {
    fn authorize_join_request(&self, request: &JoinRequest) -> JoinRequestAuthorization;
}

/// Answers a member's request for an owner-issued invitation (ADR-036).
pub(crate) trait InviteRequestService: Send + Sync {
    fn answer_invite_request(
        &self,
        owner_device_id: PeerId,
        inviter_name: &str,
        authenticated_peer: PeerId,
        request: &InviteRequest,
        address_hints: &[Multiaddr],
    ) -> InviteResponse;
}

/// Used until an owner-side service is configured; never issues.
struct RejectingInviteRequestService;

impl InviteRequestService for RejectingInviteRequestService {
    fn answer_invite_request(
        &self,
        _owner_device_id: PeerId,
        _inviter_name: &str,
        _authenticated_peer: PeerId,
        _request: &InviteRequest,
        _address_hints: &[Multiaddr],
    ) -> InviteResponse {
        InviteResponse::rejected(InviteRejectReason::Unauthorized)
    }
}

pub(crate) trait MemberAdmissionService: Send + Sync {
    fn admit_member(
        &self,
        request: &JoinRequest,
        owner_identity: &DeviceIdentity,
        authenticated_peer: PeerId,
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

    /// Highest contiguous sequence of `author_id`'s events the peer durably
    /// acknowledged storing (ADR-024); 0 when none.
    fn acknowledged_head(
        &self,
        group_id: PeerId,
        peer_id: PeerId,
        author_id: PeerId,
    ) -> Result<u64, &'static str>;

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

    /// Devices of the group's current MLS epoch that may receive the
    /// owner's new-event notices (ADR-049); empty when the group is unknown.
    fn notice_recipients(&self, group_id: PeerId) -> Vec<PeerId>;

    /// Whether this device owns the group, so nodes other than the owner
    /// advertising node may answer its requests as the owner (ADR-031).
    fn owns_group(&self, group_id: PeerId) -> bool;
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

    fn acknowledged_head(
        &self,
        group_id: PeerId,
        peer_id: PeerId,
        author_id: PeerId,
    ) -> Result<u64, &'static str> {
        MlsProviderService::acknowledged_head(self, group_id, peer_id, author_id)
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

    fn notice_recipients(&self, group_id: PeerId) -> Vec<PeerId> {
        self.group_members(group_id)
            .map(|members| {
                members
                    .iter()
                    .filter_map(|member| member.device_id.parse().ok())
                    .collect()
            })
            .unwrap_or_default()
    }

    fn owns_group(&self, group_id: PeerId) -> bool {
        MlsProviderService::owns_group(self, group_id)
    }
}

#[derive(Clone)]
pub struct BootstrapPeer {
    pub(crate) peer_id: PeerId,
    pub(crate) address: Multiaddr,
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
    /// online, relayed, memberServed (pulled from a member while the owner
    /// was unreachable), waiting or offline.
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
    /// Completion time of the initial pull from the owner, or `None` when
    /// it failed and the next synchronization fetches the history.
    pub synchronized_at_unix: Option<u64>,
    /// Address that reached the owner, remembered for later
    /// synchronizations; never sent to the frontend.
    #[serde(skip)]
    pub peer_address: Multiaddr,
    /// Time the owner's Welcome was accepted through `peer_address`, which
    /// is a successful contact even when the initial pull failed.
    #[serde(skip)]
    pub reached_at_unix: u64,
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
    /// How this device's membership commits compared with the peer's before
    /// the pull, or `None` when the peer sent no summary.
    pub membership: Option<&'static str>,
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
    owner: PeerId,
    inviter_name: String,
    /// Hands a changed key set to the running task, which announces new keys
    /// and stops refreshing retired ones without restarting the node.
    key_updates: mpsc::UnboundedSender<Vec<DiscoveryKey>>,
    task: JoinHandle<()>,
}

impl Drop for ActiveAdvertisement {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Member serving node of the open joined group (ADR-040) and the member
/// rendezvous key it advertises.
struct ActiveMemberServing {
    group_id: PeerId,
    key: DiscoveryKey,
    owner: PeerId,
    /// Whether the node announces the member key; without bootstrap nodes it
    /// only keeps the owner connection.
    advertised: bool,
    /// Inviter name of the invitations it issues for owned groups.
    inviter_name: String,
    /// Asks the serving task to lend its node while it holds an
    /// authenticated connection to `owner`.
    lend: mpsc::Sender<oneshot::Sender<LentOwnerConnection>>,
    task: JoinHandle<()>,
}

/// Member serving node lent for one synchronization over its existing
/// connection to the pinned owner (technical-design Connectivity order 1).
/// Dropping it, even when the synchronization is cancelled, hands the node
/// back to the serving task.
struct LentOwnerConnection {
    node: Option<NetworkNode>,
    path: ConnectionPath,
    address: Multiaddr,
    returns: Option<oneshot::Sender<NetworkNode>>,
}

impl LentOwnerConnection {
    fn node(&mut self) -> &mut NetworkNode {
        self.node
            .as_mut()
            .expect("a lent node is held until it is dropped")
    }
}

impl Drop for LentOwnerConnection {
    fn drop(&mut self) {
        if let (Some(node), Some(returns)) = (self.node.take(), self.returns.take()) {
            let _ = returns.send(node);
        }
    }
}

impl Drop for ActiveMemberServing {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Running opted-in contribution node (ADR-031), the relay limits it was
/// started with, and the inviter name it issues requested invitations under.
struct ActiveContribution {
    relay: Option<RelayLimits>,
    inviter_name: String,
    task: JoinHandle<()>,
}

impl Drop for ActiveContribution {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Owner-side services and state with which a node other than the owner
/// advertising node answers requests for this device's own groups.
#[derive(Clone)]
struct OwnerRequestHandlers {
    join_authorizer: Arc<dyn JoinRequestAuthorizer>,
    member_admission: Arc<dyn MemberAdmissionService>,
    synchronization: Arc<dyn SynchronizationService>,
    invite_requests: Arc<dyn InviteRequestService>,
    owner_addresses: Arc<std::sync::Mutex<Vec<Multiaddr>>>,
    owner_peers: Arc<std::sync::Mutex<BTreeMap<PeerId, ConnectionPath>>>,
    last_connection: Arc<std::sync::Mutex<Option<ObservedConnection>>>,
}

/// Owner identity, with the inviter name of the invitations it issues, under
/// which the member serving node answers requests for this device's own
/// groups; it must hold the same key as the node's network identity.
pub struct OwnerAnswerIdentity {
    pub identity: DeviceIdentity,
    pub inviter_name: String,
}

pub struct NetworkService {
    /// Built-in and environment-configured bootstrap nodes.
    fixed_bootstrap_peers: Vec<BootstrapPeer>,
    /// Community bootstrap nodes added on this device (ADR-038).
    community_peers: std::sync::RwLock<Vec<BootstrapPeer>>,
    advertisement: Mutex<Option<ActiveAdvertisement>>,
    contribution: Mutex<Option<ActiveContribution>>,
    member_serving: Mutex<Option<ActiveMemberServing>>,
    /// Groups whose pinned owner announced new events (ADR-049).
    event_notices: broadcast::Sender<PeerId>,
    /// Owned groups with newly stored events, which the owner advertising
    /// node announces to connected current members (ADR-049).
    stored_events: broadcast::Sender<PeerId>,
    /// Latest observed connection path, shared with the owner advertising
    /// node so current members connecting to it count too.
    last_connection: Arc<std::sync::Mutex<Option<ObservedConnection>>>,
    group_connections: std::sync::Mutex<BTreeMap<PeerId, ObservedGroupSynchronization>>,
    join_authorizer: Arc<dyn JoinRequestAuthorizer>,
    member_admission: Arc<dyn MemberAdmissionService>,
    pending_join: Arc<dyn PendingJoinService>,
    synchronization: Arc<dyn SynchronizationService>,
    invite_requests: Arc<dyn InviteRequestService>,
    /// Current listen addresses of the owner advertising node, without the
    /// device peer ID, offered as invitation address hints (ADR-037).
    owner_addresses: Arc<std::sync::Mutex<Vec<Multiaddr>>>,
    /// Peers currently connected to the owner advertising node and their
    /// best connection path, from which owned groups report their state.
    owner_peers: Arc<std::sync::Mutex<BTreeMap<PeerId, ConnectionPath>>>,
    /// Whether owner and member nodes also use mDNS on the local network.
    lan_discovery: bool,
    /// Whether nodes also publish private and loopback listen addresses in
    /// provider records; only isolated local test networks set this.
    publish_private_addresses: bool,
    /// Routing peers recently reached by this device (ADR-046).
    routing_peers: Option<Arc<RoutingPeersService>>,
}

impl NetworkService {
    pub fn from_environment(
        join_authorizer: Arc<dyn JoinRequestAuthorizer>,
        member_admission: Arc<dyn MemberAdmissionService>,
        mls: Arc<MlsProviderService>,
        invite_requests: Arc<dyn InviteRequestService>,
    ) -> Result<Self, &'static str> {
        let environment = std::env::var(BOOTSTRAP_ENVIRONMENT_VARIABLE).unwrap_or_default();
        Self::from_sources_with_authorizer(
            BUILT_IN_BOOTSTRAP_ADDRESSES,
            &environment,
            join_authorizer,
            member_admission,
            mls.clone(),
            mls,
        )
        .map(|service| service.with_invite_requests(invite_requests))
    }

    /// Built-in, environment-configured and community bootstrap nodes, in
    /// that order.
    fn bootstrap_peers(&self) -> Vec<BootstrapPeer> {
        let community = self
            .community_peers
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.fixed_bootstrap_peers
            .iter()
            .chain(community.iter())
            .cloned()
            .collect()
    }

    /// Parses community node addresses validated by the stored preference,
    /// leaving out nodes the build or environment already configures, and
    /// refuses a list that would exceed the bootstrap node limit (ADR-038).
    pub fn community_peers(
        &self,
        addresses: &[String],
    ) -> Result<Vec<BootstrapPeer>, &'static str> {
        let mut peers: Vec<BootstrapPeer> = Vec::new();
        for address in addresses {
            let mut peer = parse_bootstrap_peer(address).map_err(|_| "community_node_invalid")?;
            peer.source = "community";
            let known = self
                .fixed_bootstrap_peers
                .iter()
                .chain(peers.iter())
                .any(|known| known.peer_id == peer.peer_id && known.address == peer.address);
            if !known {
                peers.push(peer);
            }
        }
        if self.fixed_bootstrap_peers.len() + peers.len() > MAX_BOOTSTRAP_PEERS {
            return Err("community_nodes_limit");
        }
        Ok(peers)
    }

    /// Sets the community nodes used by connections started from now on.
    pub fn replace_community_peers(&self, peers: Vec<BootstrapPeer>) {
        *self
            .community_peers
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = peers;
    }

    /// Uses the community nodes for new connections. The owner advertising
    /// provider stops so its next refresh bootstraps and reserves relays
    /// through the new list, and the contribution node stops so the caller
    /// restarts it from the stored preference through the new list.
    pub async fn use_community_peers(&self, peers: Vec<BootstrapPeer>) {
        self.replace_community_peers(peers);
        if let Some(existing) = self.advertisement.lock().await.take() {
            existing.task.abort();
        }
        self.contribution.lock().await.take();
        clear_owner_addresses(&self.owner_addresses);
        clear_owner_peers(&self.owner_peers);
    }

    /// Remembers routing peers reached by client nodes and uses them as extra
    /// entry points when such nodes start (ADR-046).
    pub fn with_routing_peers(mut self, routing_peers: Arc<RoutingPeersService>) -> Self {
        self.routing_peers = Some(routing_peers);
        self
    }

    /// Remembered routing peers that are not configured bootstrap nodes, most
    /// recently reached first.
    fn remembered_entry_points(&self) -> Vec<BootstrapPeer> {
        let Some(routing_peers) = &self.routing_peers else {
            return Vec::new();
        };
        let configured = self.bootstrap_peers();
        routing_peers
            .remembered()
            .iter()
            .filter_map(|address| parse_bootstrap_peer(address).ok())
            .filter(|peer| !configured.iter().any(|known| known.peer_id == peer.peer_id))
            .collect()
    }

    /// Adds remembered routing peers as DHT entry points after the configured
    /// bootstrap nodes and records the routing peers this client node reaches.
    /// Remembered peers are never used for relay reservations (ADR-046).
    fn use_remembered_routing_peers(&self, node: &mut NetworkNode) {
        let Some(routing_peers) = &self.routing_peers else {
            return;
        };
        for peer in self.remembered_entry_points() {
            node.add_bootstrap_peer(peer.peer_id, peer.address);
        }
        let routing_peers = routing_peers.clone();
        node.observe_routing_peers(Box::new(move |peer_id, address| {
            let _ = routing_peers.record(peer_id, address);
        }));
    }

    /// Lets the owner advertising node answer member invite requests.
    fn with_invite_requests(mut self, invite_requests: Arc<dyn InviteRequestService>) -> Self {
        self.invite_requests = invite_requests;
        self
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
            fixed_bootstrap_peers: bootstrap_peers,
            community_peers: std::sync::RwLock::new(Vec::new()),
            advertisement: Mutex::new(None),
            contribution: Mutex::new(None),
            member_serving: Mutex::new(None),
            event_notices: broadcast::channel(EVENT_NOTICE_CAPACITY).0,
            stored_events: broadcast::channel(EVENT_NOTICE_CAPACITY).0,
            last_connection: Arc::new(std::sync::Mutex::new(None)),
            group_connections: std::sync::Mutex::new(BTreeMap::new()),
            join_authorizer,
            member_admission,
            pending_join,
            synchronization,
            invite_requests: Arc::new(RejectingInviteRequestService),
            owner_addresses: Arc::new(std::sync::Mutex::new(Vec::new())),
            owner_peers: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
            lan_discovery: true,
            publish_private_addresses: false,
            routing_peers: None,
        })
    }

    /// Returns the address hints for invitations issued by this owner
    /// device: the advertising node's current addresses, relayed ones first.
    /// Empty while the owner is not advertising.
    pub fn owner_address_hints(&self) -> Vec<Multiaddr> {
        self.owner_addresses
            .lock()
            .map(|addresses| select_address_hints(&addresses))
            .unwrap_or_default()
    }

    fn owner_request_handlers(&self) -> OwnerRequestHandlers {
        OwnerRequestHandlers {
            join_authorizer: Arc::clone(&self.join_authorizer),
            member_admission: Arc::clone(&self.member_admission),
            synchronization: Arc::clone(&self.synchronization),
            invite_requests: Arc::clone(&self.invite_requests),
            owner_addresses: Arc::clone(&self.owner_addresses),
            owner_peers: Arc::clone(&self.owner_peers),
            last_connection: Arc::clone(&self.last_connection),
        }
    }

    /// Returns the address hints for a new invitation of this owner device.
    /// When the owner advertising node is not running yet, as for the first
    /// invitation, it starts with the retained `keys` (possibly none) and
    /// waits up to `OWNER_HINT_WAIT` for a relay circuit address, so even that
    /// invitation carries hints. Empty when no bootstrap node is configured or
    /// the node could not start; the invitation then relies on the DHT.
    pub async fn prepare_owner_address_hints(
        &self,
        network_identity: DeviceIdentity,
        owner_identity: DeviceIdentity,
        inviter_name: String,
        keys: Vec<DiscoveryKey>,
    ) -> Vec<Multiaddr> {
        let running = self
            .advertisement
            .lock()
            .await
            .as_ref()
            .is_some_and(|active| !active.task.is_finished());
        if running || network_identity.peer_id() != owner_identity.peer_id() {
            return self.owner_address_hints();
        }
        match self
            .advertise_keys(network_identity, owner_identity, inviter_name, keys, None)
            .await
        {
            Ok(result) if result.status == "advertising" => {}
            _ => return Vec::new(),
        }
        let deadline = Instant::now() + OWNER_HINT_WAIT;
        loop {
            let hints = self.owner_address_hints();
            let relayed = hints
                .iter()
                .any(|hint| hint.iter().any(|protocol| protocol == Protocol::P2pCircuit));
            if relayed || Instant::now() >= deadline {
                return hints;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Builds the short-lived client node used to advertise or reach a group
    /// provider.
    fn group_client_node(&self, identity: DeviceIdentity) -> NetworkNode {
        let keypair = identity.into_network_keypair();
        let node = if self.lan_discovery {
            NetworkNode::new_with_lan_discovery(keypair)
        } else {
            NetworkNode::new(keypair)
        };
        if self.publish_private_addresses {
            node.publishing_private_addresses()
        } else {
            node
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
            invitation.inviter_name().to_owned(),
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
        let (advertising_status, advertised_discovery_keys) = if self.bootstrap_peers().is_empty() {
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
                .bootstrap_peers()
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
            remember_connection(&self.last_connection, connection_type);
        }
        result
    }

    /// Remembers the outcome of the latest synchronization attempt for a
    /// group: online (direct or LAN), relayed, offline when the network is
    /// unavailable, bootstrapRequired when no bootstrap node or address hint
    /// could reach the group peer, and waiting when the group peer could not
    /// be reached yet.
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
            Err("network_bootstrap_required") => "bootstrapRequired",
            Err(_) => "waiting",
        };
        self.remember_group_state(group_id, state, discovery);
        result
    }

    /// Remembers the outcome of a member-served pull made while the owner was
    /// unreachable (ADR-040): a pull reports "memberServed" separately from an
    /// owner synchronization, a network failure reports offline, and other
    /// failures keep the state observed for the owner attempt.
    fn observe_member_pull<T>(
        &self,
        group_id: PeerId,
        result: Result<T, &'static str>,
    ) -> Result<T, &'static str> {
        match &result {
            Ok(_) => self.remember_group_state(group_id, "memberServed", None),
            Err("network_unavailable") => self.remember_group_state(group_id, "offline", None),
            Err(_) => {}
        }
        result
    }

    fn remember_group_state(
        &self,
        group_id: PeerId,
        state: &'static str,
        discovery: Option<&'static str>,
    ) {
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

    /// Reports the connection state of each owned group from the owner
    /// advertising node: whether it runs and which current members are
    /// connected to it now. A node that cannot start for lack of bootstrap
    /// nodes reports that instead of offline.
    pub async fn owned_group_connection_states(
        &self,
        group_ids: &[PeerId],
    ) -> Vec<GroupConnectionState> {
        let serving = self
            .advertisement
            .lock()
            .await
            .as_ref()
            .is_some_and(|active| !active.task.is_finished());
        let bootstrap_required = !serving && self.bootstrap_peers().is_empty();
        let connected = self
            .owner_peers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let observed_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        group_ids
            .iter()
            .map(|group_id| {
                // The advertising node never connects to its own device.
                let members = self.synchronization.notice_recipients(*group_id);
                GroupConnectionState {
                    group_id: group_id.to_string(),
                    state: if bootstrap_required {
                        "bootstrapRequired"
                    } else {
                        owned_group_state(serving, &members, &connected)
                    },
                    discovery: None,
                    observed_at_unix,
                }
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
        } else if self.bootstrap_peers().is_empty() {
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

    /// `inviter_name` is the owner device name placed in invitations issued
    /// at a permitted member's request.
    pub async fn advertise_owner_group(
        &self,
        network_identity: DeviceIdentity,
        owner_identity: DeviceIdentity,
        inviter_name: String,
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
        self.advertise_keys(network_identity, owner_identity, inviter_name, keys, None)
            .await
    }

    async fn advertise_keys(
        &self,
        network_identity: DeviceIdentity,
        owner_identity: DeviceIdentity,
        inviter_name: String,
        mut keys: Vec<DiscoveryKey>,
        expires_at_unix: Option<u64>,
    ) -> Result<AdvertisementResult, &'static str> {
        keys.dedup();
        // Only an owner preparing its first invitation's hints starts the
        // provider without keys; a bearer advertisement always has one.
        if keys.is_empty() && expires_at_unix.is_some() {
            return Err("owner_discovery_key_missing");
        }
        if keys.len() > MAX_OWNER_DISCOVERY_KEYS {
            return Err("owner_discovery_record_invalid");
        }
        if let Some(expiry) = expires_at_unix {
            remaining_until_expiry(expiry)?;
        }
        let reported_expiry = expires_at_unix.unwrap_or(0);
        if self.bootstrap_peers().is_empty() {
            return Ok(AdvertisementResult {
                status: "bootstrapRequired",
                expires_at_unix: reported_expiry,
            });
        }

        let mut active = self.advertisement.lock().await;
        if let Some(existing) = active.as_mut() {
            let same_provider = existing.expires_at_unix == expires_at_unix
                && existing.owner == owner_identity.peer_id()
                && existing.inviter_name == inviter_name
                && !existing.task.is_finished();
            if same_provider && existing.keys == keys {
                return Ok(AdvertisementResult {
                    status: "advertising",
                    expires_at_unix: existing.expires_at_unix.unwrap_or(0),
                });
            }
            // Newly issued keys join the running provider so connected members
            // and relay reservations survive; only a bearer-bound advertisement
            // restarts, as its expiry ends the task.
            if same_provider
                && expires_at_unix.is_none()
                && existing.key_updates.send(keys.clone()).is_ok()
            {
                existing.keys = keys;
                return Ok(AdvertisementResult {
                    status: "advertising",
                    expires_at_unix: 0,
                });
            }
        }
        if let Some(existing) = active.take() {
            existing.task.abort();
        }
        clear_owner_addresses(&self.owner_addresses);
        clear_owner_peers(&self.owner_peers);

        // The owner device also answers mDNS so members on the same local
        // network can reach it without a relay.
        let mut node = self.group_client_node(network_identity);
        listen_on_all_interfaces(&mut node)?;
        for bootstrap in &self.bootstrap_peers() {
            node.add_bootstrap_peer(bootstrap.peer_id, bootstrap.address.clone());
            node.reserve_relay(bootstrap.peer_id, bootstrap.address.clone())
                .map_err(|_| "network_unavailable")?;
        }
        self.use_remembered_routing_peers(&mut node);
        node.bootstrap().map_err(|_| "network_unavailable")?;
        for key in &keys {
            node.announce_group(*key)
                .map_err(|_| "network_unavailable")?;
        }

        // Subscribing before the announcement window keeps notices for
        // events stored while it runs (ADR-049).
        let mut stored_events = self.stored_events.subscribe();
        let announced = timeout(PROVIDER_SEARCH_TIMEOUT, async {
            let mut pending = keys.clone();
            if pending.is_empty() {
                return Ok(());
            }
            loop {
                let event = tokio::select! {
                    stored = stored_events.recv() => {
                        // Missed notices only delay members to their next retry.
                        if let Ok(group_id) = stored {
                            send_event_notices(
                                &mut node,
                                self.synchronization.as_ref(),
                                group_id,
                                None,
                            );
                        }
                        continue;
                    }
                    event = node.next_event() => event,
                };
                match event {
                    NetworkEvent::Listening { address } => {
                        record_owner_address(&self.owner_addresses, address);
                    }
                    NetworkEvent::ListenAddressesExpired { addresses } => {
                        forget_owner_addresses(&self.owner_addresses, addresses);
                    }
                    NetworkEvent::PeerConnected { peer_id, path, .. } => {
                        record_owner_peer(&self.owner_peers, peer_id, path);
                    }
                    NetworkEvent::PeerDisconnected { peer_id } if !node.is_connected(peer_id) => {
                        forget_owner_peer(&self.owner_peers, peer_id);
                    }
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
                    } => answer_owner_sync_request(
                        &mut node,
                        self.synchronization.as_ref(),
                        &self.last_connection,
                        &self.owner_peers,
                        peer_id,
                        request_id,
                        &request,
                    ),
                    NetworkEvent::JoinRequestReceived {
                        peer_id,
                        request_id,
                        request,
                    } => answer_owner_join_request(
                        &mut node,
                        self.join_authorizer.as_ref(),
                        self.member_admission.as_ref(),
                        self.synchronization.as_ref(),
                        &owner_identity,
                        peer_id,
                        request_id,
                        &request,
                    ),
                    NetworkEvent::InviteRequestReceived {
                        peer_id,
                        request_id,
                        request,
                    } => {
                        let response = self.invite_requests.answer_invite_request(
                            owner_identity.peer_id(),
                            &inviter_name,
                            peer_id,
                            &request,
                            &self.owner_address_hints(),
                        );
                        let _ = node.send_invite_response(request_id, response);
                    }
                    _ => {}
                }
            }
        })
        .await
        .map_err(|_| "network_advertisement_timed_out")
        .and_then(|announced| announced)
        .and_then(|()| {
            expires_at_unix.map_or(Ok(()), |expiry| remaining_until_expiry(expiry).map(|_| ()))
        });
        if let Err(error) = announced {
            clear_owner_addresses(&self.owner_addresses);
            clear_owner_peers(&self.owner_peers);
            return Err(error);
        }

        let join_authorizer = Arc::clone(&self.join_authorizer);
        let member_admission = Arc::clone(&self.member_admission);
        let synchronization = Arc::clone(&self.synchronization);
        let invite_requests = Arc::clone(&self.invite_requests);
        let owner_addresses = Arc::clone(&self.owner_addresses);
        let owner_peers = Arc::clone(&self.owner_peers);
        let last_connection = Arc::clone(&self.last_connection);
        let mut task_keys = keys.clone();
        let owner_identity_peer = owner_identity.peer_id();
        let (key_updates, mut updated_keys) = mpsc::unbounded_channel::<Vec<DiscoveryKey>>();
        let task_inviter_name = inviter_name.clone();
        let task = tokio::spawn(async move {
            let inviter_name = task_inviter_name;
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
                    stored = stored_events.recv() => match stored {
                        Ok(group_id) => {
                            send_event_notices(&mut node, synchronization.as_ref(), group_id, None);
                        }
                        // Missed notices only delay members to their next retry.
                        Err(broadcast::error::RecvError::Lagged(_)) => {}
                        Err(broadcast::error::RecvError::Closed) => break,
                    },
                    _ = refresh.tick() => {
                        if task_keys.iter().any(|key| node.announce_group(*key).is_err()) {
                            break;
                        }
                    }
                    Some(keys) = updated_keys.recv() => {
                        if !update_announced_keys(&mut node, &mut task_keys, keys) {
                            break;
                        }
                    }
                    event = node.next_event() => {
                        match event {
                            NetworkEvent::DiscoveryFailed {
                                key: failed,
                                operation: charp2p_network::DiscoveryOperation::Announcement,
                            } if task_keys.contains(&failed) => break,
                            NetworkEvent::Listening { address } => {
                                record_owner_address(&owner_addresses, address);
                            }
                            NetworkEvent::ListenAddressesExpired { addresses } => {
                                forget_owner_addresses(&owner_addresses, addresses);
                            }
                            NetworkEvent::PeerConnected { peer_id, path, .. } => {
                                record_owner_peer(&owner_peers, peer_id, path);
                            }
                            NetworkEvent::PeerDisconnected { peer_id }
                                if !node.is_connected(peer_id) =>
                            {
                                forget_owner_peer(&owner_peers, peer_id);
                            }
                            NetworkEvent::SyncRequestReceived {
                                peer_id,
                                request_id,
                                request,
                            } => answer_owner_sync_request(
                                &mut node,
                                synchronization.as_ref(),
                                &last_connection,
                                &owner_peers,
                                peer_id,
                                request_id,
                                &request,
                            ),
                            NetworkEvent::JoinRequestReceived {
                                peer_id,
                                request_id,
                                request,
                            } => answer_owner_join_request(
                                &mut node,
                                join_authorizer.as_ref(),
                                member_admission.as_ref(),
                                synchronization.as_ref(),
                                &owner_identity,
                                peer_id,
                                request_id,
                                &request,
                            ),
                            NetworkEvent::InviteRequestReceived {
                                peer_id,
                                request_id,
                                request,
                            } => {
                                let hints = owner_addresses
                                    .lock()
                                    .map(|addresses| select_address_hints(&addresses))
                                    .unwrap_or_default();
                                let response = invite_requests.answer_invite_request(
                                    owner_identity.peer_id(),
                                    &inviter_name,
                                    peer_id,
                                    &request,
                                    &hints,
                                );
                                let _ = node.send_invite_response(request_id, response);
                            }
                            _ => {}
                        }
                    }
                }
            }
            clear_owner_addresses(&owner_addresses);
            clear_owner_peers(&owner_peers);
        });
        *active = Some(ActiveAdvertisement {
            keys,
            expires_at_unix,
            owner: owner_identity_peer,
            inviter_name,
            key_updates,
            task,
        });
        Ok(AdvertisementResult {
            status: "advertising",
            expires_at_unix: reported_expiry,
        })
    }

    /// Runs the opted-in contribution node (ADR-031) in Kademlia server mode
    /// with the given relay limits, restarting it only when the limits or the
    /// inviter name change. It shares the device peer ID, so members and
    /// joiners of this device's own groups may reach it instead of the owner
    /// advertising node; their requests get the owner answers, and requests
    /// for any other group are rejected, as routing nodes do.
    pub async fn start_contribution(
        &self,
        network_identity: DeviceIdentity,
        owner_identity: DeviceIdentity,
        inviter_name: String,
        relay: Option<RelayLimits>,
    ) -> Result<&'static str, &'static str> {
        if network_identity.peer_id() != owner_identity.peer_id() {
            return Err("invitation_inviter_mismatch");
        }
        let status = if relay.is_some() {
            "routingAndRelay"
        } else {
            "routing"
        };
        let mut active = self.contribution.lock().await;
        if self.bootstrap_peers().is_empty() {
            active.take();
            return Ok("bootstrapRequired");
        }
        if let Some(existing) = active.as_ref() {
            if existing.relay == relay
                && existing.inviter_name == inviter_name
                && !existing.task.is_finished()
            {
                return Ok(status);
            }
        }
        active.take();

        let mut node =
            NetworkNode::new_contributing(network_identity.into_network_keypair(), relay);
        listen_on_all_interfaces(&mut node)?;
        for bootstrap in &self.bootstrap_peers() {
            node.add_bootstrap_peer(bootstrap.peer_id, bootstrap.address.clone());
        }
        node.bootstrap().map_err(|_| "network_unavailable")?;

        let owner = self.owner_request_handlers();
        let task_inviter_name = inviter_name.clone();
        let task = tokio::spawn(async move {
            let inviter_name = task_inviter_name;
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
                    event = node.next_event() => answer_contribution_event(
                        &mut node,
                        event,
                        &owner,
                        &owner_identity,
                        &inviter_name,
                    ),
                }
            }
        });
        *active = Some(ActiveContribution {
            relay,
            inviter_name,
            task,
        });
        Ok(status)
    }

    /// Stops the contribution node, if one is running.
    pub async fn stop_contribution(&self) {
        self.contribution.lock().await.take();
    }

    /// Tells the connected current members of an owned group that this
    /// owner device stored new events, so they pull now (ADR-049). Members
    /// that are not connected still pull at their next retry.
    pub fn notify_group_events(&self, group_id: PeerId) {
        // No running advertising node only means nobody is connected.
        let _ = self.stored_events.send(group_id);
    }

    /// Subscribes to the groups whose pinned owner sent an acknowledged
    /// new-event notice to the member serving node (ADR-049).
    pub fn subscribe_event_notices(&self) -> broadcast::Receiver<PeerId> {
        self.event_notices.subscribe()
    }

    /// Advertises the member rendezvous key of a joined group's current MLS
    /// epoch and serves pull-only synchronization to current members
    /// (ADR-040). The node restarts only when the group or key changes, so
    /// calling this again after a synchronization re-advertises once the
    /// epoch advanced. Served bytes are charged to `bandwidth`. The node
    /// also keeps a connection to the pinned `owner`, dialled at its
    /// remembered `owner_addresses` and redialled after it closes, over
    /// which the owner sends new-event notices (ADR-049). Without bootstrap
    /// nodes the node still keeps that owner connection at the remembered
    /// addresses but cannot advertise the key, and reports bootstrapRequired.
    /// LAN discovery announces the device peer ID from this node too, so
    /// requests for groups this device owns get the owner answers under
    /// `own`, uncounted (ADR-033).
    #[allow(clippy::too_many_arguments)]
    pub async fn serve_member_group(
        &self,
        network_identity: DeviceIdentity,
        own: OwnerAnswerIdentity,
        group_id: PeerId,
        key: DiscoveryKey,
        owner: PeerId,
        owner_addresses: Vec<Multiaddr>,
        bandwidth: Arc<BandwidthService>,
    ) -> Result<&'static str, &'static str> {
        if network_identity.peer_id() != own.identity.peer_id() {
            return Err("invitation_inviter_mismatch");
        }
        let mut active = self.member_serving.lock().await;
        let bootstrap_peers = self.bootstrap_peers();
        let advertised = !bootstrap_peers.is_empty();
        let status = if advertised {
            "advertising"
        } else {
            "bootstrapRequired"
        };
        // Without bootstrap nodes only remembered owner addresses can be
        // dialled.
        if !advertised && owner_addresses.is_empty() {
            active.take();
            return Ok(status);
        }
        if let Some(existing) = active.as_ref() {
            if existing.group_id == group_id
                && existing.key == key
                && existing.advertised == advertised
                && existing.inviter_name == own.inviter_name
                && !existing.task.is_finished()
            {
                return Ok(status);
            }
        }
        active.take();

        let mut node = self.group_client_node(network_identity);
        listen_on_all_interfaces(&mut node)?;
        for bootstrap in &bootstrap_peers {
            node.add_bootstrap_peer(bootstrap.peer_id, bootstrap.address.clone());
            node.reserve_relay(bootstrap.peer_id, bootstrap.address.clone())
                .map_err(|_| "network_unavailable")?;
        }

        let synchronization = Arc::clone(&self.synchronization);
        let notices = self.event_notices.clone();
        let handlers = self.owner_request_handlers();
        let inviter_name = own.inviter_name.clone();
        let (lend, mut lend_requests) = mpsc::channel::<oneshot::Sender<LentOwnerConnection>>(4);
        if advertised {
            self.use_remembered_routing_peers(&mut node);
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
                        event => answer_member_node_event(
                            &mut node,
                            event,
                            synchronization.as_ref(),
                            &bandwidth,
                            &notices,
                            &handlers,
                            &own,
                        ),
                    }
                }
            })
            .await
            .map_err(|_| "network_advertisement_timed_out")??;
        }

        let task = tokio::spawn(async move {
            let mut refresh = interval_at(
                Instant::now() + ADVERTISEMENT_REFRESH_INTERVAL,
                ADVERTISEMENT_REFRESH_INTERVAL,
            );
            refresh.set_missed_tick_behavior(MissedTickBehavior::Skip);
            // The first tick dials the owner at once; later ticks redial only
            // while no connection to it is open.
            let mut redial = interval(OWNER_REDIAL_INTERVAL);
            redial.set_missed_tick_behavior(MissedTickBehavior::Skip);
            // Path and address of the open connection to the owner.
            let mut owner_connection: Option<(ConnectionPath, Multiaddr)> = None;
            loop {
                tokio::select! {
                    _ = refresh.tick(), if advertised => {
                        if node.announce_group(key).is_err() {
                            break;
                        }
                    }
                    Some(reply) = lend_requests.recv() => {
                        // Without an open owner connection the dropped reply
                        // sends the synchronization to a fresh dial.
                        let Some((path, address)) = owner_connection
                            .clone()
                            .filter(|_| node.is_connected(owner))
                        else {
                            continue;
                        };
                        let (returns, returned) = oneshot::channel();
                        // A refused reply drops the lent node, which returns it.
                        let _ = reply.send(LentOwnerConnection {
                            node: Some(node),
                            path,
                            address,
                            returns: Some(returns),
                        });
                        // Requests from other members wait or fail while the
                        // node is lent; they retry at their next pull.
                        let Ok(returned) = returned.await else {
                            break;
                        };
                        node = returned;
                        if !node.is_connected(owner) {
                            owner_connection = None;
                        }
                    }
                    _ = redial.tick(), if owner_connection.is_none() => {
                        // An unreachable owner is retried at the next tick;
                        // scheduled pulls still deliver its events.
                        let _ = if owner_addresses.is_empty() {
                            node.dial_peer(owner)
                        } else {
                            node.dial_peer_at(owner, owner_addresses.clone())
                        };
                    }
                    event = node.next_event() => match event {
                        NetworkEvent::DiscoveryFailed {
                            key: failed,
                            operation: charp2p_network::DiscoveryOperation::Announcement,
                        } if failed == key => break,
                        NetworkEvent::PeerConnected {
                            peer_id,
                            path,
                            remote_address,
                        } if peer_id == owner => {
                            owner_connection = Some((path, remote_address));
                        }
                        NetworkEvent::PeerDisconnected { peer_id } if peer_id == owner => {
                            owner_connection = None;
                        }
                        NetworkEvent::DirectConnectionUpgraded { peer_id } if peer_id == owner => {
                            if let Some((path, _)) = owner_connection.as_mut() {
                                *path = ConnectionPath::Direct;
                            }
                        }
                        event => answer_member_node_event(
                            &mut node,
                            event,
                            synchronization.as_ref(),
                            &bandwidth,
                            &notices,
                            &handlers,
                            &own,
                        ),
                    },
                }
            }
        });
        *active = Some(ActiveMemberServing {
            group_id,
            key,
            owner,
            advertised,
            inviter_name,
            lend,
            task,
        });
        Ok(status)
    }

    /// Borrows the member serving node of `group_id` while it holds an
    /// authenticated connection to the pinned `owner`, so synchronization
    /// reuses that connection before dialing (technical-design Connectivity
    /// order 1).
    async fn lend_owner_connection(
        &self,
        group_id: PeerId,
        owner: PeerId,
    ) -> Option<LentOwnerConnection> {
        let lend = {
            let active = self.member_serving.lock().await;
            let serving = active.as_ref().filter(|serving| {
                serving.group_id == group_id
                    && serving.owner == owner
                    && !serving.task.is_finished()
            })?;
            serving.lend.clone()
        };
        let (reply, lent) = oneshot::channel();
        lend.send(reply).await.ok()?;
        lent.await.ok()
    }

    /// Stops the member serving node, if one is running.
    pub async fn stop_member_serving(&self) {
        self.member_serving.lock().await.take();
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
        if invitation.inviter_device_id() == identity.peer_id() {
            return Err("invitation_inviter_mismatch");
        }
        // The raw dial outcome is observed before it becomes a preview
        // status, so dial failures show as offline like join and sync do.
        let dialed = self.search_providers(identity, invitation).await;
        search_result(self.observe_connection(dialed, |path| Some(connection_type_name(*path))))
    }

    async fn search_providers(
        &self,
        identity: DeviceIdentity,
        invitation: &Invitation,
    ) -> Result<ConnectionPath, &'static str> {
        // The preview reaches the pinned inviter the way the join does:
        // address hints first (ADR-037), then the DHT lookup with an mDNS
        // announcement dialed alongside it; the transport authenticates the
        // inviter on every path.
        let hints = pinned_address_hints(invitation);
        let result = self
            .dial_group_provider(
                identity,
                DiscoveryKey::from_invitation(invitation),
                invitation.inviter_device_id(),
                &hints,
            )
            .await;
        result.map(|connection| connection.path)
    }

    pub async fn join(
        &self,
        identity: DeviceIdentity,
        invitation: &Invitation,
    ) -> Result<JoinGroupResult, &'static str> {
        let hints = pinned_address_hints(invitation);
        if self.bootstrap_peers().is_empty() && hints.is_empty() {
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
        let ProviderConnection {
            mut node, address, ..
        } = self
            .connect_to_group_provider(identity, key, expected_inviter, &hints)
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
                JoinRejectReason::AwaitingApproval => "join_awaiting_approval",
                JoinRejectReason::GroupFull => "join_group_full",
            });
        }
        let welcome = response.welcome().ok_or("network_join_failed")?;
        self.pending_join
            .complete_join(invitation.group_id(), welcome)?;
        let reached_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system_clock_invalid")?
            .as_secs();
        let pulled = self
            .pull_from_connected_peer(
                &mut node,
                expected_inviter,
                invitation.group_id(),
                None,
                &mut ConnectionPath::Direct,
            )
            .await;
        let synchronized_at_unix = match pulled {
            Ok(_) => Some(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|_| "system_clock_invalid")?
                    .as_secs(),
            ),
            Err(_) => None,
        };
        Ok(JoinGroupResult {
            status: "joined",
            group_id: invitation.group_id().to_string(),
            synchronized_events: pulled.map_or(0, |(inserted, _)| inserted),
            synchronized_at_unix,
            peer_address: address,
            reached_at_unix,
        })
    }

    /// Asks the pinned owner device for an invitation this member device
    /// may share (ADR-036) and verifies the owner's answer.
    pub async fn request_member_invitation(
        &self,
        identity: DeviceIdentity,
        key: DiscoveryKey,
        group_id: PeerId,
        owner_device_id: PeerId,
        known_addresses: &[Multiaddr],
        lifetime_seconds: u32,
    ) -> Result<IssuedInvitation, &'static str> {
        if identity.peer_id() == owner_device_id {
            return Err("invitation_inviter_mismatch");
        }
        let request =
            InviteRequest::new(group_id, lifetime_seconds).map_err(|_| "invite_request_invalid")?;
        // The member serving node's open owner connection is reused before
        // dialing (technical-design Connectivity order 1).
        let mut lent = self.lend_owner_connection(group_id, owner_device_id).await;
        let mut dialed = None;
        let node = match lent.as_mut() {
            Some(lent) => lent.node(),
            None => {
                let ProviderConnection { node, .. } = self
                    .connect_to_group_provider(identity, key, owner_device_id, known_addresses)
                    .await?;
                dialed.insert(node)
            }
        };
        let request_id = node.send_invite_request(owner_device_id, request);
        let response = timeout(JOIN_RESPONSE_TIMEOUT, async {
            loop {
                match node.next_event().await {
                    NetworkEvent::InviteResponseReceived {
                        peer_id,
                        request_id: received_id,
                        response,
                    } if peer_id == owner_device_id && received_id == request_id => {
                        return Ok(response);
                    }
                    NetworkEvent::InviteRequestFailed {
                        peer_id,
                        request_id: failed_id,
                        ..
                    } if peer_id == owner_device_id && failed_id == request_id => {
                        return Err("network_invite_failed");
                    }
                    _ => {}
                }
            }
        })
        .await
        .map_err(|_| "network_invite_timed_out")??;
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "system_clock_invalid")?
            .as_secs();
        requested_invitation(&response, group_id, owner_device_id, now_unix)
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
        let mut lent = self.lend_owner_connection(group_id, expected_peer).await;
        let mut dialed = None;
        let (node, mut connection_path, peer_address) = match lent.as_mut() {
            // The member serving node's open owner connection is reused; no
            // discovery record is looked up.
            Some(lent) => {
                let path = lent.path;
                let address = lent.address.clone();
                let _ = self.observe_connection(Ok(path), |path| Some(connection_type_name(*path)));
                (lent.node(), path, address)
            }
            None => {
                let connected = self
                    .connect_to_group_provider(identity, key, expected_peer, known_addresses)
                    .await;
                // A remembered address says nothing about the discovery record.
                *discovery = match &connected {
                    Ok(connection) if !connection.looked_up => None,
                    _ => discovery_outcome(&connected),
                };
                let ProviderConnection {
                    node,
                    path,
                    address,
                    ..
                } = connected?;
                (dialed.insert(node), path, address)
            }
        };
        // A relayed connection may be hole-punched while the exchange runs;
        // the remembered address stays the relayed one, which keeps working
        // after the NAT mapping of the direct connection expires.
        let initial_path = connection_path;
        let (synchronized_events, membership) = self
            .pull_from_connected_peer(
                node,
                expected_peer,
                group_id,
                Some(bandwidth),
                &mut connection_path,
            )
            .await?;
        let uploaded_events = self
            .push_to_connected_peer(
                node,
                expected_peer,
                group_id,
                local_peer,
                bandwidth,
                &mut connection_path,
            )
            .await?;
        self.exchange_observed_heads(
            node,
            expected_peer,
            group_id,
            local_peer,
            bandwidth,
            &mut connection_path,
        )
        .await?;
        if connection_path != initial_path {
            let _ = self.observe_connection(Ok(connection_path), |path| {
                Some(connection_type_name(*path))
            });
        }
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
            membership: membership.map(membership_comparison_name),
            peer_address,
        })
    }

    /// Pulls the group history from another current member while the pinned
    /// owner cannot be reached (ADR-040): searches the member rendezvous key
    /// of the current epoch and pulls from the first reachable provider in
    /// `members`, trying at most four. Uploads and head reports stay with the
    /// owner, so nothing is pushed. The outcome is remembered as the group's
    /// member-served connection state and the device's latest connection.
    pub async fn pull_from_members(
        &self,
        identity: DeviceIdentity,
        key: DiscoveryKey,
        group_id: PeerId,
        members: &[PeerId],
        bandwidth: &BandwidthService,
    ) -> Result<SynchronizeGroupResult, &'static str> {
        let result = self
            .pull_from_member_providers(identity, key, group_id, members, bandwidth)
            .await;
        let result = self.observe_connection(result, |pulled| Some(pulled.connection_type));
        self.observe_member_pull(group_id, result)
    }

    async fn pull_from_member_providers(
        &self,
        identity: DeviceIdentity,
        key: DiscoveryKey,
        group_id: PeerId,
        members: &[PeerId],
        bandwidth: &BandwidthService,
    ) -> Result<SynchronizeGroupResult, &'static str> {
        let local_peer = identity.peer_id();
        bandwidth.ensure_sync_budget()?;
        if self.bootstrap_peers().is_empty() {
            return Err("network_bootstrap_required");
        }
        let mut node = self.group_client_node(identity);
        listen_on_all_interfaces(&mut node)?;
        for bootstrap in &self.bootstrap_peers() {
            node.add_bootstrap_peer(bootstrap.peer_id, bootstrap.address.clone());
        }
        self.use_remembered_routing_peers(&mut node);
        node.bootstrap().map_err(|_| "network_unavailable")?;
        node.find_group_peers(key);

        // Providers connected while the search ran need no second dial.
        let mut connected = Vec::new();
        // Each Kademlia step may report other providers, so candidates are
        // collected until the search ends or the provider limit is reached.
        let mut candidates = MemberCandidates::new(local_peer, members);
        let searched = timeout(PROVIDER_SEARCH_TIMEOUT, async {
            loop {
                match node.next_event().await {
                    NetworkEvent::PeerConnected {
                        peer_id,
                        path,
                        remote_address,
                    } => connected.push((peer_id, path, remote_address)),
                    NetworkEvent::GroupPeersFound {
                        key: found_key,
                        providers,
                    } if found_key == key => {
                        if candidates.add(providers) {
                            return None;
                        }
                    }
                    NetworkEvent::GroupPeerSearchFinished { key: found_key }
                        if found_key == key =>
                    {
                        return Some("network_peer_not_found");
                    }
                    NetworkEvent::DiscoveryFailed {
                        key: failed_key, ..
                    } if failed_key == key => return Some("network_unavailable"),
                    _ => {}
                }
            }
        })
        .await
        .unwrap_or(Some("network_search_timed_out"));
        let candidates = candidates.finish(searched)?;

        let mut last_error = "network_peer_unreachable";
        for provider in candidates {
            let already_connected = connected
                .iter()
                .find(|(peer_id, _, _)| *peer_id == provider)
                .map(|(_, path, address)| (*path, address.clone()));
            let reached = match already_connected {
                Some(reached) => Some(reached),
                None if node.dial_peer(provider).is_ok() => timeout(CONNECT_TIMEOUT, async {
                    loop {
                        if let NetworkEvent::PeerConnected {
                            peer_id,
                            path,
                            remote_address,
                        } = node.next_event().await
                        {
                            if peer_id == provider {
                                break (path, remote_address);
                            }
                        }
                    }
                })
                .await
                .ok(),
                None => None,
            };
            let Some((mut path, peer_address)) = reached else {
                continue;
            };
            match self
                .pull_from_connected_peer(&mut node, provider, group_id, Some(bandwidth), &mut path)
                .await
            {
                Ok((synchronized_events, membership)) => {
                    return Ok(SynchronizeGroupResult {
                        status: "memberSynchronized",
                        group_id: group_id.to_string(),
                        synchronized_events,
                        uploaded_events: 0,
                        synchronized_at_unix: SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map_err(|_| "system_clock_invalid")?
                            .as_secs(),
                        connection_type: connection_type_name(path),
                        membership: membership.map(membership_comparison_name),
                        peer_address,
                    });
                }
                // Another member cannot lift the local data limit.
                Err(error @ "synchronization_bandwidth_limited") => return Err(error),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
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
        if self.bootstrap_peers().is_empty() && known_addresses.is_empty() {
            return Err("network_bootstrap_required");
        }
        let lan_deadline = Instant::now() + LAN_DISCOVERY_WINDOW;
        let mut node = self.group_client_node(identity);
        listen_on_all_interfaces(&mut node)?;
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
        if self.bootstrap_peers().is_empty() {
            return Err("network_bootstrap_required");
        }
        for bootstrap in &self.bootstrap_peers() {
            node.add_bootstrap_peer(bootstrap.peer_id, bootstrap.address.clone());
        }
        self.use_remembered_routing_peers(&mut node);
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
        path: &mut ConnectionPath,
    ) -> Result<(usize, Option<MembershipComparison>), &'static str> {
        let (mut session, mut request) = PullSession::start(group_id);
        let mut inserted = 0_usize;
        for _ in 0..MAX_SYNC_EXCHANGES {
            if let Some(bandwidth) = bandwidth {
                bandwidth.ensure_sync_budget()?;
            }
            let request_id = node
                .send_sync_request(peer_id, request)
                .map_err(|_| "synchronization_failed")?;
            let response = await_sync_response(node, peer_id, request_id, path).await?;
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
                return Ok((inserted, session.membership_comparison()));
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
        path: &mut ConnectionPath,
    ) -> Result<usize, &'static str> {
        // Events the peer already acknowledged are not uploaded or charged
        // again; it accepts the next upload only from its own stored head.
        let mut after_sequence = self
            .synchronization
            .acknowledged_head(group_id, peer_id, author_id)?;
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
            let request_id = send_push_request(node, peer_id, request, bandwidth)?;
            let response = await_sync_response(node, peer_id, request_id, path).await?;
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
        bandwidth: &BandwidthService,
        path: &mut ConnectionPath,
    ) -> Result<(), &'static str> {
        bandwidth.ensure_sync_budget()?;
        let request = self.synchronization.report_heads_request(group_id)?;
        let request_id = node
            .send_sync_request(peer_id, request)
            .map_err(|_| "synchronization_failed")?;
        let response = await_sync_response(node, peer_id, request_id, path).await?;
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

/// Whether an owner synchronization failed because the owner could not be
/// found or reached, so a member-served pull may help (ADR-040).
pub(crate) fn owner_unreachable(error: &str) -> bool {
    matches!(
        error,
        "network_peer_not_found" | "network_peer_unreachable" | "network_search_timed_out"
    )
}

/// Sends pushed events and charges them once sent, whatever the answer, so
/// a peer that never answers cannot lift the upload limit (ADR-033).
fn send_push_request(
    node: &mut NetworkNode,
    peer_id: PeerId,
    request: SyncRequest,
    bandwidth: &BandwidthService,
) -> Result<OutboundSyncRequestId, &'static str> {
    let pushed_bytes = request_event_bytes(&request);
    let request_id = node
        .send_sync_request(peer_id, request)
        .map_err(|_| "synchronization_failed")?;
    bandwidth.charge_sync_bytes(pushed_bytes);
    Ok(request_id)
}

/// Waits for the answer to one synchronization request. A relayed
/// connection to the peer hole-punched meanwhile (DCUtR) turns `path` direct.
async fn await_sync_response(
    node: &mut NetworkNode,
    peer_id: PeerId,
    request_id: OutboundSyncRequestId,
    path: &mut ConnectionPath,
) -> Result<SyncResponse, &'static str> {
    timeout(SYNC_RESPONSE_TIMEOUT, async {
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
                event => *path = upgraded_path(*path, &event, peer_id),
            }
        }
    })
    .await
    .map_err(|_| "synchronization_timed_out")?
}

/// Returns the connection path to `peer_id` after `event`: a relayed path
/// becomes direct once the peer's connection is hole-punched.
fn upgraded_path(path: ConnectionPath, event: &NetworkEvent, peer_id: PeerId) -> ConnectionPath {
    match event {
        NetworkEvent::DirectConnectionUpgraded {
            peer_id: upgraded_peer,
        } if path == ConnectionPath::Relayed && *upgraded_peer == peer_id => ConnectionPath::Direct,
        _ => path,
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

/// Answers a synchronization request on a member serving node (ADR-040):
/// served event bytes count toward the synchronization data limit, and the
/// request is answered `busy` once that budget is spent or unreadable.
/// Owner answers stay uncounted (ADR-033).
fn answer_member_sync_request(
    synchronization: &dyn SynchronizationService,
    bandwidth: &BandwidthService,
    authenticated_peer: PeerId,
    request: &SyncRequest,
) -> SyncResponse {
    if bandwidth.ensure_sync_budget().is_err() {
        return SyncResponse::Rejected {
            reason: SyncRejectReason::Busy,
        };
    }
    let response = synchronization.answer_sync_request(authenticated_peer, request);
    bandwidth.charge_sync_bytes(response_event_bytes(&response));
    response
}

/// Answers a synchronization request on the owner advertising node, records
/// the member connection unless the request was rejected, and notifies the
/// other connected members when it stored uploaded events (ADR-049).
fn answer_owner_sync_request(
    node: &mut NetworkNode,
    synchronization: &dyn SynchronizationService,
    last_connection: &std::sync::Mutex<Option<ObservedConnection>>,
    owner_peers: &std::sync::Mutex<BTreeMap<PeerId, ConnectionPath>>,
    peer_id: PeerId,
    request_id: InboundSyncRequestId,
    request: &SyncRequest,
) {
    let response = synchronization.answer_sync_request(peer_id, request);
    if !matches!(response, SyncResponse::Rejected { .. }) {
        record_member_connection(last_connection, owner_peers, peer_id);
    }
    let accepted = match response {
        SyncResponse::EventsAccepted { group_id, inserted } if inserted > 0 => Some(group_id),
        _ => None,
    };
    let _ = node.send_sync_response(request_id, response);
    // The uploader already holds the events it pushed.
    if let Some(group_id) = accepted {
        send_event_notices(node, synchronization, group_id, Some(peer_id));
    }
}

/// Answers a join request on the owner advertising node and, after an
/// admission, tells the existing connected members to pull its commit.
#[allow(clippy::too_many_arguments)]
fn answer_owner_join_request(
    node: &mut NetworkNode,
    join_authorizer: &dyn JoinRequestAuthorizer,
    member_admission: &dyn MemberAdmissionService,
    synchronization: &dyn SynchronizationService,
    owner_identity: &DeviceIdentity,
    peer_id: PeerId,
    request_id: InboundJoinRequestId,
    request: &JoinRequest,
) {
    let response = join_response(
        join_authorizer.authorize_join_request(request),
        member_admission,
        owner_identity,
        request,
        peer_id,
    );
    let admitted = response.welcome().is_some();
    let _ = node.send_join_response(request_id, response);
    // Existing members pull the admission commit; the new member starts from
    // its Welcome.
    if admitted {
        send_event_notices(node, synchronization, request.group_id(), Some(peer_id));
    }
}

/// Sends `EventsAvailable` for an owned group to its connected current
/// members other than `skip` (ADR-049). The owner never dials members for
/// a notice, and their acknowledgements need no handling.
fn send_event_notices(
    node: &mut NetworkNode,
    synchronization: &dyn SynchronizationService,
    group_id: PeerId,
    skip: Option<PeerId>,
) {
    let local = node.peer_id();
    for member in synchronization.notice_recipients(group_id) {
        if member != local && Some(member) != skip && node.is_connected(member) {
            let _ = node.send_sync_request(member, SyncRequest::EventsAvailable { group_id });
        }
    }
}

/// Handles an event on a member serving node: synchronization requests
/// get the metered member answer and acknowledged owner notices are
/// published to `notices`. Synchronization requests for groups this device
/// owns, and join and invitation requests, get the uncounted owner answers
/// under `own` (ADR-033), whose authorizers only admit or issue for owned
/// groups.
#[allow(clippy::too_many_arguments)]
fn answer_member_node_event(
    node: &mut NetworkNode,
    event: NetworkEvent,
    synchronization: &dyn SynchronizationService,
    bandwidth: &BandwidthService,
    notices: &broadcast::Sender<PeerId>,
    owner: &OwnerRequestHandlers,
    own: &OwnerAnswerIdentity,
) {
    match event {
        // New-event notices come from the pinned owner of a joined group.
        NetworkEvent::SyncRequestReceived {
            peer_id,
            request_id,
            request,
        } if !matches!(request, SyncRequest::EventsAvailable { .. })
            && owner
                .synchronization
                .owns_group(sync_request_group_id(&request)) =>
        {
            answer_owner_sync_request(
                node,
                owner.synchronization.as_ref(),
                &owner.last_connection,
                &owner.owner_peers,
                peer_id,
                request_id,
                &request,
            );
        }
        NetworkEvent::SyncRequestReceived {
            peer_id,
            request_id,
            request,
        } => {
            let response =
                answer_member_sync_request(synchronization, bandwidth, peer_id, &request);
            if let SyncResponse::Acknowledged { group_id } = response {
                // No subscriber only means no immediate pull is wanted.
                let _ = notices.send(group_id);
            }
            let _ = node.send_sync_response(request_id, response);
        }
        NetworkEvent::JoinRequestReceived {
            peer_id,
            request_id,
            request,
        } => answer_owner_join_request(
            node,
            owner.join_authorizer.as_ref(),
            owner.member_admission.as_ref(),
            owner.synchronization.as_ref(),
            &own.identity,
            peer_id,
            request_id,
            &request,
        ),
        NetworkEvent::InviteRequestReceived {
            peer_id,
            request_id,
            request,
        } => answer_handled_invite_request(
            node,
            owner,
            &own.identity,
            &own.inviter_name,
            peer_id,
            request_id,
            &request,
        ),
        _ => {}
    }
}

/// Handles an event on the contribution node (ADR-031): synchronization
/// requests for groups this device owns, and join and invitation requests,
/// get the owner answers, whose authorizers only admit or issue for owned
/// groups; synchronization requests for any other group are rejected. The
/// invitation hints are the owner advertising node's addresses.
fn answer_contribution_event(
    node: &mut NetworkNode,
    event: NetworkEvent,
    owner: &OwnerRequestHandlers,
    owner_identity: &DeviceIdentity,
    inviter_name: &str,
) {
    match event {
        NetworkEvent::SyncRequestReceived {
            peer_id,
            request_id,
            request,
        } => {
            if owner
                .synchronization
                .owns_group(sync_request_group_id(&request))
            {
                answer_owner_sync_request(
                    node,
                    owner.synchronization.as_ref(),
                    &owner.last_connection,
                    &owner.owner_peers,
                    peer_id,
                    request_id,
                    &request,
                );
            } else {
                let _ = node.reject_sync_request(request_id, SyncRejectReason::Unauthorized);
            }
        }
        NetworkEvent::JoinRequestReceived {
            peer_id,
            request_id,
            request,
        } => answer_owner_join_request(
            node,
            owner.join_authorizer.as_ref(),
            owner.member_admission.as_ref(),
            owner.synchronization.as_ref(),
            owner_identity,
            peer_id,
            request_id,
            &request,
        ),
        NetworkEvent::InviteRequestReceived {
            peer_id,
            request_id,
            request,
        } => answer_handled_invite_request(
            node,
            owner,
            owner_identity,
            inviter_name,
            peer_id,
            request_id,
            &request,
        ),
        _ => {}
    }
}

/// Answers an invitation request on a node other than the owner advertising
/// node through the owner invite service; the invitation hints are the
/// owner advertising node's addresses.
fn answer_handled_invite_request(
    node: &mut NetworkNode,
    owner: &OwnerRequestHandlers,
    owner_identity: &DeviceIdentity,
    inviter_name: &str,
    peer_id: PeerId,
    request_id: InboundInviteRequestId,
    request: &InviteRequest,
) {
    let hints = owner
        .owner_addresses
        .lock()
        .map(|addresses| select_address_hints(&addresses))
        .unwrap_or_default();
    let response = owner.invite_requests.answer_invite_request(
        owner_identity.peer_id(),
        inviter_name,
        peer_id,
        request,
        &hints,
    );
    let _ = node.send_invite_response(request_id, response);
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
            Ok(_) => {
                match member_admission.admit_member(request, owner_identity, authenticated_peer) {
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
                    Err(MemberAdmissionError::AwaitingApproval) => {
                        JoinResponse::rejected(JoinRejectReason::AwaitingApproval)
                    }
                    Err(MemberAdmissionError::GroupFull) => {
                        JoinResponse::rejected(JoinRejectReason::GroupFull)
                    }
                }
            }
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
        _request: &JoinRequest,
        _owner_identity: &DeviceIdentity,
        _authenticated_peer: PeerId,
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

    fn acknowledged_head(
        &self,
        _group_id: PeerId,
        _peer_id: PeerId,
        _author_id: PeerId,
    ) -> Result<u64, &'static str> {
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

    fn notice_recipients(&self, _group_id: PeerId) -> Vec<PeerId> {
        Vec::new()
    }

    fn owns_group(&self, _group_id: PeerId) -> bool {
        false
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

/// Names a membership comparison for the frontend.
fn membership_comparison_name(comparison: MembershipComparison) -> &'static str {
    match comparison {
        MembershipComparison::Same => "same",
        MembershipComparison::RemoteNewer => "remoteNewer",
        MembershipComparison::RemoteStale => "remoteStale",
        MembershipComparison::Diverged => "diverged",
    }
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

/// Switches the running owner advertising node to a changed key set:
/// announces keys it did not hold and stops announcing retired ones, whose
/// provider records then expire with their network TTL. Returns false when an
/// announcement could not start, which ends the advertiser so the next
/// recheck restarts it.
fn update_announced_keys(
    node: &mut NetworkNode,
    current: &mut Vec<DiscoveryKey>,
    keys: Vec<DiscoveryKey>,
) -> bool {
    for retired in current.iter().filter(|key| !keys.contains(key)) {
        node.stop_announcing_group(*retired);
    }
    let announced = keys
        .iter()
        .filter(|key| !current.contains(key))
        .all(|key| node.announce_group(*key).is_ok());
    *current = keys;
    announced
}

/// Records a listen address of the owner advertising node as an invitation
/// hint candidate, when another device could dial it.
fn record_owner_address(addresses: &std::sync::Mutex<Vec<Multiaddr>>, address: Multiaddr) {
    let Some(hint) = address_hint(address) else {
        return;
    };
    if let Ok(mut addresses) = addresses.lock() {
        if addresses.contains(&hint) {
            return;
        }
        if addresses.len() >= MAX_OWNER_LISTEN_ADDRESSES {
            // Relay circuit addresses arrive after the reservation, once the
            // direct interface addresses may already fill the list; they
            // replace the oldest direct address so invitations keep a hint
            // that reaches an owner behind NAT.
            let relayed = |address: &Multiaddr| address.iter().any(|p| p == Protocol::P2pCircuit);
            let oldest_direct = addresses.iter().position(|address| !relayed(address));
            match oldest_direct {
                Some(index) if relayed(&hint) => {
                    addresses.remove(index);
                }
                _ => return,
            }
        }
        addresses.push(hint);
    }
}

/// Drops addresses the advertising node no longer listens on, so new
/// invitations carry only current hints.
fn forget_owner_addresses(addresses: &std::sync::Mutex<Vec<Multiaddr>>, expired: Vec<Multiaddr>) {
    let expired: Vec<Multiaddr> = expired.into_iter().filter_map(address_hint).collect();
    if let Ok(mut addresses) = addresses.lock() {
        addresses.retain(|address| !expired.contains(address));
    }
}

fn clear_owner_addresses(addresses: &std::sync::Mutex<Vec<Multiaddr>>) {
    if let Ok(mut addresses) = addresses.lock() {
        addresses.clear();
    }
}

/// Records a connection to the owner advertising node, keeping a direct or
/// LAN path over a relayed one while the peer has both.
fn record_owner_peer(
    peers: &std::sync::Mutex<BTreeMap<PeerId, ConnectionPath>>,
    peer_id: PeerId,
    path: ConnectionPath,
) {
    let mut peers = peers
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if peers.contains_key(&peer_id) || peers.len() < MAX_OWNER_PEERS {
        let best = match peers.get(&peer_id) {
            Some(ConnectionPath::Relayed) | None => path,
            Some(existing) if path == ConnectionPath::Relayed => *existing,
            Some(_) => path,
        };
        peers.insert(peer_id, best);
    }
}

/// Forgets a peer whose last connection to the owner advertising node closed.
fn forget_owner_peer(peers: &std::sync::Mutex<BTreeMap<PeerId, ConnectionPath>>, peer_id: PeerId) {
    peers
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .remove(&peer_id);
}

/// Stores the latest observed connection path shown on the Network page.
fn remember_connection(
    last_connection: &std::sync::Mutex<Option<ObservedConnection>>,
    connection_type: &'static str,
) {
    let observed_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    *last_connection
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(ObservedConnection {
        connection_type,
        observed_at_unix,
    });
}

/// Records the path of a current member whose synchronization request the
/// owner advertising node answered, so owner-only devices report the
/// connection type of their members.
fn record_member_connection(
    last_connection: &std::sync::Mutex<Option<ObservedConnection>>,
    owner_peers: &std::sync::Mutex<BTreeMap<PeerId, ConnectionPath>>,
    peer_id: PeerId,
) {
    let path = owner_peers
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .get(&peer_id)
        .copied();
    if let Some(path) = path {
        remember_connection(last_connection, connection_type_name(path));
    }
}

fn clear_owner_peers(peers: &std::sync::Mutex<BTreeMap<PeerId, ConnectionPath>>) {
    peers
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clear();
}

/// Connection state of an owned group: offline while this owner device does
/// not serve it, online or relayed while a current member is connected
/// (direct or LAN paths win), and otherwise waiting for members.
fn owned_group_state(
    serving: bool,
    members: &[PeerId],
    connected: &BTreeMap<PeerId, ConnectionPath>,
) -> &'static str {
    if !serving {
        return "offline";
    }
    let paths = members
        .iter()
        .filter_map(|member| connected.get(member))
        .collect::<Vec<_>>();
    if paths.iter().any(|path| **path != ConnectionPath::Relayed) {
        "online"
    } else if paths.is_empty() {
        "waiting"
    } else {
        "relayed"
    }
}

/// Strips the trailing device peer ID, which joiners append from the pinned
/// inviter instead, and rejects loopback, unspecified, IPv6 link-local
/// (unusable without the owner's interface scope), and oversized addresses
/// that cannot serve as an invitation hint.
fn address_hint(mut address: Multiaddr) -> Option<Multiaddr> {
    if matches!(address.iter().last(), Some(Protocol::P2p(_))) {
        address.pop();
    }
    let local_only = address.iter().any(|protocol| match protocol {
        Protocol::Ip4(ip) => ip.is_loopback() || ip.is_unspecified(),
        Protocol::Ip6(ip) => ip.is_loopback() || ip.is_unspecified() || ip.is_unicast_link_local(),
        _ => false,
    });
    let valid = !local_only
        && !address.is_empty()
        && address.len() <= MAX_ADDRESS_HINT_BYTES
        && !matches!(address.iter().last(), Some(Protocol::P2p(_)));
    valid.then_some(address)
}

/// Invitation address hints with the pinned inviter device peer ID
/// appended (ADR-037), so a dial only succeeds against that device.
fn pinned_address_hints(invitation: &Invitation) -> Vec<Multiaddr> {
    let inviter = invitation.inviter_device_id();
    invitation
        .address_hints()
        .iter()
        .map(|hint| hint.clone().with(Protocol::P2p(inviter)))
        .collect()
}

/// Maps a provider dial outcome to the join preview's reachability result.
fn search_result(
    dialed: Result<ConnectionPath, &'static str>,
) -> Result<PeerSearchResult, &'static str> {
    let (status, discovered_peers, path) = match dialed {
        Ok(path) => ("peerReachable", 1, Some(path)),
        Err("network_bootstrap_required") => ("bootstrapRequired", 0, None),
        Err("network_peer_not_found") => ("noPeers", 0, None),
        Err("network_unavailable") => ("unavailable", 0, None),
        // The lookup found the inviter's record but no dial reached it.
        Err("network_peer_unreachable") => ("peersFound", 1, None),
        Err(error) => return Err(error),
    };
    Ok(PeerSearchResult {
        status,
        discovered_peers,
        reachable_peers: usize::from(path.is_some()),
        connection_type: path.map(connection_type_name),
    })
}

/// Starts listening on QUIC and on TCP (ADR-047) on every IPv4 and IPv6
/// interface, each on a port chosen by the operating system. IPv4 is
/// required; IPv6 is skipped on devices or networks without it.
fn listen_on_all_interfaces(node: &mut NetworkNode) -> Result<(), &'static str> {
    for address in ["/ip4/0.0.0.0/udp/0/quic-v1", "/ip4/0.0.0.0/tcp/0"] {
        node.listen_on(
            address
                .parse()
                .map_err(|_| "network_configuration_invalid")?,
        )
        .map_err(|_| "network_unavailable")?;
    }
    for address in ["/ip6/::/udp/0/quic-v1", "/ip6/::/tcp/0"] {
        let address = address
            .parse()
            .map_err(|_| "network_configuration_invalid")?;
        let _ = node.listen_on(address);
    }
    Ok(())
}

/// Picks at most the invitation hint limit, relay circuit addresses first
/// because they also reach an owner behind NAT, then direct QUIC addresses
/// and finally direct TCP addresses for networks that block UDP.
fn select_address_hints(addresses: &[Multiaddr]) -> Vec<Multiaddr> {
    let (relayed, direct): (Vec<_>, Vec<_>) = addresses.iter().cloned().partition(|address| {
        address
            .iter()
            .any(|protocol| protocol == Protocol::P2pCircuit)
    });
    let (quic, other): (Vec<_>, Vec<_>) = direct
        .into_iter()
        .partition(|address| address.iter().any(|protocol| protocol == Protocol::QuicV1));
    relayed
        .into_iter()
        .chain(quic)
        .chain(other)
        .take(MAX_ADDRESS_HINTS)
        .collect()
}

pub(crate) fn parse_bootstrap_peer(input: &str) -> Result<BootstrapPeer, &'static str> {
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
        collections::BTreeMap,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    use charp2p_core::{
        DeviceIdentity, DiscoveryKey, EventKind, EventSpec, GroupIdentity, HistoryPolicy,
        Invitation, InvitationSpec, JoinRejectReason, JoinRequest, JoinResponse, PeerId,
        SignedEvent, SyncMembershipState, SyncPeerHead, SyncRejectReason, SyncRequest,
        SyncResponse,
    };
    use charp2p_mls::{
        device_credential, prepare_profile_key_package, ProfileProvider, CIPHERSUITE,
    };
    use charp2p_network::{ConnectionPath, NetworkEvent, NetworkNode};
    use libp2p::multiaddr::Protocol;
    use openmls::prelude::{tls_codec::Serialize, CredentialWithKey, KeyPackage, OpenMlsProvider};
    use openmls_basic_credential::SignatureKeyPair;
    use tokio::time::{interval, timeout};

    use crate::bandwidth::{BandwidthPreference, BandwidthService};
    use crate::routing_peers::RoutingPeersService;

    use super::{
        address_hint, answer_contribution_event, answer_member_sync_request, await_sync_response,
        clear_owner_peers, discovery_outcome, forget_owner_addresses, forget_owner_peer,
        join_response, membership_comparison_name, owned_group_state, parse_bootstrap_peer,
        pinned_address_hints, record_member_connection, record_owner_address, record_owner_peer,
        select_address_hints, send_push_request, upgraded_path, AdvertisementResult,
        BootstrapNodeStatus, JoinRequestAuthorization, JoinRequestAuthorizer,
        MemberAdmissionService, MemberCandidates, MembershipComparison, NetworkService,
        NetworkStatus, OwnerAnswerIdentity, PeerSearchResult, PendingJoinService, PullSession,
        SessionProgress, SynchronizationService, UnavailableJoinRequestAuthorizer,
        UnavailableMemberAdmissionService, UnavailablePendingJoinService, DIAGNOSTICS_FORMAT,
        MAX_GROUP_CONNECTION_STATES, MAX_MEMBER_PROVIDERS, MAX_OWNER_LISTEN_ADDRESSES,
        PROVIDER_SEARCH_TIMEOUT,
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
            _request: &JoinRequest,
            _owner_identity: &DeviceIdentity,
            _authenticated_peer: PeerId,
        ) -> Result<JoinResponse, MemberAdmissionError> {
            JoinResponse::accepted(vec![4, 5, 6]).map_err(|_| MemberAdmissionError::Unavailable)
        }
    }

    struct AwaitingApprovalMemberAdmissionService;

    impl MemberAdmissionService for AwaitingApprovalMemberAdmissionService {
        fn admit_member(
            &self,
            _request: &JoinRequest,
            _owner_identity: &DeviceIdentity,
            _authenticated_peer: PeerId,
        ) -> Result<JoinResponse, MemberAdmissionError> {
            Err(MemberAdmissionError::AwaitingApproval)
        }
    }

    struct FullMemberAdmissionService;

    impl MemberAdmissionService for FullMemberAdmissionService {
        fn admit_member(
            &self,
            _request: &JoinRequest,
            _owner_identity: &DeviceIdentity,
            _authenticated_peer: PeerId,
        ) -> Result<JoinResponse, MemberAdmissionError> {
            Err(MemberAdmissionError::GroupFull)
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
                        membership: SyncMembershipState::default(),
                    }
                }
                SyncRequest::Events { group_id, .. } if *group_id == self.group_id => {
                    SyncResponse::Events {
                        group_id: self.group_id,
                        encoded_events: vec![vec![0; 700 * 1024]],
                    }
                }
                SyncRequest::ReportHeads { group_id, .. } if *group_id == self.group_id => {
                    SyncResponse::ObservedHeads {
                        group_id: self.group_id,
                        peers: Vec::new(),
                    }
                }
                SyncRequest::EventsAvailable { group_id } if *group_id == self.group_id => {
                    SyncResponse::Acknowledged {
                        group_id: self.group_id,
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

        fn acknowledged_head(
            &self,
            _group_id: PeerId,
            _peer_id: PeerId,
            _author_id: PeerId,
        ) -> Result<u64, &'static str> {
            Ok(0)
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

        fn notice_recipients(&self, group_id: PeerId) -> Vec<PeerId> {
            if group_id == self.group_id {
                vec![self.expected_peer]
            } else {
                Vec::new()
            }
        }

        fn owns_group(&self, group_id: PeerId) -> bool {
            group_id == self.group_id
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

    /// Identities holding one key, as the app loads the network and owner
    /// identities separately.
    fn identity_copies<const N: usize>() -> [DeviceIdentity; N] {
        let (_, secret) = DeviceIdentity::generate_persistable().unwrap();
        std::array::from_fn(|_| DeviceIdentity::from_persisted_secret(&secret).unwrap())
    }

    fn owner_answers(identity: DeviceIdentity) -> OwnerAnswerIdentity {
        OwnerAnswerIdentity {
            identity,
            inviter_name: "Maya's PC".to_owned(),
        }
    }

    async fn contribute(
        service: &NetworkService,
        relay: Option<charp2p_network::RelayLimits>,
    ) -> Result<&'static str, &'static str> {
        let (network, owner) = identity_pair();
        service
            .start_contribution(network, owner, "Maya's PC".to_owned(), relay)
            .await
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
        /// Keeps tests of DHT discovery independent of mDNS on the host, and
        /// lets their loopback-only nodes publish provider addresses, which
        /// ADR-056 otherwise keeps out of the DHT.
        fn without_lan_discovery(mut self) -> Self {
            self.lan_discovery = false;
            self.publish_private_addresses = true;
            self
        }
    }

    #[test]
    fn member_connections_to_the_owner_node_set_the_last_connection() {
        let member = DeviceIdentity::generate().peer_id();
        let unknown = DeviceIdentity::generate().peer_id();
        let service = NetworkService::from_sources(&[], "").unwrap();
        let status = || tauri::async_runtime::block_on(service.status());

        // A peer without a recorded connection path leaves it unchanged.
        record_member_connection(&service.last_connection, &service.owner_peers, unknown);
        assert_eq!(status().connection_type, None);
        record_owner_peer(&service.owner_peers, member, ConnectionPath::Relayed);
        record_member_connection(&service.last_connection, &service.owner_peers, member);
        assert_eq!(status().connection_type, Some("relayed"));
        record_owner_peer(&service.owner_peers, member, ConnectionPath::Lan);
        record_member_connection(&service.last_connection, &service.owner_peers, member);
        let status = status();
        assert_eq!(status.connection_type, Some("lan"));
        assert!(status.connection_observed_at_unix > 0);
    }

    #[test]
    fn owned_group_state_follows_serving_and_connected_members() {
        let member = DeviceIdentity::generate().peer_id();
        let other = DeviceIdentity::generate().peer_id();
        let stranger = DeviceIdentity::generate().peer_id();
        let peers = std::sync::Mutex::new(BTreeMap::new());
        let members = [member, other];
        let state =
            |serving| owned_group_state(serving, &members, &peers.lock().expect("peers lock"));

        assert_eq!(state(true), "waiting");
        // A connected peer that is not a current member does not count.
        record_owner_peer(&peers, stranger, ConnectionPath::Direct);
        assert_eq!(state(true), "waiting");
        record_owner_peer(&peers, member, ConnectionPath::Relayed);
        assert_eq!(state(true), "relayed");
        assert_eq!(state(false), "offline");
        // A hole-punched direct connection wins over the relayed one and a
        // later relayed connection does not downgrade it.
        record_owner_peer(&peers, member, ConnectionPath::Direct);
        record_owner_peer(&peers, member, ConnectionPath::Relayed);
        assert_eq!(state(true), "online");
        forget_owner_peer(&peers, member);
        assert_eq!(state(true), "waiting");
        record_owner_peer(&peers, other, ConnectionPath::Lan);
        assert_eq!(state(true), "online");
        clear_owner_peers(&peers);
        assert_eq!(state(true), "waiting");
    }

    #[test]
    fn owner_address_hints_strip_the_peer_id_and_put_relays_first() {
        let device = DeviceIdentity::generate().peer_id();
        let relay = DeviceIdentity::generate().peer_id();
        let direct: libp2p::Multiaddr = "/ip4/192.168.1.20/udp/4001/quic-v1".parse().unwrap();
        let relayed: libp2p::Multiaddr =
            format!("/ip4/203.0.113.9/udp/4001/quic-v1/p2p/{relay}/p2p-circuit")
                .parse()
                .unwrap();
        let addresses = std::sync::Mutex::new(Vec::new());
        record_owner_address(
            &addresses,
            direct
                .clone()
                .with(libp2p::multiaddr::Protocol::P2p(device)),
        );
        record_owner_address(&addresses, direct.clone());
        record_owner_address(
            &addresses,
            relayed
                .clone()
                .with(libp2p::multiaddr::Protocol::P2p(device)),
        );
        record_owner_address(
            &addresses,
            "/ip4/127.0.0.1/udp/4001/quic-v1".parse().unwrap(),
        );
        record_owner_address(&addresses, "/ip6/::/udp/4001/quic-v1".parse().unwrap());
        record_owner_address(&addresses, "/ip6/fe80::1/udp/4001/quic-v1".parse().unwrap());

        let tcp: libp2p::Multiaddr = "/ip4/192.168.1.20/tcp/4001".parse().unwrap();
        record_owner_address(&addresses, tcp.clone());
        record_owner_address(&addresses, "/ip4/127.0.0.1/tcp/4001".parse().unwrap());

        let hints = select_address_hints(&addresses.lock().unwrap());
        assert_eq!(hints, vec![relayed, direct, tcp]);

        let many: Vec<libp2p::Multiaddr> = (1..=6)
            .map(|port| {
                format!("/ip4/192.168.1.20/udp/{port}/quic-v1")
                    .parse()
                    .unwrap()
            })
            .collect();
        assert_eq!(select_address_hints(&many), many[..4].to_vec());
        assert_eq!(address_hint(libp2p::Multiaddr::empty()), None);
    }

    #[test]
    fn relay_owner_address_is_kept_when_direct_addresses_fill_the_list() {
        let relay = DeviceIdentity::generate().peer_id();
        let addresses = std::sync::Mutex::new(Vec::new());
        for octet in 0..MAX_OWNER_LISTEN_ADDRESSES {
            record_owner_address(
                &addresses,
                format!("/ip4/192.168.1.{}/udp/4001/quic-v1", octet + 1)
                    .parse()
                    .unwrap(),
            );
        }
        let relayed: libp2p::Multiaddr =
            format!("/ip4/203.0.113.9/udp/4001/quic-v1/p2p/{relay}/p2p-circuit")
                .parse()
                .unwrap();
        record_owner_address(&addresses, relayed.clone());
        record_owner_address(&addresses, "/ip4/192.168.2.1/tcp/4001".parse().unwrap());

        let addresses = addresses.lock().unwrap();
        assert_eq!(addresses.len(), MAX_OWNER_LISTEN_ADDRESSES);
        assert!(!addresses.contains(&"/ip4/192.168.1.1/udp/4001/quic-v1".parse().unwrap()));
        assert_eq!(select_address_hints(&addresses)[0], relayed);
    }

    #[test]
    fn expired_owner_listen_addresses_are_no_longer_hinted() {
        let device = DeviceIdentity::generate().peer_id();
        let relay = DeviceIdentity::generate().peer_id();
        let direct: libp2p::Multiaddr = "/ip4/192.168.1.20/udp/4001/quic-v1".parse().unwrap();
        let relayed: libp2p::Multiaddr =
            format!("/ip4/203.0.113.9/udp/4001/quic-v1/p2p/{relay}/p2p-circuit")
                .parse()
                .unwrap();
        let addresses = std::sync::Mutex::new(Vec::new());
        record_owner_address(&addresses, direct.clone());
        record_owner_address(&addresses, relayed.clone());

        // A closed relay reservation reports the listen address with the
        // local peer ID appended.
        forget_owner_addresses(
            &addresses,
            vec![relayed
                .clone()
                .with(libp2p::multiaddr::Protocol::P2p(device))],
        );
        assert_eq!(
            select_address_hints(&addresses.lock().unwrap()),
            vec![direct.clone()]
        );

        forget_owner_addresses(&addresses, vec![direct]);
        assert!(select_address_hints(&addresses.lock().unwrap()).is_empty());

        record_owner_address(&addresses, relayed.clone());
        assert_eq!(
            select_address_hints(&addresses.lock().unwrap()),
            vec![relayed]
        );
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

        assert_eq!(
            join_response(
                JoinRequestAuthorization::Authorized,
                &AwaitingApprovalMemberAdmissionService,
                &owner,
                &request,
                peer_id,
            )
            .rejection(),
            Some(JoinRejectReason::AwaitingApproval)
        );

        assert_eq!(
            join_response(
                JoinRequestAuthorization::Authorized,
                &FullMemberAdmissionService,
                &owner,
                &request,
                peer_id,
            )
            .rejection(),
            Some(JoinRejectReason::GroupFull)
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
    fn community_nodes_join_the_bootstrap_list_without_repeating_known_nodes() {
        let built_in_peer = DeviceIdentity::generate().peer_id();
        let community_peer = DeviceIdentity::generate().peer_id();
        let built_in = format!("/ip4/127.0.0.1/udp/9000/quic-v1/p2p/{built_in_peer}");
        let community = format!("/ip4/203.0.113.7/udp/4001/quic-v1/p2p/{community_peer}");
        let service = NetworkService::from_sources(&[built_in.as_str()], "").unwrap();

        let peers = service
            .community_peers(&[built_in.clone(), community.clone(), community])
            .expect("community nodes are accepted");
        tauri::async_runtime::block_on(service.use_community_peers(peers));
        let status = tauri::async_runtime::block_on(service.status());

        assert_eq!(
            status.bootstrap_nodes,
            vec![
                BootstrapNodeStatus {
                    peer_id: built_in_peer.to_string(),
                    address: "/ip4/127.0.0.1/udp/9000/quic-v1".to_owned(),
                    source: "builtIn",
                },
                BootstrapNodeStatus {
                    peer_id: community_peer.to_string(),
                    address: "/ip4/203.0.113.7/udp/4001/quic-v1".to_owned(),
                    source: "community",
                },
            ]
        );

        service.replace_community_peers(Vec::new());
        assert_eq!(service.bootstrap_peers().len(), 1);
    }

    #[test]
    fn remembered_routing_peers_are_extra_entry_points_outside_the_bootstrap_list() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let routing_peers = Arc::new(RoutingPeersService::new(
            directory.path().join("routing-peers.json"),
        ));
        let built_in_peer = DeviceIdentity::generate().peer_id();
        let remembered_peer = DeviceIdentity::generate().peer_id();
        let built_in = format!("/ip4/127.0.0.1/udp/9000/quic-v1/p2p/{built_in_peer}");
        let address: libp2p::Multiaddr = "/ip4/203.0.113.7/udp/4001/quic-v1".parse().unwrap();
        routing_peers
            .record(remembered_peer, &address)
            .expect("peer is stored");
        routing_peers
            .record(built_in_peer, &address)
            .expect("peer is stored");
        let service = NetworkService::from_sources(&[built_in.as_str()], "")
            .unwrap()
            .with_routing_peers(routing_peers);

        let entry_points = service.remembered_entry_points();

        assert_eq!(entry_points.len(), 1);
        assert_eq!(entry_points[0].peer_id, remembered_peer);
        assert_eq!(entry_points[0].address, address);
        assert_eq!(service.bootstrap_peers().len(), 1);
    }

    #[test]
    fn remembered_routing_peers_do_not_replace_bootstrap_nodes() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let routing_peers = Arc::new(RoutingPeersService::new(
            directory.path().join("routing-peers.json"),
        ));
        routing_peers
            .record(
                DeviceIdentity::generate().peer_id(),
                &"/ip4/203.0.113.7/udp/4001/quic-v1".parse().unwrap(),
            )
            .expect("peer is stored");
        let service = NetworkService::from_sources(&[], "")
            .unwrap()
            .with_routing_peers(routing_peers);

        let status = tauri::async_runtime::block_on(service.status());

        assert_eq!(status.advertising_status, "bootstrapRequired");
        assert!(status.bootstrap_nodes.is_empty());
    }

    #[test]
    fn community_nodes_share_the_bootstrap_limit() {
        let entry = || {
            let peer_id = DeviceIdentity::generate().peer_id();
            format!("/ip4/127.0.0.1/udp/9000/quic-v1/p2p/{peer_id}")
        };
        let configured = (0..12).map(|_| entry()).collect::<Vec<_>>().join(";");
        let service = NetworkService::from_sources(&[], &configured).unwrap();

        assert!(service
            .community_peers(&(0..4).map(|_| entry()).collect::<Vec<_>>())
            .is_ok());
        assert_eq!(
            service
                .community_peers(&(0..5).map(|_| entry()).collect::<Vec<_>>())
                .err(),
            Some("community_nodes_limit")
        );
        assert_eq!(
            service
                .community_peers(&["not an address".to_owned()])
                .err(),
            Some("community_node_invalid")
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
    fn owned_groups_report_a_missing_bootstrap_node_instead_of_offline() {
        let group = DeviceIdentity::generate().peer_id();
        let states = |service: NetworkService| {
            tauri::async_runtime::block_on(service.owned_group_connection_states(&[group]))
        };

        let without = states(NetworkService::from_sources(&[], "").unwrap());
        assert_eq!(without.len(), 1);
        assert_eq!(without[0].group_id, group.to_string());
        assert_eq!(without[0].state, "bootstrapRequired");

        let node = DeviceIdentity::generate().peer_id();
        let configured = format!("/ip4/127.0.0.1/udp/9000/quic-v1/p2p/{node}");
        let with = states(NetworkService::from_sources(&[], &configured).unwrap());
        assert_eq!(with[0].state, "offline");
    }

    #[test]
    fn contribution_requires_a_bootstrap_node() {
        let service = NetworkService::from_sources(&[], "").unwrap();

        let started = tauri::async_runtime::block_on(contribute(&service, None));

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
            assert_eq!(contribute(&service, None).await, Ok("routing"));
            assert_eq!(service.status().await.contribution_status, "routing");
            assert_eq!(
                contribute(&service, Some(relay)).await,
                Ok("routingAndRelay")
            );
            assert_eq!(
                service.status().await.contribution_status,
                "routingAndRelay"
            );
            assert_eq!(
                contribute(&service, Some(relay)).await,
                Ok("routingAndRelay")
            );
            service.stop_contribution().await;
            assert_eq!(service.status().await.contribution_status, "inactive");
        });
    }

    #[test]
    fn contribution_node_answers_only_owned_group_sync_requests() {
        let owned = DeviceIdentity::generate().peer_id();
        let other = DeviceIdentity::generate().peer_id();
        let (network, owner) = identity_pair();
        let requester_identity = DeviceIdentity::generate();
        let requester_id = requester_identity.peer_id();
        let service = NetworkService::from_sources_with_authorizer(
            &[],
            "",
            Arc::new(StaticJoinRequestAuthorizer(
                JoinRequestAuthorization::Unauthorized,
            )),
            Arc::new(UnavailableMemberAdmissionService),
            Arc::new(UnavailablePendingJoinService),
            Arc::new(MemberSynchronizationService {
                expected_peer: requester_id,
                group_id: owned,
            }),
        )
        .unwrap();
        let handlers = service.owner_request_handlers();

        tauri::async_runtime::block_on(async {
            let mut contribution =
                NetworkNode::new_contributing(network.into_network_keypair(), None);
            let contribution_id = contribution.peer_id();
            contribution
                .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
                .unwrap();
            let address = loop {
                if let NetworkEvent::Listening { address } = contribution.next_event().await {
                    break address;
                }
            };
            let mut requester = NetworkNode::new(requester_identity.into_network_keypair());
            requester
                .dial(format!("{address}/p2p/{contribution_id}").parse().unwrap())
                .unwrap();

            let responses = timeout(Duration::from_secs(10), async {
                let mut responses = BTreeMap::new();
                loop {
                    tokio::select! {
                        event = contribution.next_event() => answer_contribution_event(
                            &mut contribution,
                            event,
                            &handlers,
                            &owner,
                            "Maya's PC",
                        ),
                        event = requester.next_event() => match event {
                            NetworkEvent::PeerConnected { peer_id, .. }
                                if peer_id == contribution_id =>
                            {
                                for group_id in [owned, other] {
                                    requester
                                        .send_sync_request(
                                            contribution_id,
                                            SyncRequest::Summary { group_id },
                                        )
                                        .unwrap();
                                }
                            }
                            NetworkEvent::SyncResponseReceived { response, .. } => {
                                let group_id = match &response {
                                    SyncResponse::Summary { group_id, .. } => *group_id,
                                    _ => other,
                                };
                                responses.insert(group_id, response);
                                if responses.len() == 2 {
                                    break responses;
                                }
                            }
                            _ => {}
                        },
                    }
                }
            })
            .await
            .expect("both sync requests should be answered");

            assert_eq!(
                responses[&owned],
                SyncResponse::Summary {
                    group_id: owned,
                    heads: Vec::new(),
                    membership: SyncMembershipState::default(),
                }
            );
            assert_eq!(
                responses[&other],
                SyncResponse::Rejected {
                    reason: SyncRejectReason::Unauthorized,
                }
            );
        });
    }

    #[test]
    fn contribution_starts_through_added_community_nodes() {
        let service = NetworkService::from_sources(&[], "").unwrap();
        let community = DeviceIdentity::generate().peer_id();
        let address = format!("/ip4/127.0.0.1/udp/9/quic-v1/p2p/{community}");

        tauri::async_runtime::block_on(async {
            assert_eq!(contribute(&service, None).await, Ok("bootstrapRequired"));
            let peers = service.community_peers(&[address]).unwrap();
            service.use_community_peers(peers).await;
            assert_eq!(contribute(&service, None).await, Ok("routing"));
            assert_eq!(service.status().await.contribution_status, "routing");

            // A changed list stops the node until the preference is re-applied.
            service.use_community_peers(Vec::new()).await;
            assert_eq!(service.status().await.contribution_status, "inactive");
        });
    }

    #[test]
    fn only_the_peers_hole_punch_turns_a_relayed_path_direct() {
        let peer = DeviceIdentity::generate().peer_id();
        let other = DeviceIdentity::generate().peer_id();
        let upgraded = NetworkEvent::DirectConnectionUpgraded { peer_id: peer };

        assert_eq!(
            upgraded_path(ConnectionPath::Relayed, &upgraded, peer),
            ConnectionPath::Direct
        );
        assert_eq!(
            upgraded_path(ConnectionPath::Relayed, &upgraded, other),
            ConnectionPath::Relayed
        );
        assert_eq!(
            upgraded_path(ConnectionPath::Lan, &upgraded, peer),
            ConnectionPath::Lan
        );
        assert_eq!(
            upgraded_path(
                ConnectionPath::Relayed,
                &NetworkEvent::PeerDisconnected { peer_id: peer },
                peer
            ),
            ConnectionPath::Relayed
        );
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
    fn pushed_events_are_charged_when_no_answer_arrives() {
        let directory = tempfile::tempdir().unwrap();
        let bandwidth = BandwidthService::new(directory.path().join("bandwidth.json"));
        bandwidth
            .set(BandwidthPreference {
                sync_limit_mib_per_hour: Some(1),
            })
            .unwrap();
        let group = GroupIdentity::generate();
        let event = SignedEvent::create(
            &DeviceIdentity::generate(),
            EventSpec {
                group_id: group.group_id(),
                author_sequence: 1,
                causal_parents: &[],
                created_at_unix_ms: NOW * 1000,
                kind: EventKind::MessageCreated,
                protected_payload: &[7; 4096],
            },
        )
        .unwrap()
        .encode()
        .unwrap();
        let pushed_bytes = event.len() as u64;
        let request = SyncRequest::PushEvents {
            group_id: group.group_id(),
            encoded_events: vec![event],
        };

        tauri::async_runtime::block_on(async {
            let mut node = NetworkNode::new(DeviceIdentity::generate().into_network_keypair());
            let unreachable = DeviceIdentity::generate().peer_id();
            let request_id =
                send_push_request(&mut node, unreachable, request, &bandwidth).unwrap();
            let mut path = ConnectionPath::Direct;
            assert!(
                await_sync_response(&mut node, unreachable, request_id, &mut path)
                    .await
                    .is_err()
            );
        });

        assert_eq!(
            bandwidth.status().unwrap().remaining_sync_bytes,
            Some(1024 * 1024 - pushed_bytes)
        );
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
    fn spent_synchronization_budget_skips_the_report_heads_exchange() {
        let directory = tempfile::tempdir().unwrap();
        let bandwidth = BandwidthService::new(directory.path().join("bandwidth.json"));
        bandwidth
            .set(BandwidthPreference {
                sync_limit_mib_per_hour: Some(1),
            })
            .unwrap();
        bandwidth.charge_sync_bytes(2 * 1024 * 1024);
        let service = NetworkService::from_sources(&[], "").unwrap();

        let result = tauri::async_runtime::block_on(async {
            let mut node = NetworkNode::new(DeviceIdentity::generate().into_network_keypair());
            let mut path = ConnectionPath::Direct;
            service
                .exchange_observed_heads(
                    &mut node,
                    DeviceIdentity::generate().peer_id(),
                    DeviceIdentity::generate().peer_id(),
                    DeviceIdentity::generate().peer_id(),
                    &bandwidth,
                    &mut path,
                )
                .await
        });

        assert_eq!(result.unwrap_err(), "synchronization_bandwidth_limited");
    }

    #[test]
    fn member_serving_charges_served_events_and_answers_busy_once_spent() {
        let directory = tempfile::tempdir().unwrap();
        let bandwidth = BandwidthService::new(directory.path().join("bandwidth.json"));
        bandwidth
            .set(BandwidthPreference {
                sync_limit_mib_per_hour: Some(1),
            })
            .unwrap();
        let peer = DeviceIdentity::generate().peer_id();
        let group_id = DeviceIdentity::generate().peer_id();
        let synchronization = MemberSynchronizationService {
            expected_peer: peer,
            group_id,
        };
        let events = SyncRequest::Events {
            group_id,
            event_ids: Vec::new(),
        };
        let busy = SyncResponse::Rejected {
            reason: SyncRejectReason::Busy,
        };

        let summary = answer_member_sync_request(
            &synchronization,
            &bandwidth,
            peer,
            &SyncRequest::Summary { group_id },
        );
        assert!(matches!(summary, SyncResponse::Summary { .. }));
        assert_eq!(
            bandwidth.status().unwrap().remaining_sync_bytes,
            Some(1024 * 1024)
        );

        let first = answer_member_sync_request(&synchronization, &bandwidth, peer, &events);
        assert!(matches!(first, SyncResponse::Events { .. }));
        // The exchange already started completes and overshoots the budget.
        let second = answer_member_sync_request(&synchronization, &bandwidth, peer, &events);
        assert!(matches!(second, SyncResponse::Events { .. }));
        assert_eq!(bandwidth.status().unwrap().remaining_sync_bytes, Some(0));

        let spent = answer_member_sync_request(
            &synchronization,
            &bandwidth,
            peer,
            &SyncRequest::Summary { group_id },
        );
        assert_eq!(spent, busy);
    }

    #[test]
    fn member_serving_is_unmetered_without_a_limit() {
        let directory = tempfile::tempdir().unwrap();
        let bandwidth = BandwidthService::new(directory.path().join("bandwidth.json"));
        let peer = DeviceIdentity::generate().peer_id();
        let group_id = DeviceIdentity::generate().peer_id();
        let synchronization = MemberSynchronizationService {
            expected_peer: peer,
            group_id,
        };
        let events = SyncRequest::Events {
            group_id,
            event_ids: Vec::new(),
        };

        for _ in 0..4 {
            let response = answer_member_sync_request(&synchronization, &bandwidth, peer, &events);
            assert!(matches!(response, SyncResponse::Events { .. }));
        }
        assert_eq!(bandwidth.status().unwrap().remaining_sync_bytes, None);
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
        let no_bootstrap = Err::<&str, _>("network_bootstrap_required");
        let _ = service.observe_group_synchronization(
            group,
            no_bootstrap,
            discovery_outcome(&no_bootstrap),
            |path| path,
        );
        assert_eq!(
            service.group_connection_states(&[group])[0].state,
            "bootstrapRequired"
        );
        let timed_out = Err::<&str, _>("network_search_timed_out");
        assert_eq!(discovery_outcome(&timed_out), Some("missing"));
        assert_eq!(discovery_outcome(&Ok::<_, &str>(())), Some("found"));
        assert_eq!(
            discovery_outcome(&Err::<(), _>("synchronization_bandwidth_limited")),
            None
        );
    }

    #[test]
    fn membership_comparisons_have_frontend_names() {
        assert_eq!(
            membership_comparison_name(MembershipComparison::Same),
            "same"
        );
        assert_eq!(
            membership_comparison_name(MembershipComparison::RemoteNewer),
            "remoteNewer"
        );
        assert_eq!(
            membership_comparison_name(MembershipComparison::RemoteStale),
            "remoteStale"
        );
        assert_eq!(
            membership_comparison_name(MembershipComparison::Diverged),
            "diverged"
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

        // A member-served pull is reported separately from the owner attempt
        // and keeps its discovery outcome; a failed pull leaves it waiting.
        let _ = service.observe_group_synchronization::<&str>(
            second,
            Err("network_peer_unreachable"),
            Some("found"),
            |path| path,
        );
        let _ = service.observe_member_pull::<&str>(second, Err("network_peer_not_found"));
        assert_eq!(state(second), Some("waiting"));
        let _ = service.observe_member_pull(second, Ok(()));
        assert_eq!(state(second), Some("memberServed"));
        assert_eq!(
            service.group_connection_states(&[second])[0].discovery,
            Some("found")
        );
        let _ = service.observe_member_pull::<&str>(second, Err("network_unavailable"));
        assert_eq!(state(second), Some("offline"));
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
    fn search_refuses_an_invitation_this_device_issued() {
        let identity = DeviceIdentity::generate();
        let invitation = Invitation::issue(
            &GroupIdentity::generate(),
            identity.peer_id(),
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
        let service = NetworkService::from_sources(&[], "").unwrap();

        let result = tauri::async_runtime::block_on(service.search(identity, &invitation));

        assert_eq!(result, Err("invitation_inviter_mismatch"));
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

    fn hinted_invitation(
        group: &GroupIdentity,
        inviter: PeerId,
        hints: &[libp2p::Multiaddr],
        now: u64,
    ) -> Invitation {
        Invitation::issue_with_address_hints(
            group,
            inviter,
            InvitationSpec {
                group_name: "Design Crew",
                inviter_name: "Maya",
                expires_at_unix: now + 3_600,
                history_policy: HistoryPolicy::None,
                reusable: false,
            },
            hints,
            now,
        )
        .unwrap()
    }

    #[test]
    fn address_hints_are_pinned_to_the_inviter_device() {
        let inviter = DeviceIdentity::generate().peer_id();
        let relay = DeviceIdentity::generate().peer_id();
        let direct: libp2p::Multiaddr = "/ip4/192.168.1.20/udp/4001/quic-v1".parse().unwrap();
        let relayed: libp2p::Multiaddr =
            format!("/ip4/203.0.113.9/udp/4001/quic-v1/p2p/{relay}/p2p-circuit")
                .parse()
                .unwrap();
        let invitation = hinted_invitation(
            &GroupIdentity::generate(),
            inviter,
            &[relayed.clone(), direct.clone()],
            NOW,
        );

        assert_eq!(
            pinned_address_hints(&invitation),
            vec![
                relayed.with(libp2p::multiaddr::Protocol::P2p(inviter)),
                direct.with(libp2p::multiaddr::Protocol::P2p(inviter)),
            ]
        );
        assert!(pinned_address_hints(&join_invitation()).is_empty());
    }

    #[test]
    fn reachability_check_dials_address_hints_without_bootstrap_peers() {
        let now = unix_now();
        tauri::async_runtime::block_on(async {
            let mut inviter = NetworkNode::new(DeviceIdentity::generate().into_network_keypair());
            inviter
                .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
                .unwrap();
            let address = loop {
                if let NetworkEvent::Listening { address } = inviter.next_event().await {
                    break address;
                }
            };
            let invitation = hinted_invitation(
                &GroupIdentity::generate(),
                inviter.peer_id(),
                &[address],
                now,
            );
            let service = NetworkService::from_sources(&[], "").unwrap();
            let search = service.search(DeviceIdentity::generate(), &invitation);
            tokio::pin!(search);
            let result = timeout(Duration::from_secs(10), async {
                loop {
                    tokio::select! {
                        result = &mut search => break result,
                        _ = inviter.next_event() => {}
                    }
                }
            })
            .await
            .expect("reachability check should complete")
            .unwrap();

            assert_eq!(result.status, "peerReachable");
            assert_eq!(result.reachable_peers, 1);
        });
    }

    #[test]
    fn join_dials_the_hinted_owner_without_bootstrap_peers() {
        let now = unix_now();
        let group = GroupIdentity::generate();
        let (owner, owner_signer) = identity_pair();
        let owner_id = owner.peer_id();
        let unhinted = hinted_invitation(&group, owner_id, &[], now);

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
                    group_id: unhinted.group_id(),
                }),
            )
            .unwrap()
            .without_lan_discovery();
            let advertise = owner_service.advertise(owner, owner_signer, &unhinted);
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
            // The owner listens on every interface; its recorded non-loopback
            // IPv4 address supplies the port for a loopback hint.
            let port = timeout(Duration::from_secs(10), async {
                loop {
                    let port = owner_service.owner_address_hints().iter().find_map(|hint| {
                        let ipv4 = hint.iter().any(|protocol| {
                            matches!(protocol, libp2p::multiaddr::Protocol::Ip4(_))
                        });
                        hint.iter().find_map(|protocol| match protocol {
                            libp2p::multiaddr::Protocol::Udp(port) if ipv4 => Some(port),
                            _ => None,
                        })
                    });
                    if let Some(port) = port {
                        break port;
                    }
                    tokio::select! {
                        _ = routing.next_event() => {}
                        _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                    }
                }
            })
            .await
            .expect("owner should record a listen address");
            let hint: libp2p::Multiaddr = format!("/ip4/127.0.0.1/udp/{port}/quic-v1")
                .parse()
                .unwrap();
            let invitation = hinted_invitation(&group, owner_id, std::slice::from_ref(&hint), now);

            let pending_join = Arc::new(RecordingPendingJoinService::default());
            let joiner_service = NetworkService::from_sources_with_authorizer(
                &[],
                "",
                Arc::new(UnavailableJoinRequestAuthorizer),
                Arc::new(UnavailableMemberAdmissionService),
                pending_join.clone(),
                Arc::new(MemberSynchronizationService {
                    expected_peer: owner_id,
                    group_id: invitation.group_id(),
                }),
            )
            .unwrap()
            .without_lan_discovery();
            let result = timeout(
                Duration::from_secs(15),
                joiner_service.join(joiner_identity, &invitation),
            )
            .await
            .expect("join exchange should complete")
            .unwrap();

            assert_eq!(result.status, "joined");
            assert!(pending_join.completed.load(Ordering::SeqCst));
            // The hint that reached the owner is returned for remembering.
            assert!(result
                .peer_address
                .to_string()
                .starts_with(&hint.to_string()));
            assert!(result.synchronized_at_unix.is_some());
            assert!(result.reached_at_unix >= now);
        });
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
    fn reachability_check_finds_the_owner_over_lan_when_the_dht_has_no_record() {
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
                    expected_peer: DeviceIdentity::generate().peer_id(),
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

            let member_service = NetworkService::from_sources(&[], &bootstraps[1]).unwrap();
            let search = member_service.search(DeviceIdentity::generate(), &invitation);
            tokio::pin!(search);
            let result = timeout(Duration::from_secs(15), async {
                loop {
                    tokio::select! {
                        result = &mut search => break result,
                        _ = owner_routing.next_event() => {}
                        _ = member_routing.next_event() => {}
                    }
                }
            })
            .await
            .expect("LAN reachability check should complete")
            .unwrap();

            assert_eq!(result.status, "peerReachable");
            assert_eq!(result.reachable_peers, 1);
            assert_eq!(result.connection_type, Some("lan"));
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
    fn owner_advertisement_announces_new_keys_without_restarting() {
        let now = unix_now();
        let group = GroupIdentity::generate();
        let (_, owner_secret) = DeviceIdentity::generate_persistable().unwrap();
        let owner_id = DeviceIdentity::from_persisted_secret(&owner_secret)
            .unwrap()
            .peer_id();
        let issue = |group_name| {
            Invitation::issue(
                &group,
                owner_id,
                InvitationSpec {
                    group_name,
                    inviter_name: "Maya",
                    expires_at_unix: now + 3_600,
                    history_policy: HistoryPolicy::None,
                    reusable: false,
                },
                now,
            )
            .unwrap()
        };
        let first = issue("Design Crew");
        let requested = issue("Design Crew");
        let first_key = DiscoveryKey::from_invitation(&first);
        let requested_key = DiscoveryKey::from_invitation(&requested);
        assert_ne!(first_key, requested_key);
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
            let advertise = service.advertise_owner_group(
                DeviceIdentity::from_persisted_secret(&owner_secret).unwrap(),
                DeviceIdentity::from_persisted_secret(&owner_secret).unwrap(),
                "Maya's PC".to_owned(),
                vec![first_key],
            );
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
            let first_task_id = service
                .advertisement
                .lock()
                .await
                .as_ref()
                .expect("advertisement should be active")
                .task
                .id();

            let updated = service
                .advertise_owner_group(
                    DeviceIdentity::from_persisted_secret(&owner_secret).unwrap(),
                    DeviceIdentity::from_persisted_secret(&owner_secret).unwrap(),
                    "Maya's PC".to_owned(),
                    vec![first_key, requested_key],
                )
                .await
                .unwrap();
            assert_eq!(updated.status, "advertising");
            let updated_task_id = service
                .advertisement
                .lock()
                .await
                .as_ref()
                .expect("advertisement should remain active")
                .task
                .id();
            assert_eq!(updated_task_id, first_task_id);
            assert_eq!(
                service
                    .owned_group_discovery_status(&[first_key, requested_key])
                    .await
                    .status,
                "advertising"
            );

            let search = service.search(DeviceIdentity::generate(), &requested);
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
            result
        });

        assert_eq!(result.status, "peerReachable");
        assert_eq!(result.discovered_peers, 1);
    }

    #[test]
    fn first_invitation_hints_start_the_owner_node_without_keys() {
        let now = unix_now();
        let group = GroupIdentity::generate();
        let (_, owner_secret) = DeviceIdentity::generate_persistable().unwrap();
        let owner = || DeviceIdentity::from_persisted_secret(&owner_secret).unwrap();
        let owner_id = owner().peer_id();
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
            let service = NetworkService::from_sources(&[], &format!("{address}/p2p/{routing_id}"))
                .unwrap()
                .without_lan_discovery();
            assert!(service.owner_address_hints().is_empty());
            let prepare = service.prepare_owner_address_hints(
                owner(),
                owner(),
                "Maya's PC".to_owned(),
                Vec::new(),
            );
            tokio::pin!(prepare);
            let hints = timeout(Duration::from_secs(10), async {
                loop {
                    tokio::select! {
                        hints = &mut prepare => break hints,
                        _ = routing.next_event() => {}
                    }
                }
            })
            .await
            .expect("hint preparation should complete");
            // A loopback relay yields no circuit hint, so the wait ends with
            // the node's direct addresses.
            assert!(!hints.is_empty());
            let first_task_id = service
                .advertisement
                .lock()
                .await
                .as_ref()
                .expect("owner node should keep running")
                .task
                .id();

            // The invitation issued with these hints joins the same node.
            let invitation = hinted_invitation(&group, owner_id, &hints, now);
            let key = DiscoveryKey::from_invitation(&invitation);
            let advertise =
                service.advertise_owner_group(owner(), owner(), "Maya's PC".to_owned(), vec![key]);
            tokio::pin!(advertise);
            let result = timeout(Duration::from_secs(10), async {
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
            assert_eq!(result.status, "advertising");
            let task_id = service
                .advertisement
                .lock()
                .await
                .as_ref()
                .expect("advertisement should remain active")
                .task
                .id();
            assert_eq!(task_id, first_task_id);
            assert_eq!(
                service
                    .prepare_owner_address_hints(
                        owner(),
                        owner(),
                        "Maya's PC".to_owned(),
                        vec![key]
                    )
                    .await,
                service.owner_address_hints()
            );
            service.stop_advertising().await;
        });
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
            let advertise = service.advertise_owner_group(
                owner,
                owner_signer,
                "Maya's PC".to_owned(),
                vec![key],
            );
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
            .unwrap()
            .without_lan_discovery();
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
                    membership: SyncMembershipState::default(),
                }
            );

            // Newly stored events reach the connected member as a notice;
            // other groups have no recipients.
            service.notify_group_events(DeviceIdentity::generate().peer_id());
            service.notify_group_events(invitation.group_id());
            let notice = timeout(Duration::from_secs(10), async {
                loop {
                    tokio::select! {
                        event = requester.next_event() => {
                            if let NetworkEvent::SyncRequestReceived {
                                peer_id,
                                request_id,
                                request,
                            } = event
                            {
                                if peer_id == owner_id {
                                    let _ = requester.send_sync_response(
                                        request_id,
                                        SyncResponse::Acknowledged {
                                            group_id: invitation.group_id(),
                                        },
                                    );
                                    break request;
                                }
                            }
                        },
                        _ = routing.next_event() => {}
                    }
                }
            })
            .await
            .expect("connected member should receive the owner's notice");
            assert_eq!(
                notice,
                SyncRequest::EventsAvailable {
                    group_id: invitation.group_id(),
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
    fn advertiser_serves_members_during_its_announcement_window() {
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
            // The routing node is never polled, so the announcement stays
            // pending for the whole window.
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
            let service = NetworkService::from_sources_with_authorizer(
                &[],
                &format!("{address}/p2p/{routing_id}"),
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
            .unwrap()
            .without_lan_discovery();
            let mut requester = NetworkNode::new(requester_identity.into_network_keypair());
            requester
                .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
                .unwrap();

            let advertise = service.advertise(owner, owner_signer, &invitation);
            tokio::pin!(advertise);
            let mut poll = interval(Duration::from_millis(20));
            let notice = timeout(PROVIDER_SEARCH_TIMEOUT, async {
                let mut dialed = false;
                loop {
                    tokio::select! {
                        result = &mut advertise => {
                            panic!("announcement window ended early: {result:?}");
                        }
                        _ = poll.tick(), if !dialed => {
                            let addresses = service
                                .owner_addresses
                                .lock()
                                .unwrap()
                                .iter()
                                .filter(|address| {
                                    address
                                        .iter()
                                        .any(|protocol| matches!(protocol, Protocol::Ip4(_)))
                                        && address
                                            .iter()
                                            .any(|protocol| matches!(protocol, Protocol::QuicV1))
                                })
                                .cloned()
                                .collect::<Vec<_>>();
                            if !addresses.is_empty() {
                                requester.dial_peer_at(owner_id, addresses).unwrap();
                                dialed = true;
                            }
                        }
                        event = requester.next_event() => match event {
                            NetworkEvent::PeerConnected { peer_id, .. } if peer_id == owner_id => {
                                requester
                                    .send_sync_request(
                                        owner_id,
                                        SyncRequest::Summary {
                                            group_id: invitation.group_id(),
                                        },
                                    )
                                    .unwrap();
                            }
                            NetworkEvent::SyncResponseReceived { peer_id, .. }
                                if peer_id == owner_id =>
                            {
                                service.notify_group_events(invitation.group_id());
                            }
                            NetworkEvent::SyncRequestReceived {
                                peer_id,
                                request_id,
                                request,
                            } if peer_id == owner_id => {
                                let _ = requester.send_sync_response(
                                    request_id,
                                    SyncResponse::Acknowledged {
                                        group_id: invitation.group_id(),
                                    },
                                );
                                break request;
                            }
                            _ => {}
                        },
                    }
                }
            })
            .await
            .expect("a member connected during the window should receive the notice");
            assert_eq!(
                notice,
                SyncRequest::EventsAvailable {
                    group_id: invitation.group_id(),
                }
            );
            // The advertiser still holds its lock, so read the recorded
            // member connection directly.
            assert!(service.last_connection.lock().unwrap().is_some());
        });
    }

    #[test]
    fn only_unreachable_owner_errors_fall_back_to_members() {
        for error in [
            "network_peer_not_found",
            "network_peer_unreachable",
            "network_search_timed_out",
        ] {
            assert!(super::owner_unreachable(error), "{error}");
        }
        for error in [
            "network_unavailable",
            "network_bootstrap_required",
            "synchronization_unauthorized",
            "synchronization_bandwidth_limited",
        ] {
            assert!(!super::owner_unreachable(error), "{error}");
        }
    }

    #[test]
    fn member_candidates_collect_across_search_steps() {
        let local = DeviceIdentity::generate().peer_id();
        let stranger = DeviceIdentity::generate().peer_id();
        let members: Vec<_> = (0..5)
            .map(|_| DeviceIdentity::generate().peer_id())
            .chain([local])
            .collect();
        let mut candidates = MemberCandidates::new(local, &members);
        assert!(!candidates.add(vec![stranger, local, members[0]]));
        assert!(!candidates.add(vec![members[0], members[1]]));
        assert!(candidates.add(vec![members[2], members[3], members[4]]));
        assert_eq!(
            candidates.finish(None),
            Ok(members[..MAX_MEMBER_PROVIDERS].to_vec())
        );

        let mut partial = MemberCandidates::new(local, &members);
        partial.add(vec![members[4]]);
        assert_eq!(
            partial.finish(Some("network_peer_not_found")),
            Ok(vec![members[4]])
        );

        let mut empty = MemberCandidates::new(local, &members);
        empty.add(vec![stranger, local]);
        assert_eq!(
            empty.finish(Some("network_search_timed_out")),
            Err("network_search_timed_out")
        );
    }

    #[test]
    fn member_pull_reaches_only_listed_current_members() {
        let directory = tempfile::tempdir().unwrap();
        let bandwidth = Arc::new(BandwidthService::new(
            directory.path().join("bandwidth.json"),
        ));
        let group_id = DeviceIdentity::generate().peer_id();
        let key = DiscoveryKey::derive(group_id, &[9; 32]);
        let [member, member_own] = identity_copies();
        let member_id = member.peer_id();
        let (puller, puller_again) = identity_pair();
        let puller_id = puller.peer_id();
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
            let service = |expected_peer| {
                NetworkService::from_sources_with_authorizer(
                    &[],
                    &bootstrap,
                    Arc::new(StaticJoinRequestAuthorizer(
                        JoinRequestAuthorization::Authorized,
                    )),
                    Arc::new(UnavailableMemberAdmissionService),
                    Arc::new(UnavailablePendingJoinService),
                    Arc::new(MemberSynchronizationService {
                        expected_peer,
                        group_id,
                    }),
                )
                .unwrap()
                .without_lan_discovery()
            };
            let serving = service(puller_id);
            let pulling = service(member_id);
            {
                let serve = serving.serve_member_group(
                    member,
                    owner_answers(member_own),
                    group_id,
                    key,
                    DeviceIdentity::generate().peer_id(),
                    Vec::new(),
                    Arc::clone(&bandwidth),
                );
                tokio::pin!(serve);
                let status = timeout(Duration::from_secs(10), async {
                    loop {
                        tokio::select! {
                            result = &mut serve => break result,
                            _ = routing.next_event() => {}
                        }
                    }
                })
                .await
                .expect("member advertisement should complete")
                .unwrap();
                assert_eq!(status, "advertising");
            }

            // A provider outside the current member list is never asked.
            {
                let pull = pulling.pull_from_members(puller, key, group_id, &[], &bandwidth);
                tokio::pin!(pull);
                let result = timeout(Duration::from_secs(15), async {
                    loop {
                        tokio::select! {
                            result = &mut pull => break result,
                            _ = routing.next_event() => {}
                        }
                    }
                })
                .await
                .expect("member search should end");
                assert!(matches!(
                    result,
                    Err("network_peer_not_found" | "network_search_timed_out")
                ));
            }

            let members = [puller_id, member_id];
            let pull = pulling.pull_from_members(puller_again, key, group_id, &members, &bandwidth);
            tokio::pin!(pull);
            let result = timeout(Duration::from_secs(15), async {
                loop {
                    tokio::select! {
                        result = &mut pull => break result,
                        _ = routing.next_event() => {}
                    }
                }
            })
            .await
            .expect("member pull should complete")
            .unwrap();
            assert_eq!(result.status, "memberSynchronized");
            assert_eq!(
                pulling.group_connection_states(&[group_id])[0].state,
                "memberServed"
            );
            assert_eq!(result.synchronized_events, 3);
            assert_eq!(result.uploaded_events, 0);
            assert_eq!(result.group_id, group_id.to_string());
        });
    }

    #[test]
    fn member_serving_node_is_discoverable_and_answers_owned_groups_as_owner() {
        let directory = tempfile::tempdir().unwrap();
        let bandwidth = Arc::new(BandwidthService::new(
            directory.path().join("bandwidth.json"),
        ));
        // Owner answers are not charged to the spent member budget.
        bandwidth
            .set(BandwidthPreference {
                sync_limit_mib_per_hour: Some(1),
            })
            .unwrap();
        bandwidth.charge_sync_bytes(2 * 1024 * 1024);
        let group_id = DeviceIdentity::generate().peer_id();
        let key = DiscoveryKey::derive(group_id, &[7; 32]);
        let [member, member_own, member_again, member_again_own] = identity_copies();
        let member_id = member.peer_id();
        let owner_id = DeviceIdentity::generate().peer_id();
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
            let service = NetworkService::from_sources_with_authorizer(
                &[],
                &format!("{address}/p2p/{routing_id}"),
                Arc::new(StaticJoinRequestAuthorizer(
                    JoinRequestAuthorization::Unavailable,
                )),
                Arc::new(UnavailableMemberAdmissionService),
                Arc::new(UnavailablePendingJoinService),
                Arc::new(MemberSynchronizationService {
                    expected_peer: requester_id,
                    group_id,
                }),
            )
            .unwrap()
            .without_lan_discovery();
            {
                let serve = service.serve_member_group(
                    member,
                    owner_answers(member_own),
                    group_id,
                    key,
                    owner_id,
                    Vec::new(),
                    Arc::clone(&bandwidth),
                );
                tokio::pin!(serve);
                let status = timeout(Duration::from_secs(10), async {
                    loop {
                        tokio::select! {
                            result = &mut serve => break result,
                            _ = routing.next_event() => {}
                        }
                    }
                })
                .await
                .expect("member advertisement should complete")
                .unwrap();
                assert_eq!(status, "advertising");
            }
            let first_task = service
                .member_serving
                .lock()
                .await
                .as_ref()
                .expect("member serving should be active")
                .task
                .id();
            // The same epoch key keeps the running node.
            assert_eq!(
                service
                    .serve_member_group(
                        member_again,
                        owner_answers(member_again_own),
                        group_id,
                        key,
                        owner_id,
                        Vec::new(),
                        Arc::clone(&bandwidth),
                    )
                    .await,
                Ok("advertising")
            );
            assert_eq!(
                service
                    .member_serving
                    .lock()
                    .await
                    .as_ref()
                    .unwrap()
                    .task
                    .id(),
                first_task
            );

            let mut requester = NetworkNode::new(requester_identity.into_network_keypair());
            requester
                .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
                .unwrap();
            requester.add_bootstrap_peer(routing_id, address);
            requester.bootstrap().unwrap();
            requester.find_group_peers(key);

            let response = timeout(Duration::from_secs(10), async {
                let mut request_sent = false;
                loop {
                    tokio::select! {
                        event = requester.next_event() => match event {
                            NetworkEvent::GroupPeersFound { providers, .. }
                                if providers.contains(&member_id) && !request_sent =>
                            {
                                requester
                                    .send_sync_request(
                                        member_id,
                                        SyncRequest::Summary { group_id },
                                    )
                                    .unwrap();
                                request_sent = true;
                            }
                            NetworkEvent::SyncResponseReceived {
                                peer_id,
                                response,
                                ..
                            } if peer_id == member_id => break response,
                            _ => {}
                        },
                        _ = routing.next_event() => {}
                    }
                }
            })
            .await
            .expect("member serving node should answer the pull");
            assert_eq!(
                response,
                SyncResponse::Summary {
                    group_id,
                    heads: Vec::new(),
                    membership: SyncMembershipState::default(),
                }
            );

            // Join requests reach the owner authorizer, which admits only for
            // owned groups.
            requester.send_join_request(
                member_id,
                JoinRequest::from_invitation(&join_invitation(), vec![1]).unwrap(),
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
                                if peer_id == member_id {
                                    break response;
                                }
                            }
                        },
                        _ = routing.next_event() => {}
                    }
                }
            })
            .await
            .expect("join request should receive a response");
            assert_eq!(join_response.rejection(), Some(JoinRejectReason::Busy));

            let serving_task = service
                .member_serving
                .lock()
                .await
                .as_ref()
                .unwrap()
                .task
                .abort_handle();
            service.stop_member_serving().await;
            timeout(Duration::from_secs(1), async {
                while !serving_task.is_finished() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("stopping should end the member serving node");
        });
    }

    #[test]
    fn member_serving_node_connects_to_the_owner_and_reports_its_notices() {
        let directory = tempfile::tempdir().unwrap();
        let bandwidth = Arc::new(BandwidthService::new(
            directory.path().join("bandwidth.json"),
        ));
        let group_id = DeviceIdentity::generate().peer_id();
        let key = DiscoveryKey::derive(group_id, &[8; 32]);
        let [member, member_own] = identity_copies();
        let member_id = member.peer_id();
        tauri::async_runtime::block_on(async {
            let owner_identity = DeviceIdentity::generate();
            let owner_id = owner_identity.peer_id();
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
            let mut owner = NetworkNode::new(owner_identity.into_network_keypair());
            owner
                .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
                .unwrap();
            let owner_address = loop {
                if let NetworkEvent::Listening { address } = owner.next_event().await {
                    break address;
                }
            };
            let service = NetworkService::from_sources_with_authorizer(
                &[],
                &format!("{address}/p2p/{routing_id}"),
                Arc::new(StaticJoinRequestAuthorizer(
                    JoinRequestAuthorization::Authorized,
                )),
                Arc::new(UnavailableMemberAdmissionService),
                Arc::new(UnavailablePendingJoinService),
                Arc::new(MemberSynchronizationService {
                    expected_peer: owner_id,
                    group_id,
                }),
            )
            .unwrap()
            .without_lan_discovery();
            let mut notices = service.subscribe_event_notices();
            {
                let serve = service.serve_member_group(
                    member,
                    owner_answers(member_own),
                    group_id,
                    key,
                    owner_id,
                    vec![owner_address],
                    Arc::clone(&bandwidth),
                );
                tokio::pin!(serve);
                let status = timeout(Duration::from_secs(10), async {
                    loop {
                        tokio::select! {
                            result = &mut serve => break result,
                            _ = routing.next_event() => {}
                            _ = owner.next_event() => {}
                        }
                    }
                })
                .await
                .expect("member advertisement should complete")
                .unwrap();
                assert_eq!(status, "advertising");
            }

            // The member dials the owner, which notices over that connection.
            let response = timeout(Duration::from_secs(10), async {
                loop {
                    tokio::select! {
                        event = owner.next_event() => match event {
                            NetworkEvent::PeerConnected { peer_id, .. } if peer_id == member_id => {
                                owner
                                    .send_sync_request(
                                        member_id,
                                        SyncRequest::EventsAvailable { group_id },
                                    )
                                    .unwrap();
                            }
                            NetworkEvent::SyncResponseReceived {
                                peer_id,
                                response,
                                ..
                            } if peer_id == member_id => break response,
                            _ => {}
                        },
                        _ = routing.next_event() => {}
                    }
                }
            })
            .await
            .expect("member should acknowledge the owner's notice");
            assert_eq!(response, SyncResponse::Acknowledged { group_id });
            assert_eq!(notices.try_recv(), Ok(group_id));
        });
    }

    #[test]
    fn member_serving_node_keeps_the_owner_connection_without_bootstrap_nodes() {
        let directory = tempfile::tempdir().unwrap();
        let bandwidth = Arc::new(BandwidthService::new(
            directory.path().join("bandwidth.json"),
        ));
        let group_id = DeviceIdentity::generate().peer_id();
        let key = DiscoveryKey::derive(group_id, &[10; 32]);
        let [member, member_own] = identity_copies();
        let member_id = member.peer_id();
        tauri::async_runtime::block_on(async {
            let owner_identity = DeviceIdentity::generate();
            let owner_id = owner_identity.peer_id();
            let mut owner = NetworkNode::new(owner_identity.into_network_keypair());
            owner
                .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
                .unwrap();
            let owner_address = loop {
                if let NetworkEvent::Listening { address } = owner.next_event().await {
                    break address;
                }
            };
            let service = NetworkService::from_sources_with_authorizer(
                &[],
                "",
                Arc::new(StaticJoinRequestAuthorizer(
                    JoinRequestAuthorization::Authorized,
                )),
                Arc::new(UnavailableMemberAdmissionService),
                Arc::new(UnavailablePendingJoinService),
                Arc::new(MemberSynchronizationService {
                    expected_peer: owner_id,
                    group_id,
                }),
            )
            .unwrap()
            .without_lan_discovery();
            // Without a remembered owner address there is nothing to dial.
            let [unserved, unserved_own] = identity_copies();
            assert_eq!(
                service
                    .serve_member_group(
                        unserved,
                        owner_answers(unserved_own),
                        group_id,
                        key,
                        owner_id,
                        Vec::new(),
                        Arc::clone(&bandwidth),
                    )
                    .await,
                Ok("bootstrapRequired")
            );
            assert!(service.member_serving.lock().await.is_none());

            let mut notices = service.subscribe_event_notices();
            // The key is not advertised, but the owner connection is kept.
            assert_eq!(
                service
                    .serve_member_group(
                        member,
                        owner_answers(member_own),
                        group_id,
                        key,
                        owner_id,
                        vec![owner_address],
                        Arc::clone(&bandwidth),
                    )
                    .await,
                Ok("bootstrapRequired")
            );
            let response = timeout(Duration::from_secs(10), async {
                loop {
                    match owner.next_event().await {
                        NetworkEvent::PeerConnected { peer_id, .. } if peer_id == member_id => {
                            owner
                                .send_sync_request(
                                    member_id,
                                    SyncRequest::EventsAvailable { group_id },
                                )
                                .unwrap();
                        }
                        NetworkEvent::SyncResponseReceived {
                            peer_id, response, ..
                        } if peer_id == member_id => break response,
                        _ => {}
                    }
                }
            })
            .await
            .expect("member should acknowledge the owner's notice");
            assert_eq!(response, SyncResponse::Acknowledged { group_id });
            assert_eq!(notices.try_recv(), Ok(group_id));
        });
    }

    #[test]
    fn synchronization_reuses_the_member_serving_connection_to_the_owner() {
        let directory = tempfile::tempdir().unwrap();
        let bandwidth = Arc::new(BandwidthService::new(
            directory.path().join("bandwidth.json"),
        ));
        let group_id = DeviceIdentity::generate().peer_id();
        let key = DiscoveryKey::derive(group_id, &[9; 32]);
        let [member, member_own, member_again] = identity_copies();
        let member_id = member.peer_id();
        tauri::async_runtime::block_on(async {
            let owner_identity = DeviceIdentity::generate();
            let owner_id = owner_identity.peer_id();
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
            let mut owner = NetworkNode::new(owner_identity.into_network_keypair());
            owner
                .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
                .unwrap();
            let owner_address = loop {
                if let NetworkEvent::Listening { address } = owner.next_event().await {
                    break address;
                }
            };
            let service = NetworkService::from_sources_with_authorizer(
                &[],
                &format!("{address}/p2p/{routing_id}"),
                Arc::new(StaticJoinRequestAuthorizer(
                    JoinRequestAuthorization::Authorized,
                )),
                Arc::new(UnavailableMemberAdmissionService),
                Arc::new(UnavailablePendingJoinService),
                Arc::new(MemberSynchronizationService {
                    expected_peer: owner_id,
                    group_id,
                }),
            )
            .unwrap()
            .without_lan_discovery();
            let mut member_connections = 0;
            {
                let serve = service.serve_member_group(
                    member,
                    owner_answers(member_own),
                    group_id,
                    key,
                    owner_id,
                    vec![owner_address.clone()],
                    Arc::clone(&bandwidth),
                );
                tokio::pin!(serve);
                let status = timeout(Duration::from_secs(10), async {
                    loop {
                        tokio::select! {
                            result = &mut serve => break result,
                            _ = routing.next_event() => {}
                            event = owner.next_event() => {
                                if matches!(
                                    event,
                                    NetworkEvent::PeerConnected { peer_id, .. } if peer_id == member_id
                                ) {
                                    member_connections += 1;
                                }
                            }
                        }
                    }
                })
                .await
                .expect("member advertisement should complete")
                .unwrap();
                assert_eq!(status, "advertising");
            }
            // Wait until the serving node holds its connection to the owner.
            timeout(Duration::from_secs(10), async {
                while member_connections == 0 {
                    tokio::select! {
                        _ = routing.next_event() => {}
                        event = owner.next_event() => {
                            if matches!(
                                event,
                                NetworkEvent::PeerConnected { peer_id, .. } if peer_id == member_id
                            ) {
                                member_connections += 1;
                            }
                        }
                    }
                }
            })
            .await
            .expect("member serving node should connect to the owner");

            // No remembered address and no discovery record: only the open
            // serving connection can reach the owner.
            let synchronize =
                service.synchronize(member_again, key, group_id, owner_id, &[], &bandwidth);
            tokio::pin!(synchronize);
            let result = timeout(Duration::from_secs(15), async {
                loop {
                    tokio::select! {
                        result = &mut synchronize => break result,
                        _ = routing.next_event() => {}
                        event = owner.next_event() => match event {
                            NetworkEvent::PeerConnected { peer_id, .. } if peer_id == member_id => {
                                member_connections += 1;
                            }
                            NetworkEvent::SyncRequestReceived {
                                peer_id,
                                request_id,
                                request,
                            } if peer_id == member_id => {
                                let response = match request {
                                    SyncRequest::Summary { .. } => SyncResponse::Summary {
                                        group_id,
                                        heads: Vec::new(),
                                        membership: SyncMembershipState::default(),
                                    },
                                    SyncRequest::ReportHeads { .. } => SyncResponse::ObservedHeads {
                                        group_id,
                                        peers: Vec::new(),
                                    },
                                    _ => SyncResponse::Rejected {
                                        reason: SyncRejectReason::InvalidRequest,
                                    },
                                };
                                owner.send_sync_response(request_id, response).unwrap();
                            }
                            _ => {}
                        },
                    }
                }
            })
            .await
            .expect("synchronization should complete")
            .unwrap();
            assert_eq!(result.status, "synchronized");
            assert_eq!(result.synchronized_events, 3);
            assert_eq!(result.peer_address, owner_address);
            assert_eq!(member_connections, 1);
            assert_eq!(
                service.group_connection_states(&[group_id])[0].discovery,
                None
            );

            // The serving node got its node back and still answers notices.
            let mut notices = service.subscribe_event_notices();
            owner
                .send_sync_request(member_id, SyncRequest::EventsAvailable { group_id })
                .unwrap();
            let response = timeout(Duration::from_secs(10), async {
                loop {
                    tokio::select! {
                        event = owner.next_event() => {
                            if let NetworkEvent::SyncResponseReceived {
                                peer_id,
                                response,
                                ..
                            } = event
                            {
                                if peer_id == member_id {
                                    break response;
                                }
                            }
                        },
                        _ = routing.next_event() => {}
                    }
                }
            })
            .await
            .expect("member should acknowledge the owner's notice");
            assert_eq!(response, SyncResponse::Acknowledged { group_id });
            assert_eq!(notices.try_recv(), Ok(group_id));
        });
    }

    #[test]
    fn member_invitation_request_reuses_the_member_serving_connection_to_the_owner() {
        let directory = tempfile::tempdir().unwrap();
        let bandwidth = Arc::new(BandwidthService::new(
            directory.path().join("bandwidth.json"),
        ));
        let group_id = DeviceIdentity::generate().peer_id();
        let key = DiscoveryKey::derive(group_id, &[9; 32]);
        let [member, member_own, member_again] = identity_copies();
        let member_id = member.peer_id();
        tauri::async_runtime::block_on(async {
            let owner_identity = DeviceIdentity::generate();
            let owner_id = owner_identity.peer_id();
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
            let mut owner = NetworkNode::new(owner_identity.into_network_keypair());
            owner
                .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
                .unwrap();
            let owner_address = loop {
                if let NetworkEvent::Listening { address } = owner.next_event().await {
                    break address;
                }
            };
            let service = NetworkService::from_sources_with_authorizer(
                &[],
                &format!("{address}/p2p/{routing_id}"),
                Arc::new(StaticJoinRequestAuthorizer(
                    JoinRequestAuthorization::Authorized,
                )),
                Arc::new(UnavailableMemberAdmissionService),
                Arc::new(UnavailablePendingJoinService),
                Arc::new(MemberSynchronizationService {
                    expected_peer: owner_id,
                    group_id,
                }),
            )
            .unwrap()
            .without_lan_discovery();
            let mut member_connections = 0;
            {
                let serve = service.serve_member_group(
                    member,
                    owner_answers(member_own),
                    group_id,
                    key,
                    owner_id,
                    vec![owner_address.clone()],
                    Arc::clone(&bandwidth),
                );
                tokio::pin!(serve);
                let status = timeout(Duration::from_secs(10), async {
                    loop {
                        tokio::select! {
                            result = &mut serve => break result,
                            _ = routing.next_event() => {}
                            event = owner.next_event() => {
                                if matches!(
                                    event,
                                    NetworkEvent::PeerConnected { peer_id, .. } if peer_id == member_id
                                ) {
                                    member_connections += 1;
                                }
                            }
                        }
                    }
                })
                .await
                .expect("member advertisement should complete")
                .unwrap();
                assert_eq!(status, "advertising");
            }
            // Wait until the serving node holds its connection to the owner.
            timeout(Duration::from_secs(10), async {
                while member_connections == 0 {
                    tokio::select! {
                        _ = routing.next_event() => {}
                        event = owner.next_event() => {
                            if matches!(
                                event,
                                NetworkEvent::PeerConnected { peer_id, .. } if peer_id == member_id
                            ) {
                                member_connections += 1;
                            }
                        }
                    }
                }
            })
            .await
            .expect("member serving node should connect to the owner");

            // No remembered address and no discovery record: only the open
            // serving connection can reach the owner.
            let request = service.request_member_invitation(
                member_again,
                key,
                group_id,
                owner_id,
                &[],
                3_600,
            );
            tokio::pin!(request);
            let result = timeout(Duration::from_secs(15), async {
                loop {
                    tokio::select! {
                        result = &mut request => break result,
                        _ = routing.next_event() => {}
                        event = owner.next_event() => match event {
                            NetworkEvent::PeerConnected { peer_id, .. } if peer_id == member_id => {
                                member_connections += 1;
                            }
                            NetworkEvent::InviteRequestReceived {
                                peer_id,
                                request_id,
                                request,
                            } if peer_id == member_id => {
                                assert_eq!(request.group_id(), group_id);
                                owner
                                    .send_invite_response(
                                        request_id,
                                        charp2p_core::InviteResponse::rejected(
                                            charp2p_core::InviteRejectReason::Unauthorized,
                                        ),
                                    )
                                    .unwrap();
                            }
                            _ => {}
                        },
                    }
                }
            })
            .await
            .expect("invitation request should complete");
            assert_eq!(result.err(), Some("invite_unauthorized"));
            assert_eq!(member_connections, 1);
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
