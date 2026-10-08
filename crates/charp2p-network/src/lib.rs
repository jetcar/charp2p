#![forbid(unsafe_code)]

//! Portable libp2p transport and peer-discovery foundation for CharP2P.

mod invite_codec;
mod ip_limits;
mod join_codec;

use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};

use charp2p_core::{
    DiscoveryKey, InviteRejectReason, InviteRequest, InviteResponse, JoinRejectReason, JoinRequest,
    JoinResponse, MAX_SYNC_RESPONSE_BYTES, SyncError, SyncRejectReason, SyncRequest, SyncResponse,
};
use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder, allow_block_list, connection_limits, dcutr, identify,
    identity::Keypair,
    kad, mdns,
    multiaddr::Protocol,
    noise, ping, relay, request_response,
    swarm::{
        NetworkBehaviour, StreamProtocol, SwarmEvent, behaviour::toggle::Toggle,
        dial_opts::DialOpts,
    },
    yamux,
};
use thiserror::Error;

use crate::{invite_codec::InviteCodec, join_codec::JoinCodec};

const IDENTIFY_PROTOCOL: &str = "/charp2p/identify/1.0.0";
const AGENT_VERSION: &str = concat!("charp2p/", env!("CARGO_PKG_VERSION"));
const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);
const SYNC_PROTOCOL: &str = "/charp2p/sync/2.0.0";
const SYNC_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const JOIN_PROTOCOL: &str = "/charp2p/join/1.0.0";
const JOIN_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const INVITE_PROTOCOL: &str = "/charp2p/invite/1.0.0";
const INVITE_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_SYNC_WIRE_REQUEST_BYTES: u64 = (MAX_SYNC_RESPONSE_BYTES + 128 * 1024) as u64;
const MAX_SYNC_WIRE_RESPONSE_BYTES: u64 = (MAX_SYNC_RESPONSE_BYTES + 128 * 1024) as u64;
const RELAY_RESERVATION_DURATION: Duration = Duration::from_secs(60 * 60);
const RELAY_CIRCUIT_DURATION: Duration = Duration::from_secs(5 * 60);
const RELAY_CIRCUIT_BYTES: u64 = 32 * 1024 * 1024;
const MAX_RELAY_CIRCUITS: u32 = 32;
const MEBIBYTE: u64 = 1024 * 1024;
const MAX_PENDING_INCOMING_CONNECTIONS: u32 = 128;
const MAX_ESTABLISHED_INCOMING_CONNECTIONS: u32 = 1_024;
const MAX_ESTABLISHED_CONNECTIONS_PER_PEER: u32 = 4;
const MAX_ESTABLISHED_INCOMING_CONNECTIONS_PER_IP: u32 = 16;
/// Provider records expire quickly; online advertisers republish well
/// within the lifetime and the app refreshes its own publication every five
/// minutes.
const PROVIDER_RECORD_TTL: Duration = Duration::from_secs(30 * 60);
const PROVIDER_PUBLICATION_INTERVAL: Duration = Duration::from_secs(10 * 60);
const DISCOVERY_KEY_BYTES: usize = 32;
const MAX_PROVIDER_KEYS: usize = 1_024;
const MAX_PROVIDERS_PER_KEY: usize = 20;
const MAX_PROVIDER_ADDRESSES: usize = 8;
const MAX_PROVIDER_ADDRESS_BYTES: usize = 256;

#[derive(NetworkBehaviour)]
struct Behaviour {
    blocked_peers: allow_block_list::Behaviour<allow_block_list::BlockedPeers>,
    connection_limits: connection_limits::Behaviour,
    ip_limits: ip_limits::Behaviour,
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    dht: kad::Behaviour<kad::store::MemoryStore>,
    join: request_response::Behaviour<JoinCodec>,
    invite: request_response::Behaviour<InviteCodec>,
    sync: request_response::cbor::Behaviour<SyncRequest, SyncResponse>,
    relay_client: relay::client::Behaviour,
    relay_server: Toggle<relay::Behaviour>,
    hole_punching: Toggle<dcutr::Behaviour>,
    lan_discovery: Toggle<mdns::tokio::Behaviour>,
}

impl Behaviour {
    fn new(
        identity: &Keypair,
        dht_mode: kad::Mode,
        relay_client: relay::client::Behaviour,
        relay_server: Option<relay::Config>,
        connection_limits: connection_limits::ConnectionLimits,
        max_inbound_per_ip: Option<u32>,
        lan_discovery: bool,
    ) -> Self {
        let peer_id = identity.public().to_peer_id();
        // Routing and contributor nodes serve inbound peers; only client nodes
        // upgrade their own relayed connections through coordinated NAT
        // traversal.
        let hole_punching = (dht_mode == kad::Mode::Client).then(|| dcutr::Behaviour::new(peer_id));
        // mDNS is an additional discovery path only: when the multicast socket
        // cannot be opened, the node keeps working through the DHT.
        let lan_discovery = lan_discovery
            .then(|| mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id).ok())
            .flatten();
        // Serving nodes store only validated provider records for opaque
        // discovery keys (see `accepted_provider_record`); value records are
        // never stored because CharP2P does not publish any.
        let mut dht_config = kad::Config::new(kad::PROTOCOL_NAME);
        dht_config
            .set_record_filtering(kad::StoreInserts::FilterBoth)
            .set_provider_record_ttl(Some(PROVIDER_RECORD_TTL))
            .set_provider_publication_interval(Some(PROVIDER_PUBLICATION_INTERVAL));
        let dht_store = kad::store::MemoryStore::with_config(
            peer_id,
            kad::store::MemoryStoreConfig {
                max_records: MAX_PROVIDER_KEYS,
                max_value_bytes: 0,
                max_providers_per_key: MAX_PROVIDERS_PER_KEY,
                max_provided_keys: MAX_PROVIDER_KEYS,
            },
        );
        let mut dht = kad::Behaviour::with_config(peer_id, dht_store, dht_config);
        dht.set_mode(Some(dht_mode));
        let join = request_response::Behaviour::with_codec(
            JoinCodec,
            [(
                StreamProtocol::new(JOIN_PROTOCOL),
                request_response::ProtocolSupport::Full,
            )],
            request_response::Config::default()
                .with_request_timeout(JOIN_REQUEST_TIMEOUT)
                .with_max_concurrent_streams(16),
        );
        let invite = request_response::Behaviour::with_codec(
            InviteCodec,
            [(
                StreamProtocol::new(INVITE_PROTOCOL),
                request_response::ProtocolSupport::Full,
            )],
            request_response::Config::default()
                .with_request_timeout(INVITE_REQUEST_TIMEOUT)
                .with_max_concurrent_streams(16),
        );
        let sync_codec = request_response::cbor::codec::Codec::default()
            .set_request_size_maximum(MAX_SYNC_WIRE_REQUEST_BYTES)
            .set_response_size_maximum(MAX_SYNC_WIRE_RESPONSE_BYTES);
        let sync = request_response::Behaviour::with_codec(
            sync_codec,
            [(
                StreamProtocol::new(SYNC_PROTOCOL),
                request_response::ProtocolSupport::Full,
            )],
            request_response::Config::default()
                .with_request_timeout(SYNC_REQUEST_TIMEOUT)
                .with_max_concurrent_streams(32),
        );

        Self {
            blocked_peers: allow_block_list::Behaviour::default(),
            connection_limits: connection_limits::Behaviour::new(connection_limits),
            ip_limits: ip_limits::Behaviour::new(max_inbound_per_ip),
            ping: ping::Behaviour::new(ping::Config::new()),
            identify: identify::Behaviour::new(
                identify::Config::new(IDENTIFY_PROTOCOL.to_owned(), identity.public())
                    .with_agent_version(AGENT_VERSION.to_owned()),
            ),
            dht,
            join,
            invite,
            sync,
            relay_client,
            relay_server: Toggle::from(
                relay_server.map(|config| relay::Behaviour::new(peer_id, config)),
            ),
            hole_punching: Toggle::from(hole_punching),
            lan_discovery: Toggle::from(lan_discovery),
        }
    }
}

/// Connection bounds for nodes that accept inbound peers on behalf of the
/// network. Client nodes dial only the peers they need and stay unbounded.
fn serving_connection_limits() -> connection_limits::ConnectionLimits {
    connection_limits::ConnectionLimits::default()
        .with_max_pending_incoming(Some(MAX_PENDING_INCOMING_CONNECTIONS))
        .with_max_established_incoming(Some(MAX_ESTABLISHED_INCOMING_CONNECTIONS))
        .with_max_established_per_peer(Some(MAX_ESTABLISHED_CONNECTIONS_PER_PEER))
}

/// Relay capacity chosen by a routing node operator or an opted-in desktop
/// contributor. Both limits stay within the fixed bounds of ADR-026 and
/// ADR-031.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayLimits {
    max_circuits: u32,
    max_circuit_bytes: u64,
}

impl RelayLimits {
    /// Validates the simultaneous circuit count and the per-circuit byte limit
    /// in whole MiB.
    pub fn new(max_circuits: u32, max_circuit_mib: u32) -> Result<Self, NetworkError> {
        let max_circuit_bytes = u64::from(max_circuit_mib) * MEBIBYTE;
        if !(1..=MAX_RELAY_CIRCUITS).contains(&max_circuits)
            || !(MEBIBYTE..=RELAY_CIRCUIT_BYTES).contains(&max_circuit_bytes)
        {
            return Err(NetworkError::RelayLimits);
        }
        Ok(Self {
            max_circuits,
            max_circuit_bytes,
        })
    }

    /// Returns the largest relay capacity any node may offer.
    pub fn maximum() -> Self {
        Self {
            max_circuits: MAX_RELAY_CIRCUITS,
            max_circuit_bytes: RELAY_CIRCUIT_BYTES,
        }
    }

    /// Returns the most relayed bytes these limits allow per circuit duration.
    pub fn max_bytes_per_circuit_period(&self) -> u64 {
        u64::from(self.max_circuits) * self.max_circuit_bytes
    }

    /// Returns how long one relayed circuit may stay open.
    pub fn circuit_duration() -> Duration {
        RELAY_CIRCUIT_DURATION
    }

    fn server_config(&self) -> relay::Config {
        relay::Config {
            max_reservations: self.max_circuits as usize,
            max_reservations_per_peer: 1,
            reservation_duration: RELAY_RESERVATION_DURATION,
            max_circuits: self.max_circuits as usize,
            max_circuits_per_peer: self.max_circuits.min(4) as usize,
            max_circuit_duration: RELAY_CIRCUIT_DURATION,
            max_circuit_bytes: self.max_circuit_bytes,
            ..Default::default()
        }
    }
}

/// A client-mode CharP2P node using authenticated direct and relayed transport.
pub struct NetworkNode {
    swarm: Swarm<Behaviour>,
    relay_server: bool,
    discovery_queries: HashMap<kad::QueryId, DiscoveryKey>,
    lan_addresses: HashSet<Multiaddr>,
    pending_sync_responses:
        HashMap<InboundSyncRequestId, request_response::ResponseChannel<SyncResponse>>,
    pending_join_responses:
        HashMap<InboundJoinRequestId, request_response::ResponseChannel<JoinResponse>>,
    pending_invite_responses:
        HashMap<InboundInviteRequestId, request_response::ResponseChannel<InviteResponse>>,
}

impl NetworkNode {
    /// Builds a node from its persistent libp2p device identity.
    pub fn new(identity: Keypair) -> Self {
        Self::with_dht_mode(
            identity,
            kad::Mode::Client,
            None,
            connection_limits::ConnectionLimits::default(),
            None,
            false,
        )
    }

    /// Builds a client node that also announces itself and finds other
    /// CharP2P devices on the local network through mDNS. LAN discovery only
    /// adds addresses for peers; group membership is still established
    /// through invitation-bound DHT discovery and authenticated protocols.
    pub fn new_with_lan_discovery(identity: Keypair) -> Self {
        Self::with_dht_mode(
            identity,
            kad::Mode::Client,
            None,
            connection_limits::ConnectionLimits::default(),
            None,
            true,
        )
    }

    /// Builds a routing node that answers Kademlia queries from other peers
    /// and relays circuits within the maximum relay limits.
    pub fn new_routing(identity: Keypair) -> Self {
        Self::new_routing_with_relay(identity, Some(RelayLimits::maximum()))
    }

    /// Builds a routing node whose operator chose its relay capacity, or
    /// disabled relaying when no limits are given.
    pub fn new_routing_with_relay(identity: Keypair, relay: Option<RelayLimits>) -> Self {
        Self::with_dht_mode(
            identity,
            kad::Mode::Server,
            relay.map(|limits| limits.server_config()),
            serving_connection_limits(),
            Some(MAX_ESTABLISHED_INCOMING_CONNECTIONS_PER_IP),
            false,
        )
    }

    /// Builds an opted-in desktop contributor that answers Kademlia queries
    /// and, when relay limits are given, relays circuits within them.
    pub fn new_contributing(identity: Keypair, relay: Option<RelayLimits>) -> Self {
        Self::with_dht_mode(
            identity,
            kad::Mode::Server,
            relay.map(|limits| limits.server_config()),
            serving_connection_limits(),
            Some(MAX_ESTABLISHED_INCOMING_CONNECTIONS_PER_IP),
            false,
        )
    }

    fn with_dht_mode(
        identity: Keypair,
        dht_mode: kad::Mode,
        relay_server: Option<relay::Config>,
        connection_limits: connection_limits::ConnectionLimits,
        max_inbound_per_ip: Option<u32>,
        lan_discovery: bool,
    ) -> Self {
        let relay_server_enabled = relay_server.is_some();
        let swarm = SwarmBuilder::with_existing_identity(identity)
            .with_tokio()
            .with_quic()
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .expect("relay transport construction is infallible")
            .with_behaviour(|identity, relay_client| {
                Behaviour::new(
                    identity,
                    dht_mode,
                    relay_client,
                    relay_server,
                    connection_limits,
                    max_inbound_per_ip,
                    lan_discovery,
                )
            })
            .expect("behaviour construction is infallible")
            .with_swarm_config(|config| {
                config.with_idle_connection_timeout(IDLE_CONNECTION_TIMEOUT)
            })
            .build();

        Self {
            swarm,
            relay_server: relay_server_enabled,
            discovery_queries: HashMap::new(),
            lan_addresses: HashSet::new(),
            pending_sync_responses: HashMap::new(),
            pending_join_responses: HashMap::new(),
            pending_invite_responses: HashMap::new(),
        }
    }

    /// Returns this node's authenticated peer identifier.
    pub fn peer_id(&self) -> PeerId {
        *self.swarm.local_peer_id()
    }

    /// Starts listening on a QUIC multiaddress.
    pub fn listen_on(&mut self, address: Multiaddr) -> Result<(), NetworkError> {
        self.swarm.listen_on(address)?;
        Ok(())
    }

    /// Requests a circuit-relay reservation and starts listening through it.
    pub fn reserve_relay(
        &mut self,
        relay_peer_id: PeerId,
        relay_address: Multiaddr,
    ) -> Result<(), NetworkError> {
        self.listen_on(
            relay_address
                .with(libp2p::multiaddr::Protocol::P2p(relay_peer_id))
                .with(libp2p::multiaddr::Protocol::P2pCircuit),
        )
    }

    /// Dials a peer multiaddress.
    pub fn dial(&mut self, address: Multiaddr) -> Result<(), NetworkError> {
        self.swarm.dial(address)?;
        Ok(())
    }

    /// Dials a discovered peer using addresses already learned by behaviours.
    pub fn dial_peer(&mut self, peer_id: PeerId) -> Result<(), NetworkError> {
        self.swarm.dial(peer_id)?;
        Ok(())
    }

    /// Dials a peer at previously remembered addresses. The connection only
    /// completes when the remote authenticates as `peer_id`.
    pub fn dial_peer_at(
        &mut self,
        peer_id: PeerId,
        addresses: Vec<Multiaddr>,
    ) -> Result<(), NetworkError> {
        self.swarm
            .dial(DialOpts::peer_id(peer_id).addresses(addresses).build())?;
        Ok(())
    }

    /// Registers a known bootstrap peer address with the routing table.
    pub fn add_bootstrap_peer(&mut self, peer_id: PeerId, address: Multiaddr) {
        self.swarm
            .behaviour_mut()
            .dht
            .add_address(&peer_id, address);
    }

    /// Refuses every connection with `peer_id` and closes existing ones. The
    /// block is local to this node and lasts until it is lifted or the node
    /// stops.
    pub fn block_peer(&mut self, peer_id: PeerId) {
        self.swarm.behaviour_mut().blocked_peers.block_peer(peer_id);
    }

    /// Lifts a local block so `peer_id` may connect again.
    pub fn unblock_peer(&mut self, peer_id: PeerId) {
        self.swarm
            .behaviour_mut()
            .blocked_peers
            .unblock_peer(peer_id);
    }

    /// Starts a Kademlia bootstrap query using configured peer addresses.
    pub fn bootstrap(&mut self) -> Result<(), NetworkError> {
        self.swarm.behaviour_mut().dht.bootstrap()?;
        Ok(())
    }

    /// Advertises this online peer for an invitation-scoped rendezvous key.
    pub fn announce_group(&mut self, key: DiscoveryKey) -> Result<(), NetworkError> {
        let query_id = self
            .swarm
            .behaviour_mut()
            .dht
            .start_providing(record_key(key))?;
        self.discovery_queries.insert(query_id, key);
        Ok(())
    }

    /// Stops periodically advertising this peer for a rendezvous key.
    pub fn stop_announcing_group(&mut self, key: DiscoveryKey) {
        self.swarm
            .behaviour_mut()
            .dht
            .stop_providing(&record_key(key));
    }

    /// Searches the DHT for peers advertising the same rendezvous key.
    pub fn find_group_peers(&mut self, key: DiscoveryKey) {
        let query_id = self
            .swarm
            .behaviour_mut()
            .dht
            .get_providers(record_key(key));
        self.discovery_queries.insert(query_id, key);
    }

    /// Sends a validated synchronization request to an authenticated peer.
    pub fn send_sync_request(
        &mut self,
        peer_id: PeerId,
        request: SyncRequest,
    ) -> Result<OutboundSyncRequestId, NetworkError> {
        request.validate()?;
        Ok(OutboundSyncRequestId(
            self.swarm
                .behaviour_mut()
                .sync
                .send_request(&peer_id, request),
        ))
    }

    /// Sends a bounded membership request to an authenticated peer.
    pub fn send_join_request(
        &mut self,
        peer_id: PeerId,
        request: JoinRequest,
    ) -> OutboundJoinRequestId {
        OutboundJoinRequestId(
            self.swarm
                .behaviour_mut()
                .join
                .send_request(&peer_id, request),
        )
    }

    /// Sends a bounded membership response to a previously surfaced request.
    pub fn send_join_response(
        &mut self,
        request_id: InboundJoinRequestId,
        response: JoinResponse,
    ) -> Result<(), NetworkError> {
        let channel = self
            .pending_join_responses
            .remove(&request_id)
            .ok_or(NetworkError::UnknownJoinRequest)?;
        self.swarm
            .behaviour_mut()
            .join
            .send_response(channel, response)
            .map_err(|_| NetworkError::JoinResponseChannelClosed)
    }

    /// Rejects an inbound membership request without disclosing group state.
    pub fn reject_join_request(
        &mut self,
        request_id: InboundJoinRequestId,
        reason: JoinRejectReason,
    ) -> Result<(), NetworkError> {
        self.send_join_response(request_id, JoinResponse::rejected(reason))
    }

    /// Asks a group owner device for an invitation on behalf of a permitted
    /// member (ADR-036).
    pub fn send_invite_request(
        &mut self,
        peer_id: PeerId,
        request: InviteRequest,
    ) -> OutboundInviteRequestId {
        OutboundInviteRequestId(
            self.swarm
                .behaviour_mut()
                .invite
                .send_request(&peer_id, request),
        )
    }

    /// Sends an issued invitation or rejection to a previously surfaced
    /// invite request.
    pub fn send_invite_response(
        &mut self,
        request_id: InboundInviteRequestId,
        response: InviteResponse,
    ) -> Result<(), NetworkError> {
        let channel = self
            .pending_invite_responses
            .remove(&request_id)
            .ok_or(NetworkError::UnknownInviteRequest)?;
        self.swarm
            .behaviour_mut()
            .invite
            .send_response(channel, response)
            .map_err(|_| NetworkError::InviteResponseChannelClosed)
    }

    /// Rejects an inbound invite request without revealing which check failed.
    pub fn reject_invite_request(
        &mut self,
        request_id: InboundInviteRequestId,
        reason: InviteRejectReason,
    ) -> Result<(), NetworkError> {
        self.send_invite_response(request_id, InviteResponse::rejected(reason))
    }

    /// Sends a validated response to a previously surfaced inbound request.
    pub fn send_sync_response(
        &mut self,
        request_id: InboundSyncRequestId,
        response: SyncResponse,
    ) -> Result<(), NetworkError> {
        response.validate()?;
        let channel = self
            .pending_sync_responses
            .remove(&request_id)
            .ok_or(NetworkError::UnknownSyncRequest)?;
        self.swarm
            .behaviour_mut()
            .sync
            .send_response(channel, response)
            .map_err(|_| NetworkError::SyncResponseChannelClosed)
    }

    /// Rejects an inbound request without disclosing group state.
    pub fn reject_sync_request(
        &mut self,
        request_id: InboundSyncRequestId,
        reason: SyncRejectReason,
    ) -> Result<(), NetworkError> {
        self.send_sync_response(request_id, SyncResponse::Rejected { reason })
    }

    /// Waits for the next application-relevant network event.
    pub async fn next_event(&mut self) -> NetworkEvent {
        loop {
            match self.swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => {
                    if self.relay_server {
                        self.swarm.add_external_address(address.clone());
                    }
                    return NetworkEvent::Listening { address };
                }
                SwarmEvent::ConnectionEstablished {
                    peer_id, endpoint, ..
                } => {
                    let remote_address = transport_address(endpoint.get_remote_address());
                    // An address announced over mDNS was reachable on the local
                    // network segment even when it is not in a private range.
                    let path =
                        if !endpoint.is_relayed() && self.lan_addresses.contains(&remote_address) {
                            ConnectionPath::Lan
                        } else {
                            connection_path(&endpoint)
                        };
                    return NetworkEvent::PeerConnected {
                        peer_id,
                        path,
                        remote_address,
                    };
                }
                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    return NetworkEvent::PeerDisconnected { peer_id };
                }
                SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                    peer_id,
                    info,
                    ..
                })) => {
                    for address in info.listen_addrs.iter().cloned() {
                        self.swarm
                            .behaviour_mut()
                            .dht
                            .add_address(&peer_id, address);
                    }
                    return NetworkEvent::PeerIdentified {
                        peer_id,
                        listen_addresses: info.listen_addrs,
                    };
                }
                SwarmEvent::Behaviour(BehaviourEvent::LanDiscovery(mdns::Event::Discovered(
                    peers,
                ))) => {
                    for (peer_id, address) in &peers {
                        self.swarm.add_peer_address(*peer_id, address.clone());
                        self.lan_addresses.insert(transport_address(address));
                    }
                    return NetworkEvent::LanPeersDiscovered { peers };
                }
                SwarmEvent::Behaviour(BehaviourEvent::LanDiscovery(mdns::Event::Expired(
                    peers,
                ))) => {
                    for (_, address) in &peers {
                        self.lan_addresses.remove(&transport_address(address));
                    }
                    return NetworkEvent::LanPeersExpired { peers };
                }
                SwarmEvent::Behaviour(BehaviourEvent::RelayClient(
                    relay::client::Event::ReservationReqAccepted { relay_peer_id, .. },
                )) => {
                    return NetworkEvent::RelayReservationAccepted { relay_peer_id };
                }
                SwarmEvent::Behaviour(BehaviourEvent::HolePunching(dcutr::Event {
                    remote_peer_id,
                    result: Ok(_),
                })) => {
                    return NetworkEvent::DirectConnectionUpgraded {
                        peer_id: remote_peer_id,
                    };
                }
                SwarmEvent::Behaviour(BehaviourEvent::Dht(kad::Event::InboundRequest {
                    request:
                        kad::InboundRequest::AddProvider {
                            record: Some(record),
                        },
                })) => {
                    // A full store or per-key limit drops the record; the
                    // advertiser republishes and other close peers hold it.
                    if let Some(record) = accepted_provider_record(record) {
                        let _ = kad::store::RecordStore::add_provider(
                            self.swarm.behaviour_mut().dht.store_mut(),
                            record,
                        );
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Dht(
                    kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::StartProviding(result),
                        step,
                        ..
                    },
                )) => {
                    let key = self.discovery_queries.get(&id).copied();
                    if step.last {
                        self.discovery_queries.remove(&id);
                    }
                    if let Some(key) = key {
                        return match result {
                            Ok(_) => NetworkEvent::GroupAnnounced { key },
                            Err(_) => NetworkEvent::DiscoveryFailed {
                                key,
                                operation: DiscoveryOperation::Announcement,
                            },
                        };
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Dht(
                    kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::GetProviders(result),
                        step,
                        ..
                    },
                )) => {
                    let key = self.discovery_queries.get(&id).copied();
                    if step.last {
                        self.discovery_queries.remove(&id);
                    }
                    if let Some(key) = key {
                        return match result {
                            Ok(kad::GetProvidersOk::FoundProviders { providers, .. }) => {
                                let mut providers: Vec<_> = providers.into_iter().collect();
                                providers.sort();
                                NetworkEvent::GroupPeersFound { key, providers }
                            }
                            Ok(kad::GetProvidersOk::FinishedWithNoAdditionalRecord { .. }) => {
                                NetworkEvent::GroupPeerSearchFinished { key }
                            }
                            Err(_) => NetworkEvent::DiscoveryFailed {
                                key,
                                operation: DiscoveryOperation::Search,
                            },
                        };
                    }
                }
                SwarmEvent::Behaviour(BehaviourEvent::Join(request_response::Event::Message {
                    peer,
                    message:
                        request_response::Message::Request {
                            request_id,
                            request,
                            channel,
                        },
                    ..
                })) => {
                    let request_id = InboundJoinRequestId(request_id);
                    self.pending_join_responses.insert(request_id, channel);
                    return NetworkEvent::JoinRequestReceived {
                        peer_id: peer,
                        request_id,
                        request,
                    };
                }
                SwarmEvent::Behaviour(BehaviourEvent::Join(request_response::Event::Message {
                    peer,
                    message:
                        request_response::Message::Response {
                            request_id,
                            response,
                        },
                    ..
                })) => {
                    return NetworkEvent::JoinResponseReceived {
                        peer_id: peer,
                        request_id: OutboundJoinRequestId(request_id),
                        response,
                    };
                }
                SwarmEvent::Behaviour(BehaviourEvent::Join(
                    request_response::Event::OutboundFailure {
                        peer,
                        request_id,
                        error,
                        ..
                    },
                )) => {
                    return NetworkEvent::JoinRequestFailed {
                        peer_id: peer,
                        request_id: OutboundJoinRequestId(request_id),
                        failure: JoinFailure::from(error),
                    };
                }
                SwarmEvent::Behaviour(BehaviourEvent::Join(
                    request_response::Event::InboundFailure { request_id, .. },
                )) => {
                    self.pending_join_responses
                        .remove(&InboundJoinRequestId(request_id));
                }
                SwarmEvent::Behaviour(BehaviourEvent::Invite(
                    request_response::Event::Message {
                        peer,
                        message:
                            request_response::Message::Request {
                                request_id,
                                request,
                                channel,
                            },
                        ..
                    },
                )) => {
                    let request_id = InboundInviteRequestId(request_id);
                    self.pending_invite_responses.insert(request_id, channel);
                    return NetworkEvent::InviteRequestReceived {
                        peer_id: peer,
                        request_id,
                        request,
                    };
                }
                SwarmEvent::Behaviour(BehaviourEvent::Invite(
                    request_response::Event::Message {
                        peer,
                        message:
                            request_response::Message::Response {
                                request_id,
                                response,
                            },
                        ..
                    },
                )) => {
                    return NetworkEvent::InviteResponseReceived {
                        peer_id: peer,
                        request_id: OutboundInviteRequestId(request_id),
                        response,
                    };
                }
                SwarmEvent::Behaviour(BehaviourEvent::Invite(
                    request_response::Event::OutboundFailure {
                        peer,
                        request_id,
                        error,
                        ..
                    },
                )) => {
                    return NetworkEvent::InviteRequestFailed {
                        peer_id: peer,
                        request_id: OutboundInviteRequestId(request_id),
                        failure: JoinFailure::from(error),
                    };
                }
                SwarmEvent::Behaviour(BehaviourEvent::Invite(
                    request_response::Event::InboundFailure { request_id, .. },
                )) => {
                    self.pending_invite_responses
                        .remove(&InboundInviteRequestId(request_id));
                }
                SwarmEvent::Behaviour(BehaviourEvent::Sync(request_response::Event::Message {
                    peer,
                    message:
                        request_response::Message::Request {
                            request_id,
                            request,
                            channel,
                        },
                    ..
                })) => {
                    if request.validate().is_err() {
                        let _ = self.swarm.behaviour_mut().sync.send_response(
                            channel,
                            SyncResponse::Rejected {
                                reason: SyncRejectReason::InvalidRequest,
                            },
                        );
                        continue;
                    }
                    let request_id = InboundSyncRequestId(request_id);
                    self.pending_sync_responses.insert(request_id, channel);
                    return NetworkEvent::SyncRequestReceived {
                        peer_id: peer,
                        request_id,
                        request,
                    };
                }
                SwarmEvent::Behaviour(BehaviourEvent::Sync(request_response::Event::Message {
                    peer,
                    message:
                        request_response::Message::Response {
                            request_id,
                            response,
                        },
                    ..
                })) => {
                    let request_id = OutboundSyncRequestId(request_id);
                    return match response.validate() {
                        Ok(()) => NetworkEvent::SyncResponseReceived {
                            peer_id: peer,
                            request_id,
                            response,
                        },
                        Err(_) => NetworkEvent::SyncRequestFailed {
                            peer_id: peer,
                            request_id,
                            failure: SyncFailure::InvalidResponse,
                        },
                    };
                }
                SwarmEvent::Behaviour(BehaviourEvent::Sync(
                    request_response::Event::OutboundFailure {
                        peer,
                        request_id,
                        error,
                        ..
                    },
                )) => {
                    return NetworkEvent::SyncRequestFailed {
                        peer_id: peer,
                        request_id: OutboundSyncRequestId(request_id),
                        failure: SyncFailure::from(error),
                    };
                }
                SwarmEvent::Behaviour(BehaviourEvent::Sync(
                    request_response::Event::InboundFailure { request_id, .. },
                )) => {
                    self.pending_sync_responses
                        .remove(&InboundSyncRequestId(request_id));
                }
                _ => {}
            }
        }
    }
}

/// Opaque identifier for an inbound synchronization request awaiting response.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct InboundSyncRequestId(request_response::InboundRequestId);

/// Opaque identifier for an outbound synchronization request.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OutboundSyncRequestId(request_response::OutboundRequestId);

/// Opaque identifier for an inbound membership request awaiting response.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct InboundJoinRequestId(request_response::InboundRequestId);

/// Opaque identifier for an outbound membership request.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OutboundJoinRequestId(request_response::OutboundRequestId);

/// Opaque identifier for an inbound invite request awaiting response.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct InboundInviteRequestId(request_response::InboundRequestId);

/// Opaque identifier for an outbound invite request.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct OutboundInviteRequestId(request_response::OutboundRequestId);

/// Application-facing network lifecycle events.
#[derive(Debug)]
pub enum NetworkEvent {
    /// The local node started listening.
    Listening {
        /// Bound network address.
        address: Multiaddr,
    },
    /// A configured relay granted this node a bounded listen reservation.
    RelayReservationAccepted {
        /// Authenticated relay peer.
        relay_peer_id: PeerId,
    },
    /// A relayed connection was upgraded to a direct connection through
    /// coordinated NAT traversal (DCUtR). The direct connection is also
    /// reported as `PeerConnected`.
    DirectConnectionUpgraded {
        /// Remote peer identity authenticated by the direct connection.
        peer_id: PeerId,
    },
    /// An authenticated transport connection was established.
    PeerConnected {
        /// Remote peer identity authenticated by the negotiated transport.
        peer_id: PeerId,
        /// Whether this connection reached the peer directly or through a relay.
        path: ConnectionPath,
        /// Remote transport address without a trailing peer id; for dialled
        /// connections this is the address that reached the peer.
        remote_address: Multiaddr,
    },
    /// An authenticated connection ended.
    PeerDisconnected {
        /// Remote peer identity.
        peer_id: PeerId,
    },
    /// A peer supplied protocol and listen-address metadata.
    PeerIdentified {
        /// Remote peer identity.
        peer_id: PeerId,
        /// Addresses advertised by the remote Identify behaviour.
        listen_addresses: Vec<Multiaddr>,
    },
    /// mDNS found CharP2P devices on the local network. Their addresses are
    /// registered with the swarm, so `dial_peer` can reach them directly.
    LanPeersDiscovered {
        /// Local-network peer identities with one advertised address each.
        peers: Vec<(PeerId, Multiaddr)>,
    },
    /// mDNS records for local-network devices expired without renewal.
    LanPeersExpired {
        /// Peer identities and addresses that are no longer announced.
        peers: Vec<(PeerId, Multiaddr)>,
    },
    /// This node's provider record was published to the DHT.
    GroupAnnounced {
        /// Invitation-scoped rendezvous key.
        key: DiscoveryKey,
    },
    /// A DHT lookup returned peers sharing the rendezvous key.
    GroupPeersFound {
        /// Invitation-scoped rendezvous key.
        key: DiscoveryKey,
        /// Newly discovered provider identities.
        providers: Vec<PeerId>,
    },
    /// A provider search completed with no further records.
    GroupPeerSearchFinished {
        /// Invitation-scoped rendezvous key.
        key: DiscoveryKey,
    },
    /// A rendezvous DHT operation timed out.
    DiscoveryFailed {
        /// Invitation-scoped rendezvous key.
        key: DiscoveryKey,
        /// Operation that failed.
        operation: DiscoveryOperation,
    },
    /// A bounded membership request arrived from an authenticated peer.
    JoinRequestReceived {
        /// Authenticated transport peer that must match the MLS credential.
        peer_id: PeerId,
        /// Token used to send the response.
        request_id: InboundJoinRequestId,
        /// Structurally validated invitation and MLS KeyPackage.
        request: JoinRequest,
    },
    /// A bounded membership response arrived from an authenticated peer.
    JoinResponseReceived {
        /// Authenticated transport peer that processed the request.
        peer_id: PeerId,
        /// Original local request token.
        request_id: OutboundJoinRequestId,
        /// MLS Welcome or privacy-preserving rejection.
        response: JoinResponse,
    },
    /// An outbound membership request failed.
    JoinRequestFailed {
        /// Target peer.
        peer_id: PeerId,
        /// Original local request token.
        request_id: OutboundJoinRequestId,
        /// Stable failure category.
        failure: JoinFailure,
    },
    /// A bounded invite request arrived from an authenticated peer.
    InviteRequestReceived {
        /// Authenticated transport peer whose membership and permission the
        /// owner must recheck.
        peer_id: PeerId,
        /// Token used to send the response.
        request_id: InboundInviteRequestId,
        /// Requested group and lifetime.
        request: InviteRequest,
    },
    /// A bounded invite response arrived from an authenticated peer.
    InviteResponseReceived {
        /// Authenticated transport peer that processed the request.
        peer_id: PeerId,
        /// Original local request token.
        request_id: OutboundInviteRequestId,
        /// Issued invitation or privacy-preserving rejection.
        response: InviteResponse,
    },
    /// An outbound invite request failed; it uses the same transport failure
    /// categories as membership requests.
    InviteRequestFailed {
        /// Target peer.
        peer_id: PeerId,
        /// Original local request token.
        request_id: OutboundInviteRequestId,
        /// Stable failure category.
        failure: JoinFailure,
    },
    /// A validated synchronization request arrived from a connected peer.
    SyncRequestReceived {
        /// Authenticated transport peer.
        peer_id: PeerId,
        /// Token used to send the response.
        request_id: InboundSyncRequestId,
        /// Bounded and structurally validated request.
        request: SyncRequest,
    },
    /// A validated synchronization response arrived from a connected peer.
    SyncResponseReceived {
        /// Authenticated transport peer.
        peer_id: PeerId,
        /// Original local request token.
        request_id: OutboundSyncRequestId,
        /// Bounded response with verified event envelopes.
        response: SyncResponse,
    },
    /// An outbound synchronization request failed.
    SyncRequestFailed {
        /// Target peer.
        peer_id: PeerId,
        /// Original local request token.
        request_id: OutboundSyncRequestId,
        /// Stable failure category.
        failure: SyncFailure,
    },
}

/// Transport path used by an authenticated peer connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionPath {
    /// The endpoints established a direct connection.
    Direct,
    /// The endpoints established a direct connection over a local address.
    Lan,
    /// The endpoints connected through Circuit Relay v2.
    Relayed,
}

fn connection_path(endpoint: &libp2p::core::ConnectedPoint) -> ConnectionPath {
    if endpoint.is_relayed() {
        return ConnectionPath::Relayed;
    }

    if is_lan_address(endpoint.get_remote_address()) {
        ConnectionPath::Lan
    } else {
        ConnectionPath::Direct
    }
}

fn transport_address(address: &Multiaddr) -> Multiaddr {
    let mut address = address.clone();
    if matches!(address.iter().last(), Some(Protocol::P2p(_))) {
        address.pop();
    }
    address
}

fn is_lan_address(address: &Multiaddr) -> bool {
    address.iter().any(|protocol| match protocol {
        libp2p::multiaddr::Protocol::Ip4(address) => {
            address.is_private() || address.is_loopback() || address.is_link_local()
        }
        libp2p::multiaddr::Protocol::Ip6(address) => {
            address.is_loopback() || address.is_unique_local() || address.is_unicast_link_local()
        }
        _ => false,
    })
}

/// Stable membership transport failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JoinFailure {
    /// The peer could not be dialled.
    Dial,
    /// The request exceeded its deadline.
    Timeout,
    /// The authenticated connection ended before completion.
    ConnectionClosed,
    /// The peer does not implement the membership protocol version.
    UnsupportedProtocol,
    /// The peer stream failed or returned an invalid bounded message.
    Stream,
}

impl From<request_response::OutboundFailure> for JoinFailure {
    fn from(failure: request_response::OutboundFailure) -> Self {
        match failure {
            request_response::OutboundFailure::DialFailure => Self::Dial,
            request_response::OutboundFailure::Timeout => Self::Timeout,
            request_response::OutboundFailure::ConnectionClosed => Self::ConnectionClosed,
            request_response::OutboundFailure::UnsupportedProtocols => Self::UnsupportedProtocol,
            request_response::OutboundFailure::Io(_) => Self::Stream,
        }
    }
}

/// Stable synchronization transport failure categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncFailure {
    /// The peer could not be dialled.
    Dial,
    /// The request exceeded its deadline.
    Timeout,
    /// The authenticated connection ended before completion.
    ConnectionClosed,
    /// The peer does not implement the synchronization protocol version.
    UnsupportedProtocol,
    /// The peer stream failed during transfer.
    Stream,
    /// The peer returned a response that violated protocol validation.
    InvalidResponse,
}

impl From<request_response::OutboundFailure> for SyncFailure {
    fn from(failure: request_response::OutboundFailure) -> Self {
        match failure {
            request_response::OutboundFailure::DialFailure => Self::Dial,
            request_response::OutboundFailure::Timeout => Self::Timeout,
            request_response::OutboundFailure::ConnectionClosed => Self::ConnectionClosed,
            request_response::OutboundFailure::UnsupportedProtocols => Self::UnsupportedProtocol,
            request_response::OutboundFailure::Io(_) => Self::Stream,
        }
    }
}

/// Rendezvous operation associated with a discovery failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiscoveryOperation {
    /// Publishing the local provider record.
    Announcement,
    /// Searching for provider records.
    Search,
}

/// Failures while configuring or operating a network node.
#[derive(Debug, Error)]
pub enum NetworkError {
    /// The transport could not start listening.
    #[error("failed to listen on the requested address")]
    Listen(#[from] libp2p::TransportError<std::io::Error>),
    /// A peer address could not be dialled.
    #[error("failed to dial peer")]
    Dial(#[from] libp2p::swarm::DialError),
    /// No bootstrap peer is configured or the DHT query could not start.
    #[error("failed to start DHT bootstrap")]
    Bootstrap(#[from] kad::NoKnownPeers),
    /// The local DHT store rejected a provider record.
    #[error("failed to store the local DHT provider record")]
    ProviderStore(#[from] kad::store::Error),
    /// A locally created synchronization message violated protocol limits.
    #[error("invalid synchronization message")]
    Sync(#[from] SyncError),
    /// Relay contribution limits fall outside the supported bounds.
    #[error("relay limits are outside the supported bounds")]
    RelayLimits,
    /// The inbound request token is no longer pending.
    #[error("synchronization request is no longer awaiting a response")]
    UnknownSyncRequest,
    /// The peer stream closed before the response could be queued.
    #[error("synchronization response channel is closed")]
    SyncResponseChannelClosed,
    /// The inbound membership request token is no longer pending.
    #[error("membership request is no longer awaiting a response")]
    UnknownJoinRequest,
    /// The peer stream closed before the membership response could be queued.
    #[error("membership response channel is closed")]
    JoinResponseChannelClosed,
    /// The inbound invite request token is no longer pending.
    #[error("invite request is no longer awaiting a response")]
    UnknownInviteRequest,
    /// The peer stream closed before the invite response could be queued.
    #[error("invite response channel is closed")]
    InviteResponseChannelClosed,
}

/// Validates a provider record received by a serving node: the key must be a
/// 32-byte opaque discovery key, and at most a bounded number of
/// size-limited addresses are kept.
fn accepted_provider_record(mut record: kad::ProviderRecord) -> Option<kad::ProviderRecord> {
    if record.key.as_ref().len() != DISCOVERY_KEY_BYTES {
        return None;
    }
    record
        .addresses
        .retain(|address| address.len() <= MAX_PROVIDER_ADDRESS_BYTES);
    record.addresses.truncate(MAX_PROVIDER_ADDRESSES);
    Some(record)
}

fn record_key(key: DiscoveryKey) -> kad::RecordKey {
    kad::RecordKey::new(key.as_bytes())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use charp2p_core::{
        DiscoveryKey, GroupIdentity, HistoryPolicy, Invitation, InvitationSpec, InviteRejectReason,
        InviteRequest, InviteResponse, JoinRequest, JoinResponse, SyncAuthorHead, SyncRequest,
        SyncResponse,
    };
    use libp2p::{
        Multiaddr, PeerId, connection_limits, identity::Keypair, kad, multiaddr::Protocol,
    };
    use tokio::time::timeout;

    use super::{
        ConnectionPath, MAX_PROVIDER_ADDRESSES, NetworkEvent, NetworkNode, RELAY_CIRCUIT_DURATION,
        RelayLimits, accepted_provider_record, record_key,
    };

    const TEST_TIMEOUT: Duration = Duration::from_secs(10);
    const NOW: u64 = 1_800_000_000;

    #[test]
    fn local_ip_addresses_are_classified_as_lan() {
        assert!(super::is_lan_address(
            &"/ip4/192.168.1.8/udp/4001/quic-v1".parse().unwrap()
        ));
        assert!(super::is_lan_address(
            &"/ip6/fd00::8/udp/4001/quic-v1".parse().unwrap()
        ));
        assert!(!super::is_lan_address(
            &"/ip4/203.0.113.8/udp/4001/quic-v1".parse().unwrap()
        ));
    }

    #[tokio::test]
    async fn two_nodes_establish_an_authenticated_quic_connection() {
        let _ = connected_nodes().await;
    }

    #[tokio::test]
    async fn connected_peers_exchange_validated_sync_messages() {
        let (mut listener, mut dialer, listener_id, dialer_id) = connected_nodes().await;
        let group_id = GroupIdentity::generate().group_id();
        let outbound_id = dialer
            .send_sync_request(listener_id, SyncRequest::Summary { group_id })
            .unwrap();

        let (request_peer, inbound_id, request) =
            timeout(TEST_TIMEOUT, next_sync_request(&mut listener, &mut dialer))
                .await
                .expect("listener should receive the sync request");
        assert_eq!(request_peer, dialer_id);
        assert_eq!(request, SyncRequest::Summary { group_id });

        let response = SyncResponse::Summary {
            group_id,
            heads: vec![SyncAuthorHead {
                author_id: dialer_id,
                contiguous_sequence: 4,
            }],
        };
        listener
            .send_sync_response(inbound_id, response.clone())
            .unwrap();

        let (response_peer, received_id, received) =
            timeout(TEST_TIMEOUT, next_sync_response(&mut dialer, &mut listener))
                .await
                .expect("dialer should receive the sync response");
        assert_eq!(response_peer, listener_id);
        assert_eq!(received_id, outbound_id);
        assert_eq!(received, response);
    }

    #[tokio::test]
    async fn connected_peers_exchange_bounded_join_messages() {
        let (mut listener, mut dialer, listener_id, dialer_id) = connected_nodes().await;
        let invitation = Invitation::issue(
            &GroupIdentity::generate(),
            listener_id,
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
        let outbound_id = dialer.send_join_request(
            listener_id,
            JoinRequest::from_invitation(&invitation, vec![1, 2, 3]).unwrap(),
        );

        let (request_peer, inbound_id, request) =
            timeout(TEST_TIMEOUT, next_join_request(&mut listener, &mut dialer))
                .await
                .expect("listener should receive the join request");
        assert_eq!(request_peer, dialer_id);
        assert_eq!(request.group_id(), invitation.group_id());
        assert_eq!(request.invitation(), invitation.encode().unwrap());
        assert_eq!(request.key_package(), &[1, 2, 3]);

        listener
            .send_join_response(inbound_id, JoinResponse::accepted(vec![4, 5, 6]).unwrap())
            .unwrap();

        let (response_peer, received_id, response) =
            timeout(TEST_TIMEOUT, next_join_response(&mut dialer, &mut listener))
                .await
                .expect("dialer should receive the join response");
        assert_eq!(response_peer, listener_id);
        assert_eq!(received_id, outbound_id);
        assert_eq!(response.welcome(), Some([4, 5, 6].as_slice()));
    }

    #[tokio::test]
    async fn connected_peers_exchange_bounded_invite_messages() {
        let (mut listener, mut dialer, listener_id, dialer_id) = connected_nodes().await;
        let group = GroupIdentity::generate();
        let invitation = Invitation::issue(
            &group,
            listener_id,
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
        let outbound_id = dialer.send_invite_request(
            listener_id,
            InviteRequest::new(group.group_id(), 3_600).unwrap(),
        );

        let (request_peer, inbound_id, request) = timeout(TEST_TIMEOUT, async {
            loop {
                tokio::select! {
                    event = listener.next_event() => {
                        if let NetworkEvent::InviteRequestReceived { peer_id, request_id, request } = event {
                            return (peer_id, request_id, request);
                        }
                    }
                    _ = dialer.next_event() => {}
                }
            }
        })
        .await
        .expect("listener should receive the invite request");
        assert_eq!(request_peer, dialer_id);
        assert_eq!(request.group_id(), group.group_id());
        assert_eq!(request.lifetime_seconds(), 3_600);

        listener
            .send_invite_response(inbound_id, InviteResponse::issued(&invitation).unwrap())
            .unwrap();
        assert!(matches!(
            listener.send_invite_response(
                inbound_id,
                InviteResponse::rejected(InviteRejectReason::Busy)
            ),
            Err(super::NetworkError::UnknownInviteRequest)
        ));

        let (response_peer, received_id, response) = timeout(TEST_TIMEOUT, async {
            loop {
                tokio::select! {
                    event = dialer.next_event() => {
                        if let NetworkEvent::InviteResponseReceived { peer_id, request_id, response } = event {
                            return (peer_id, request_id, response);
                        }
                    }
                    _ = listener.next_event() => {}
                }
            }
        })
        .await
        .expect("dialer should receive the invite response");
        assert_eq!(response_peer, listener_id);
        assert_eq!(received_id, outbound_id);
        assert_eq!(
            response.invitation(),
            Some(invitation.encode().unwrap().as_str())
        );
    }

    #[test]
    fn relay_limits_stay_within_routing_node_bounds() {
        assert!(RelayLimits::new(0, 8).is_err());
        assert!(RelayLimits::new(33, 8).is_err());
        assert!(RelayLimits::new(4, 0).is_err());
        assert!(RelayLimits::new(4, 33).is_err());

        let limits = RelayLimits::new(4, 8).unwrap();
        assert_eq!(limits.max_bytes_per_circuit_period(), 32 * 1024 * 1024);
        let config = limits.server_config();
        assert_eq!(config.max_circuits, 4);
        assert_eq!(config.max_reservations, 4);
        assert_eq!(config.max_circuit_bytes, 8 * 1024 * 1024);
        assert_eq!(config.max_circuit_duration, RELAY_CIRCUIT_DURATION);

        let single = RelayLimits::new(1, 32).unwrap().server_config();
        assert_eq!(single.max_circuits_per_peer, 1);

        let maximum = RelayLimits::maximum();
        assert_eq!(maximum, RelayLimits::new(32, 32).unwrap());
        let config = maximum.server_config();
        assert_eq!(config.max_reservations, 32);
        assert_eq!(config.max_reservations_per_peer, 1);
        assert_eq!(config.max_circuits, 32);
        assert_eq!(config.max_circuits_per_peer, 4);
        assert_eq!(config.max_circuit_bytes, 32 * 1024 * 1024);
    }

    #[tokio::test]
    async fn routing_node_relays_an_authenticated_connection() {
        relays_an_authenticated_connection(NetworkNode::new_routing(Keypair::generate_ed25519()))
            .await;
    }

    #[tokio::test]
    async fn desktop_contributor_relays_within_its_limits() {
        relays_an_authenticated_connection(NetworkNode::new_contributing(
            Keypair::generate_ed25519(),
            Some(RelayLimits::new(2, 1).unwrap()),
        ))
        .await;
    }

    async fn relays_an_authenticated_connection(mut relay: NetworkNode) {
        let relay_id = relay.peer_id();
        relay
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
            .unwrap();
        let relay_address = next_listen_address(&mut relay).await;

        let mut destination = NetworkNode::new(Keypair::generate_ed25519());
        let destination_id = destination.peer_id();
        destination.reserve_relay(relay_id, relay_address).unwrap();
        let relayed_address = timeout(TEST_TIMEOUT, async {
            loop {
                tokio::select! {
                    event = destination.next_event() => {
                        if let NetworkEvent::Listening { address } = event
                            && address.iter().any(|protocol| protocol == Protocol::P2pCircuit)
                        {
                            break address;
                        }
                    }
                    _ = relay.next_event() => {}
                }
            }
        })
        .await
        .expect("relay should grant a listen reservation");

        let mut source = NetworkNode::new(Keypair::generate_ed25519());
        let source_id = source.peer_id();
        source.dial(relayed_address).unwrap();

        timeout(TEST_TIMEOUT, async {
            let mut source_connected = false;
            let mut destination_connected = false;
            while !source_connected || !destination_connected {
                tokio::select! {
                    event = source.next_event() => {
                        source_connected |= matches!(
                            event,
                            NetworkEvent::PeerConnected {
                                peer_id,
                                path: ConnectionPath::Relayed,
                                ..
                            } if peer_id == destination_id
                        );
                    }
                    event = destination.next_event() => {
                        destination_connected |= matches!(
                            event,
                            NetworkEvent::PeerConnected {
                                peer_id,
                                path: ConnectionPath::Relayed,
                                ..
                            } if peer_id == source_id
                        );
                    }
                    _ = relay.next_event() => {}
                }
            }
        })
        .await
        .expect("peers should connect through the routing node relay");
    }

    #[tokio::test]
    async fn client_nodes_upgrade_a_relayed_connection_to_a_direct_one() {
        let mut relay = NetworkNode::new_routing(Keypair::generate_ed25519());
        let relay_id = relay.peer_id();
        relay
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
            .unwrap();
        let relay_address = next_listen_address(&mut relay).await;

        let mut destination = NetworkNode::new(Keypair::generate_ed25519());
        let destination_id = destination.peer_id();
        destination
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
            .unwrap();
        destination.reserve_relay(relay_id, relay_address).unwrap();
        let relayed_address = timeout(TEST_TIMEOUT, async {
            loop {
                tokio::select! {
                    event = destination.next_event() => {
                        if let NetworkEvent::Listening { address } = event
                            && address.iter().any(|protocol| protocol == Protocol::P2pCircuit)
                        {
                            break address;
                        }
                    }
                    _ = relay.next_event() => {}
                }
            }
        })
        .await
        .expect("relay should grant a listen reservation");

        let mut source = NetworkNode::new(Keypair::generate_ed25519());
        source
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
            .unwrap();
        source.dial(relayed_address).unwrap();

        timeout(TEST_TIMEOUT, async {
            loop {
                tokio::select! {
                    event = source.next_event() => {
                        if matches!(
                            event,
                            NetworkEvent::DirectConnectionUpgraded { peer_id }
                                if peer_id == destination_id
                        ) {
                            break;
                        }
                    }
                    _ = destination.next_event() => {}
                    _ = relay.next_event() => {}
                }
            }
        })
        .await
        .expect("peers should hole-punch a direct connection over the relay");
    }

    #[tokio::test]
    async fn remembered_address_dial_reports_the_address_that_reached_the_peer() {
        let mut listener = NetworkNode::new(Keypair::generate_ed25519());
        let mut dialer = NetworkNode::new(Keypair::generate_ed25519());
        let listener_id = listener.peer_id();
        listener
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
            .unwrap();
        let listen_address = next_listen_address(&mut listener).await;

        dialer
            .dial_peer_at(listener_id, vec![listen_address.clone()])
            .unwrap();
        let (peer_id, path, remote_address) = timeout(TEST_TIMEOUT, async {
            loop {
                tokio::select! {
                    event = dialer.next_event() => {
                        if let NetworkEvent::PeerConnected { peer_id, path, remote_address } = event {
                            break (peer_id, path, remote_address);
                        }
                    }
                    _ = listener.next_event() => {}
                }
            }
        })
        .await
        .expect("remembered address dial should connect");

        assert_eq!(peer_id, listener_id);
        assert_eq!(path, ConnectionPath::Lan);
        assert_eq!(remote_address, listen_address);
    }

    #[tokio::test]
    async fn remembered_address_dial_rejects_another_peer_at_that_address() {
        let mut listener = NetworkNode::new(Keypair::generate_ed25519());
        let mut dialer = NetworkNode::new(Keypair::generate_ed25519());
        listener
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
            .unwrap();
        let listen_address = next_listen_address(&mut listener).await;
        let expected_peer = Keypair::generate_ed25519().public().to_peer_id();

        dialer
            .dial_peer_at(expected_peer, vec![listen_address])
            .unwrap();
        let connected = timeout(Duration::from_secs(3), async {
            loop {
                tokio::select! {
                    event = dialer.next_event() => {
                        if matches!(event, NetworkEvent::PeerConnected { .. }) {
                            break;
                        }
                    }
                    _ = listener.next_event() => {}
                }
            }
        })
        .await;

        assert!(connected.is_err(), "a different peer must not connect");
    }

    async fn connected_nodes() -> (NetworkNode, NetworkNode, libp2p::PeerId, libp2p::PeerId) {
        let mut listener = NetworkNode::new(Keypair::generate_ed25519());
        let mut dialer = NetworkNode::new(Keypair::generate_ed25519());
        let listener_id = listener.peer_id();
        let dialer_id = dialer.peer_id();

        listener
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
            .unwrap();
        let listen_address = next_listen_address(&mut listener).await;
        let dial_address: Multiaddr = format!("{listen_address}/p2p/{listener_id}")
            .parse()
            .unwrap();
        dialer.dial(dial_address).unwrap();

        let ((listener_peer, listener_path), (dialer_peer, dialer_path)) =
            timeout(TEST_TIMEOUT, async {
                futures::join!(
                    next_connected_peer(&mut listener),
                    next_connected_peer(&mut dialer)
                )
            })
            .await
            .expect("loopback QUIC connection should complete");

        assert_eq!(listener_peer, dialer_id);
        assert_eq!(listener_path, ConnectionPath::Lan);
        assert_eq!(dialer_peer, listener_id);
        assert_eq!(dialer_path, ConnectionPath::Lan);

        (listener, dialer, listener_id, dialer_id)
    }

    #[tokio::test]
    async fn blocking_a_connected_peer_closes_its_connection() {
        let (mut listener, mut dialer, _, dialer_id) = connected_nodes().await;

        listener.block_peer(dialer_id);

        timeout(TEST_TIMEOUT, async {
            loop {
                tokio::select! {
                    event = listener.next_event() => {
                        if let NetworkEvent::PeerDisconnected { peer_id } = event {
                            assert_eq!(peer_id, dialer_id);
                            break;
                        }
                    }
                    _ = dialer.next_event() => {}
                }
            }
        })
        .await
        .expect("blocking should close the existing connection");
    }

    #[tokio::test]
    async fn blocked_peer_cannot_connect_until_unblocked() {
        let mut listener = NetworkNode::new_routing(Keypair::generate_ed25519());
        let mut dialer = NetworkNode::new(Keypair::generate_ed25519());
        let listener_id = listener.peer_id();
        let dialer_id = dialer.peer_id();
        listener.block_peer(dialer_id);

        listener
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
            .unwrap();
        let listen_address = next_listen_address(&mut listener).await;
        let dial_address: Multiaddr = format!("{listen_address}/p2p/{listener_id}")
            .parse()
            .unwrap();
        dialer.dial(dial_address.clone()).unwrap();

        let refused = timeout(Duration::from_secs(2), async {
            loop {
                tokio::select! {
                    event = listener.next_event() => {
                        if let NetworkEvent::PeerConnected { peer_id, .. } = event {
                            break peer_id;
                        }
                    }
                    _ = dialer.next_event() => {}
                }
            }
        })
        .await;
        assert!(refused.is_err(), "a blocked peer must not be accepted");

        listener.unblock_peer(dialer_id);
        dialer.dial(dial_address).unwrap();
        let (peer_id, _) = timeout(TEST_TIMEOUT, async {
            loop {
                tokio::select! {
                    connected = next_connected_peer(&mut listener) => break connected,
                    _ = dialer.next_event() => {}
                }
            }
        })
        .await
        .expect("an unblocked peer should connect");
        assert_eq!(peer_id, dialer_id);
    }

    #[tokio::test]
    async fn serving_node_refuses_inbound_connections_beyond_its_limit() {
        let mut listener = NetworkNode::with_dht_mode(
            Keypair::generate_ed25519(),
            kad::Mode::Server,
            None,
            connection_limits::ConnectionLimits::default().with_max_established_incoming(Some(1)),
            None,
            false,
        );
        let mut first = NetworkNode::new(Keypair::generate_ed25519());
        let mut second = NetworkNode::new(Keypair::generate_ed25519());
        let listener_id = listener.peer_id();
        let first_id = first.peer_id();

        listener
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
            .unwrap();
        let listen_address = next_listen_address(&mut listener).await;
        let dial_address: Multiaddr = format!("{listen_address}/p2p/{listener_id}")
            .parse()
            .unwrap();

        first.dial(dial_address.clone()).unwrap();
        let (peer_id, _) = timeout(TEST_TIMEOUT, async {
            loop {
                tokio::select! {
                    connected = next_connected_peer(&mut listener) => break connected,
                    _ = first.next_event() => {}
                }
            }
        })
        .await
        .expect("the first peer should connect");
        assert_eq!(peer_id, first_id);

        second.dial(dial_address).unwrap();
        let refused = timeout(Duration::from_secs(2), async {
            loop {
                tokio::select! {
                    event = listener.next_event() => {
                        if let NetworkEvent::PeerConnected { peer_id, .. } = event {
                            break peer_id;
                        }
                    }
                    _ = first.next_event() => {}
                    _ = second.next_event() => {}
                }
            }
        })
        .await;
        assert!(
            refused.is_err(),
            "a peer beyond the limit must not be accepted"
        );
    }

    #[tokio::test]
    async fn serving_node_refuses_inbound_connections_beyond_its_per_ip_limit() {
        let mut listener = NetworkNode::with_dht_mode(
            Keypair::generate_ed25519(),
            kad::Mode::Server,
            None,
            connection_limits::ConnectionLimits::default(),
            Some(1),
            false,
        );
        let mut first = NetworkNode::new(Keypair::generate_ed25519());
        let mut second = NetworkNode::new(Keypair::generate_ed25519());
        let listener_id = listener.peer_id();
        let first_id = first.peer_id();

        listener
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
            .unwrap();
        let listen_address = next_listen_address(&mut listener).await;
        let dial_address: Multiaddr = format!("{listen_address}/p2p/{listener_id}")
            .parse()
            .unwrap();

        first.dial(dial_address.clone()).unwrap();
        let (peer_id, _) = timeout(TEST_TIMEOUT, async {
            loop {
                tokio::select! {
                    connected = next_connected_peer(&mut listener) => break connected,
                    _ = first.next_event() => {}
                }
            }
        })
        .await
        .expect("the first peer should connect");
        assert_eq!(peer_id, first_id);

        second.dial(dial_address).unwrap();
        let refused = timeout(Duration::from_secs(2), async {
            loop {
                tokio::select! {
                    event = listener.next_event() => {
                        if let NetworkEvent::PeerConnected { peer_id, .. } = event {
                            break peer_id;
                        }
                    }
                    _ = first.next_event() => {}
                    _ = second.next_event() => {}
                }
            }
        })
        .await;
        assert!(
            refused.is_err(),
            "a second peer from the same IP address must not be accepted"
        );
    }

    #[tokio::test]
    async fn announced_group_is_found_by_its_invitation_scoped_key() {
        let mut node = NetworkNode::new(Keypair::generate_ed25519());
        let key = DiscoveryKey::derive(GroupIdentity::generate().group_id(), &[7; 32]);

        node.announce_group(key).unwrap();
        node.find_group_peers(key);

        let providers = timeout(TEST_TIMEOUT, async {
            loop {
                if let NetworkEvent::GroupPeersFound {
                    key: found_key,
                    providers,
                } = node.next_event().await
                {
                    assert_eq!(found_key, key);
                    break providers;
                }
            }
        })
        .await
        .expect("local provider lookup should complete");

        assert_eq!(providers, vec![node.peer_id()]);
    }

    #[test]
    fn serving_node_accepts_only_bounded_discovery_key_provider_records() {
        let provider = PeerId::random();
        let short_key = kad::ProviderRecord::new(kad::RecordKey::new(&[1; 31]), provider, vec![]);
        assert!(accepted_provider_record(short_key).is_none());

        let oversized: Multiaddr = format!("/dns4/{}/udp/1/quic-v1", "a".repeat(250))
            .parse()
            .unwrap();
        let mut addresses = vec![oversized];
        addresses.extend((0..10).map(|port| {
            format!("/ip4/192.0.2.1/udp/{}/quic-v1", 1_000 + port)
                .parse::<Multiaddr>()
                .unwrap()
        }));
        let key = DiscoveryKey::derive(GroupIdentity::generate().group_id(), &[7; 32]);
        let record = accepted_provider_record(kad::ProviderRecord::new(
            record_key(key),
            provider,
            addresses.clone(),
        ))
        .expect("a discovery key provider record is accepted");

        assert_eq!(record.provider, provider);
        assert_eq!(record.addresses, addresses[1..=MAX_PROVIDER_ADDRESSES]);
    }

    #[tokio::test]
    async fn routing_node_stores_an_announcement_for_other_clients() {
        let mut routing = NetworkNode::new_routing(Keypair::generate_ed25519());
        let routing_id = routing.peer_id();
        routing
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
            .unwrap();
        let routing_address = next_listen_address(&mut routing).await;
        let key = DiscoveryKey::derive(GroupIdentity::generate().group_id(), &[9; 32]);

        let mut advertiser = NetworkNode::new(Keypair::generate_ed25519());
        let advertiser_id = advertiser.peer_id();
        advertiser
            .listen_on("/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap())
            .unwrap();
        next_listen_address(&mut advertiser).await;
        advertiser.add_bootstrap_peer(routing_id, routing_address.clone());
        advertiser.announce_group(key).unwrap();
        timeout(TEST_TIMEOUT, async {
            loop {
                tokio::select! {
                    event = advertiser.next_event() => {
                        if matches!(event, NetworkEvent::GroupAnnounced { key: announced } if announced == key) {
                            break;
                        }
                    }
                    _ = routing.next_event() => {}
                }
            }
        })
        .await
        .expect("the routing node should accept the announcement");

        let mut searcher = NetworkNode::new(Keypair::generate_ed25519());
        searcher.add_bootstrap_peer(routing_id, routing_address);
        searcher.find_group_peers(key);
        let providers = timeout(TEST_TIMEOUT, async {
            loop {
                tokio::select! {
                    event = searcher.next_event() => {
                        if let NetworkEvent::GroupPeersFound { key: found, providers } = event
                            && found == key
                            && !providers.is_empty()
                        {
                            break providers;
                        }
                    }
                    _ = routing.next_event() => {}
                    _ = advertiser.next_event() => {}
                }
            }
        })
        .await
        .expect("the searcher should find the stored provider");
        assert_eq!(providers, vec![advertiser_id]);
    }

    #[tokio::test]
    async fn lan_discovery_finds_and_dials_a_local_device() {
        let mut first = NetworkNode::new_with_lan_discovery(Keypair::generate_ed25519());
        let mut second = NetworkNode::new_with_lan_discovery(Keypair::generate_ed25519());
        let second_peer_id = second.peer_id();
        first
            .listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap())
            .unwrap();
        second
            .listen_on("/ip4/0.0.0.0/udp/0/quic-v1".parse().unwrap())
            .unwrap();

        timeout(Duration::from_secs(30), async {
            loop {
                tokio::select! {
                    event = first.next_event() => {
                        if let NetworkEvent::LanPeersDiscovered { peers } = event
                            && peers.iter().any(|(peer_id, _)| *peer_id == second_peer_id)
                        {
                            break;
                        }
                    }
                    _ = second.next_event() => {}
                }
            }
        })
        .await
        .expect("mDNS should find the other local device");

        first.dial_peer(second_peer_id).unwrap();
        let path = timeout(TEST_TIMEOUT, async {
            loop {
                tokio::select! {
                    event = first.next_event() => {
                        if let NetworkEvent::PeerConnected { peer_id, path, .. } = event
                            && peer_id == second_peer_id
                        {
                            break path;
                        }
                    }
                    _ = second.next_event() => {}
                }
            }
        })
        .await
        .expect("a LAN-discovered peer should be dialable by identity");

        assert_eq!(path, ConnectionPath::Lan);
    }

    #[tokio::test]
    async fn client_nodes_do_not_announce_on_the_local_network() {
        let node = NetworkNode::new(Keypair::generate_ed25519());

        assert!(!node.swarm.behaviour().lan_discovery.is_enabled());
    }

    async fn next_listen_address(node: &mut NetworkNode) -> Multiaddr {
        loop {
            if let NetworkEvent::Listening { address } = node.next_event().await {
                return address;
            }
        }
    }

    async fn next_connected_peer(node: &mut NetworkNode) -> (libp2p::PeerId, ConnectionPath) {
        loop {
            if let NetworkEvent::PeerConnected { peer_id, path, .. } = node.next_event().await {
                return (peer_id, path);
            }
        }
    }

    async fn next_sync_request(
        receiver: &mut NetworkNode,
        other: &mut NetworkNode,
    ) -> (libp2p::PeerId, super::InboundSyncRequestId, SyncRequest) {
        loop {
            tokio::select! {
                event = receiver.next_event() => {
                    if let NetworkEvent::SyncRequestReceived {
                        peer_id,
                        request_id,
                        request,
                    } = event
                    {
                        return (peer_id, request_id, request);
                    }
                }
                _ = other.next_event() => {}
            }
        }
    }

    async fn next_sync_response(
        receiver: &mut NetworkNode,
        other: &mut NetworkNode,
    ) -> (libp2p::PeerId, super::OutboundSyncRequestId, SyncResponse) {
        loop {
            tokio::select! {
                event = receiver.next_event() => {
                    if let NetworkEvent::SyncResponseReceived {
                        peer_id,
                        request_id,
                        response,
                    } = event
                    {
                        return (peer_id, request_id, response);
                    }
                }
                _ = other.next_event() => {}
            }
        }
    }

    async fn next_join_request(
        receiver: &mut NetworkNode,
        other: &mut NetworkNode,
    ) -> (libp2p::PeerId, super::InboundJoinRequestId, JoinRequest) {
        loop {
            tokio::select! {
                event = receiver.next_event() => {
                    if let NetworkEvent::JoinRequestReceived {
                        peer_id,
                        request_id,
                        request,
                    } = event
                    {
                        return (peer_id, request_id, request);
                    }
                }
                _ = other.next_event() => {}
            }
        }
    }

    async fn next_join_response(
        receiver: &mut NetworkNode,
        other: &mut NetworkNode,
    ) -> (libp2p::PeerId, super::OutboundJoinRequestId, JoinResponse) {
        loop {
            tokio::select! {
                event = receiver.next_event() => {
                    if let NetworkEvent::JoinResponseReceived {
                        peer_id,
                        request_id,
                        response,
                    } = event
                    {
                        return (peer_id, request_id, response);
                    }
                }
                _ = other.next_event() => {}
            }
        }
    }
}
