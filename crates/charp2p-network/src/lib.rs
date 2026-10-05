#![forbid(unsafe_code)]

//! Portable libp2p transport and peer-discovery foundation for CharP2P.

mod join_codec;

use std::{collections::HashMap, time::Duration};

use charp2p_core::{
    DiscoveryKey, JoinRejectReason, JoinRequest, JoinResponse, SyncError, SyncRejectReason,
    SyncRequest, SyncResponse, MAX_SYNC_RESPONSE_BYTES,
};
use futures::StreamExt;
use libp2p::{
    identify,
    identity::Keypair,
    kad, noise, ping, relay, request_response,
    swarm::{behaviour::toggle::Toggle, NetworkBehaviour, StreamProtocol, SwarmEvent},
    yamux, Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use thiserror::Error;

use crate::join_codec::JoinCodec;

const IDENTIFY_PROTOCOL: &str = "/charp2p/identify/1.0.0";
const AGENT_VERSION: &str = concat!("charp2p/", env!("CARGO_PKG_VERSION"));
const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);
const SYNC_PROTOCOL: &str = "/charp2p/sync/2.0.0";
const SYNC_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const JOIN_PROTOCOL: &str = "/charp2p/join/1.0.0";
const JOIN_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_SYNC_WIRE_REQUEST_BYTES: u64 = (MAX_SYNC_RESPONSE_BYTES + 128 * 1024) as u64;
const MAX_SYNC_WIRE_RESPONSE_BYTES: u64 = (MAX_SYNC_RESPONSE_BYTES + 128 * 1024) as u64;
const RELAY_RESERVATION_DURATION: Duration = Duration::from_secs(60 * 60);
const RELAY_CIRCUIT_DURATION: Duration = Duration::from_secs(5 * 60);
const RELAY_CIRCUIT_BYTES: u64 = 32 * 1024 * 1024;

#[derive(NetworkBehaviour)]
struct Behaviour {
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    dht: kad::Behaviour<kad::store::MemoryStore>,
    join: request_response::Behaviour<JoinCodec>,
    sync: request_response::cbor::Behaviour<SyncRequest, SyncResponse>,
    relay_client: relay::client::Behaviour,
    relay_server: Toggle<relay::Behaviour>,
}

impl Behaviour {
    fn new(
        identity: &Keypair,
        dht_mode: kad::Mode,
        relay_client: relay::client::Behaviour,
        relay_server: bool,
    ) -> Self {
        let peer_id = identity.public().to_peer_id();
        let mut dht = kad::Behaviour::new(peer_id, kad::store::MemoryStore::new(peer_id));
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
            ping: ping::Behaviour::new(ping::Config::new()),
            identify: identify::Behaviour::new(
                identify::Config::new(IDENTIFY_PROTOCOL.to_owned(), identity.public())
                    .with_agent_version(AGENT_VERSION.to_owned()),
            ),
            dht,
            join,
            sync,
            relay_client,
            relay_server: Toggle::from(relay_server.then(|| {
                relay::Behaviour::new(peer_id, relay_server_config())
            })),
        }
    }
}

fn relay_server_config() -> relay::Config {
    relay::Config {
        max_reservations: 32,
        max_reservations_per_peer: 1,
        reservation_duration: RELAY_RESERVATION_DURATION,
        max_circuits: 32,
        max_circuits_per_peer: 4,
        max_circuit_duration: RELAY_CIRCUIT_DURATION,
        max_circuit_bytes: RELAY_CIRCUIT_BYTES,
        ..Default::default()
    }
}

/// A client-mode CharP2P node using authenticated direct and relayed transport.
pub struct NetworkNode {
    swarm: Swarm<Behaviour>,
    relay_server: bool,
    discovery_queries: HashMap<kad::QueryId, DiscoveryKey>,
    pending_sync_responses:
        HashMap<InboundSyncRequestId, request_response::ResponseChannel<SyncResponse>>,
    pending_join_responses:
        HashMap<InboundJoinRequestId, request_response::ResponseChannel<JoinResponse>>,
}

impl NetworkNode {
    /// Builds a node from its persistent libp2p device identity.
    pub fn new(identity: Keypair) -> Self {
        Self::with_dht_mode(identity, kad::Mode::Client, false)
    }

    /// Builds a routing node that answers Kademlia queries from other peers.
    pub fn new_routing(identity: Keypair) -> Self {
        Self::with_dht_mode(identity, kad::Mode::Server, true)
    }

    fn with_dht_mode(identity: Keypair, dht_mode: kad::Mode, relay_server: bool) -> Self {
        let swarm = SwarmBuilder::with_existing_identity(identity)
            .with_tokio()
            .with_quic()
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .expect("relay transport construction is infallible")
            .with_behaviour(|identity, relay_client| {
                Behaviour::new(identity, dht_mode, relay_client, relay_server)
            })
            .expect("behaviour construction is infallible")
            .with_swarm_config(|config| {
                config.with_idle_connection_timeout(IDLE_CONNECTION_TIMEOUT)
            })
            .build();

        Self {
            swarm,
            relay_server,
            discovery_queries: HashMap::new(),
            pending_sync_responses: HashMap::new(),
            pending_join_responses: HashMap::new(),
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

    /// Registers a known bootstrap peer address with the routing table.
    pub fn add_bootstrap_peer(&mut self, peer_id: PeerId, address: Multiaddr) {
        self.swarm
            .behaviour_mut()
            .dht
            .add_address(&peer_id, address);
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
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    return NetworkEvent::PeerConnected { peer_id };
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
                SwarmEvent::Behaviour(BehaviourEvent::RelayClient(
                    relay::client::Event::ReservationReqAccepted { relay_peer_id, .. },
                )) => {
                    return NetworkEvent::RelayReservationAccepted { relay_peer_id };
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
    /// An authenticated transport connection was established.
    PeerConnected {
        /// Remote peer identity authenticated by the negotiated transport.
        peer_id: PeerId,
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
}

fn record_key(key: DiscoveryKey) -> kad::RecordKey {
    kad::RecordKey::new(key.as_bytes())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use charp2p_core::{
        DiscoveryKey, GroupIdentity, HistoryPolicy, Invitation, InvitationSpec, JoinRequest,
        JoinResponse, SyncAuthorHead, SyncRequest, SyncResponse,
    };
    use libp2p::{identity::Keypair, multiaddr::Protocol, Multiaddr};
    use tokio::time::timeout;

    use super::{NetworkEvent, NetworkNode};

    const TEST_TIMEOUT: Duration = Duration::from_secs(10);
    const NOW: u64 = 1_800_000_000;

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
    async fn routing_node_relays_an_authenticated_connection() {
        let mut relay = NetworkNode::new_routing(Keypair::generate_ed25519());
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
                            NetworkEvent::PeerConnected { peer_id } if peer_id == destination_id
                        );
                    }
                    event = destination.next_event() => {
                        destination_connected |= matches!(
                            event,
                            NetworkEvent::PeerConnected { peer_id } if peer_id == source_id
                        );
                    }
                    _ = relay.next_event() => {}
                }
            }
        })
        .await
        .expect("peers should connect through the routing node relay");
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

        let (listener_peer, dialer_peer) = timeout(TEST_TIMEOUT, async {
            futures::join!(
                next_connected_peer(&mut listener),
                next_connected_peer(&mut dialer)
            )
        })
        .await
        .expect("loopback QUIC connection should complete");

        assert_eq!(listener_peer, dialer_id);
        assert_eq!(dialer_peer, listener_id);

        (listener, dialer, listener_id, dialer_id)
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

    async fn next_listen_address(node: &mut NetworkNode) -> Multiaddr {
        loop {
            if let NetworkEvent::Listening { address } = node.next_event().await {
                return address;
            }
        }
    }

    async fn next_connected_peer(node: &mut NetworkNode) -> libp2p::PeerId {
        loop {
            if let NetworkEvent::PeerConnected { peer_id } = node.next_event().await {
                return peer_id;
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
