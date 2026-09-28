#![forbid(unsafe_code)]

//! Portable libp2p transport and peer-discovery foundation for CharP2P.

use std::time::Duration;

use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, Swarm, SwarmBuilder, identify,
    identity::Keypair,
    kad, ping,
    swarm::{NetworkBehaviour, SwarmEvent},
};
use thiserror::Error;

const IDENTIFY_PROTOCOL: &str = "/charp2p/identify/1.0.0";
const AGENT_VERSION: &str = concat!("charp2p/", env!("CARGO_PKG_VERSION"));
const IDLE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);

#[derive(NetworkBehaviour)]
struct Behaviour {
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    dht: kad::Behaviour<kad::store::MemoryStore>,
}

impl Behaviour {
    fn new(identity: &Keypair) -> Self {
        let peer_id = identity.public().to_peer_id();
        let mut dht = kad::Behaviour::new(peer_id, kad::store::MemoryStore::new(peer_id));
        dht.set_mode(Some(kad::Mode::Client));

        Self {
            ping: ping::Behaviour::new(ping::Config::new()),
            identify: identify::Behaviour::new(
                identify::Config::new(IDENTIFY_PROTOCOL.to_owned(), identity.public())
                    .with_agent_version(AGENT_VERSION.to_owned()),
            ),
            dht,
        }
    }
}

/// A client-mode CharP2P node using authenticated, encrypted QUIC transport.
pub struct NetworkNode {
    swarm: Swarm<Behaviour>,
}

impl NetworkNode {
    /// Builds a node from its persistent libp2p device identity.
    pub fn new(identity: Keypair) -> Self {
        let swarm = SwarmBuilder::with_existing_identity(identity)
            .with_tokio()
            .with_quic()
            .with_behaviour(Behaviour::new)
            .expect("behaviour construction is infallible")
            .with_swarm_config(|config| {
                config.with_idle_connection_timeout(IDLE_CONNECTION_TIMEOUT)
            })
            .build();

        Self { swarm }
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

    /// Dials a peer multiaddress.
    pub fn dial(&mut self, address: Multiaddr) -> Result<(), NetworkError> {
        self.swarm.dial(address)?;
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

    /// Waits for the next application-relevant network event.
    pub async fn next_event(&mut self) -> NetworkEvent {
        loop {
            match self.swarm.select_next_some().await {
                SwarmEvent::NewListenAddr { address, .. } => {
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
                _ => {}
            }
        }
    }
}

/// Application-facing network lifecycle events.
#[derive(Debug, Eq, PartialEq)]
pub enum NetworkEvent {
    /// The local node started listening.
    Listening {
        /// Bound network address.
        address: Multiaddr,
    },
    /// An authenticated transport connection was established.
    PeerConnected {
        /// Remote peer identity authenticated by QUIC.
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
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use libp2p::{Multiaddr, identity::Keypair};
    use tokio::time::timeout;

    use super::{NetworkEvent, NetworkNode};

    const TEST_TIMEOUT: Duration = Duration::from_secs(10);

    #[tokio::test]
    async fn two_nodes_establish_an_authenticated_quic_connection() {
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
}
