#![forbid(unsafe_code)]

use std::{
    collections::HashSet,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use charp2p_core::{InviteRejectReason, JoinRejectReason, SyncRejectReason};
use charp2p_network::{DiscoveryOperation, NetworkEvent, NetworkNode, RelayLimits};
use clap::Parser;
use libp2p::{Multiaddr, PeerId, identity::Keypair, multiaddr::Protocol};
use thiserror::Error;
use zeroize::Zeroizing;

const IDENTITY_VERSION: u8 = 1;
const MAX_IDENTITY_BYTES: usize = 512;
const MAX_BLOCKED_PEERS_BYTES: u64 = 256 * 1024;
const MAX_BLOCKED_PEERS: usize = 4_096;
const MAX_BOOTSTRAP_PEERS: usize = 16;
const REBOOTSTRAP_INTERVAL: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Parser)]
#[command(
    name = "charp2p-node",
    about = "CharP2P community bootstrap and routing node"
)]
struct Config {
    /// QUIC address on which the routing node accepts peer connections.
    /// Repeat the flag, or separate environment values with commas, to also
    /// listen on IPv6 or on further addresses.
    #[arg(
        long,
        env = "CHARP2P_NODE_LISTEN",
        default_value = "/ip4/0.0.0.0/udp/4001/quic-v1",
        value_delimiter = ','
    )]
    listen: Vec<Multiaddr>,

    /// TCP address on which the routing node also accepts peer connections,
    /// for clients on networks that block UDP. Repeatable like `--listen`.
    #[arg(
        long,
        env = "CHARP2P_NODE_LISTEN_TCP",
        default_value = "/ip4/0.0.0.0/tcp/4001",
        value_delimiter = ','
    )]
    listen_tcp: Vec<Multiaddr>,

    /// File containing this node's persistent libp2p identity.
    #[arg(
        long,
        env = "CHARP2P_NODE_IDENTITY",
        default_value = "data/node-identity.key"
    )]
    identity: PathBuf,

    /// Other routing nodes to join into one Kademlia DHT, as multiaddresses
    /// ending in `/p2p/<peer-id>`. Repeatable, or comma-separated in the
    /// environment value; at most 16.
    #[arg(long, env = "CHARP2P_NODE_BOOTSTRAP", value_delimiter = ',')]
    bootstrap: Vec<Multiaddr>,

    /// Optional file listing peer IDs this node refuses, one per line.
    /// Blank lines and lines starting with `#` are ignored.
    #[arg(long, env = "CHARP2P_NODE_BLOCKED_PEERS")]
    blocked_peers: Option<PathBuf>,

    /// Simultaneous relayed circuits this node allows (1 to 32).
    #[arg(long, env = "CHARP2P_NODE_RELAY_MAX_CIRCUITS", default_value_t = 32)]
    relay_max_circuits: u32,

    /// Bytes one relayed circuit may carry, in whole MiB (1 to 32).
    #[arg(long, env = "CHARP2P_NODE_RELAY_MAX_CIRCUIT_MIB", default_value_t = 32)]
    relay_max_circuit_mib: u32,

    /// Offer DHT routing only and refuse relay reservations and circuits.
    #[arg(long, env = "CHARP2P_NODE_DISABLE_RELAY")]
    disable_relay: bool,
}

impl Config {
    fn relay_limits(&self) -> Result<Option<RelayLimits>, NodeError> {
        if self.disable_relay {
            return Ok(None);
        }
        RelayLimits::new(self.relay_max_circuits, self.relay_max_circuit_mib)
            .map(Some)
            .map_err(|_| NodeError::RelayLimitsInvalid)
    }

    /// Splits each bootstrap address into its peer ID and dialable address,
    /// skipping duplicates and this node's own identity.
    fn bootstrap_peers(&self, own_peer_id: PeerId) -> Result<Vec<(PeerId, Multiaddr)>, NodeError> {
        if self.bootstrap.len() > MAX_BOOTSTRAP_PEERS {
            return Err(NodeError::BootstrapTooMany);
        }
        let mut peers = Vec::new();
        for entry in &self.bootstrap {
            let mut address = entry.clone();
            let Some(Protocol::P2p(peer_id)) = address.pop() else {
                return Err(NodeError::BootstrapInvalid);
            };
            if address.is_empty() {
                return Err(NodeError::BootstrapInvalid);
            }
            if peer_id != own_peer_id && !peers.contains(&(peer_id, address.clone())) {
                peers.push((peer_id, address));
            }
        }
        Ok(peers)
    }
}

#[tokio::main]
async fn main() -> Result<(), NodeError> {
    let config = Config::parse();
    let relay_limits = config.relay_limits()?;
    let identity = load_or_create_identity(&config.identity)?;
    let mut blocked_peers = match &config.blocked_peers {
        Some(path) => read_blocked_peers(path)?,
        None => Vec::new(),
    };
    let mut node = NetworkNode::new_routing_with_relay(identity, relay_limits);
    for blocked_peer in &blocked_peers {
        node.block_peer(*blocked_peer);
    }
    let peer_id = node.peer_id();
    let bootstrap_peers = config.bootstrap_peers(peer_id)?;
    for address in config.listen.iter().chain(&config.listen_tcp) {
        node.listen_on(address.clone())?;
    }
    for (bootstrap_peer, address) in &bootstrap_peers {
        node.add_bootstrap_peer(*bootstrap_peer, address.clone());
    }

    println!("CharP2P routing node");
    println!("Peer ID: {peer_id}");
    match relay_limits {
        Some(limits) => println!(
            "Relay: up to {} MiB per {}-second circuit period",
            limits.max_bytes_per_circuit_period() / (1024 * 1024),
            RelayLimits::circuit_duration().as_secs()
        ),
        None => println!("Relay: disabled"),
    }
    if !blocked_peers.is_empty() {
        println!("Blocked peer identities: {}", blocked_peers.len());
    }
    if !bootstrap_peers.is_empty() {
        println!("Bootstrap nodes: {}", bootstrap_peers.len());
    }

    // The first tick fires at once, so the node joins the DHT at startup and
    // then refreshes its routing table so restarted peers are found again.
    let mut rebootstrap = tokio::time::interval(REBOOTSTRAP_INTERVAL);
    rebootstrap.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut signals = OperatorSignals::new().map_err(NodeError::ShutdownSignal)?;
    loop {
        tokio::select! {
            _ = rebootstrap.tick(), if !bootstrap_peers.is_empty() => {
                for (bootstrap_peer, address) in &bootstrap_peers {
                    node.add_bootstrap_peer(*bootstrap_peer, address.clone());
                }
                if node.bootstrap().is_err() {
                    eprintln!("DHT bootstrap could not start");
                }
            }
            event = node.next_event() => match event {
                NetworkEvent::Listening { address } => {
                    println!("Listening: {address}/p2p/{peer_id}");
                }
                NetworkEvent::SyncRequestReceived { request_id, .. } => {
                    // A peer that closed its stream before the answer was sent
                    // must not stop the node.
                    if node.reject_sync_request(request_id, SyncRejectReason::Unauthorized).is_err() {
                        eprintln!("Synchronization rejection not delivered: peer stream closed");
                    }
                }
                NetworkEvent::JoinRequestReceived { request_id, .. } => {
                    if node.reject_join_request(request_id, JoinRejectReason::Unauthorized).is_err() {
                        eprintln!("Join rejection not delivered: peer stream closed");
                    }
                }
                NetworkEvent::InviteRequestReceived { request_id, .. } => {
                    if node.reject_invite_request(request_id, InviteRejectReason::Unauthorized).is_err() {
                        eprintln!("Invitation rejection not delivered: peer stream closed");
                    }
                }
                NetworkEvent::DiscoveryFailed { operation, .. } => {
                    eprintln!("DHT {} operation failed", operation_name(operation));
                }
                _ => {}
            },
            signal = signals.next() => {
                match signal.map_err(NodeError::ShutdownSignal)? {
                    OperatorSignal::Stop => {
                        println!("Stopping CharP2P routing node");
                        return Ok(());
                    }
                    OperatorSignal::Reload => {
                        reload_blocked_peers(&config, &mut node, &mut blocked_peers);
                    }
                }
            }
        }
    }
}

/// Re-reads the blocked peer list and applies only its changes. A list that
/// cannot be read or parsed leaves the current blocks in place.
fn reload_blocked_peers(config: &Config, node: &mut NetworkNode, blocked_peers: &mut Vec<PeerId>) {
    let Some(path) = &config.blocked_peers else {
        println!("No blocked peer list configured; nothing to reload");
        return;
    };
    let reloaded = match read_blocked_peers(path) {
        Ok(reloaded) => reloaded,
        Err(error) => {
            eprintln!("Blocked peer list not reloaded: {error}");
            return;
        }
    };
    let (added, removed) = blocked_peer_changes(blocked_peers, &reloaded);
    for peer_id in &added {
        node.block_peer(*peer_id);
    }
    for peer_id in &removed {
        node.unblock_peer(*peer_id);
    }
    *blocked_peers = reloaded;
    println!(
        "Blocked peer identities: {} ({} added, {} removed)",
        blocked_peers.len(),
        added.len(),
        removed.len()
    );
}

/// Returns the peers newly present in `reloaded` and those no longer in it.
fn blocked_peer_changes(current: &[PeerId], reloaded: &[PeerId]) -> (Vec<PeerId>, Vec<PeerId>) {
    let current_set = current.iter().collect::<HashSet<_>>();
    let reloaded_set = reloaded.iter().collect::<HashSet<_>>();
    let added = reloaded
        .iter()
        .filter(|peer_id| !current_set.contains(peer_id))
        .copied()
        .collect();
    let removed = current
        .iter()
        .filter(|peer_id| !reloaded_set.contains(peer_id))
        .copied()
        .collect();
    (added, removed)
}

enum OperatorSignal {
    Stop,
    // Windows has no SIGHUP equivalent, but keeping one signal enum lets the
    // event loop share its shutdown path across platforms.
    #[cfg_attr(not(unix), expect(dead_code, reason = "reload is delivered by SIGHUP"))]
    Reload,
}

/// Interrupt and SIGTERM stop the node; SIGHUP reloads the blocked peer list.
#[cfg(unix)]
struct OperatorSignals {
    terminate: tokio::signal::unix::Signal,
    hangup: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl OperatorSignals {
    fn new() -> io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};

        Ok(Self {
            terminate: signal(SignalKind::terminate())?,
            hangup: signal(SignalKind::hangup())?,
        })
    }

    async fn next(&mut self) -> io::Result<OperatorSignal> {
        tokio::select! {
            result = tokio::signal::ctrl_c() => result.map(|()| OperatorSignal::Stop),
            _ = self.terminate.recv() => Ok(OperatorSignal::Stop),
            _ = self.hangup.recv() => Ok(OperatorSignal::Reload),
        }
    }
}

/// Interrupt stops the node; other platforms have no reload signal.
#[cfg(not(unix))]
struct OperatorSignals;

#[cfg(not(unix))]
impl OperatorSignals {
    fn new() -> io::Result<Self> {
        Ok(Self)
    }

    async fn next(&mut self) -> io::Result<OperatorSignal> {
        tokio::signal::ctrl_c().await.map(|()| OperatorSignal::Stop)
    }
}

fn operation_name(operation: DiscoveryOperation) -> &'static str {
    match operation {
        DiscoveryOperation::Announcement => "announcement",
        DiscoveryOperation::Search => "search",
    }
}

fn read_blocked_peers(path: &Path) -> Result<Vec<PeerId>, NodeError> {
    let mut text = String::new();
    File::open(path)
        .map_err(NodeError::BlockedPeersIo)?
        .take(MAX_BLOCKED_PEERS_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(NodeError::BlockedPeersIo)?;
    if text.len() as u64 > MAX_BLOCKED_PEERS_BYTES {
        return Err(NodeError::BlockedPeersTooLarge);
    }
    parse_blocked_peers(&text)
}

fn parse_blocked_peers(text: &str) -> Result<Vec<PeerId>, NodeError> {
    let mut peers = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let peer_id = line
            .parse::<PeerId>()
            .map_err(|_| NodeError::BlockedPeerInvalid { line: index + 1 })?;
        if !peers.contains(&peer_id) {
            if peers.len() == MAX_BLOCKED_PEERS {
                return Err(NodeError::BlockedPeersTooLarge);
            }
            peers.push(peer_id);
        }
    }
    Ok(peers)
}

fn load_or_create_identity(path: &Path) -> Result<Keypair, NodeError> {
    match read_identity(path) {
        Ok(identity) => return Ok(identity),
        Err(NodeError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let identity = Keypair::generate_ed25519();
    let encoded = Zeroizing::new(
        identity
            .to_protobuf_encoding()
            .map_err(NodeError::IdentityEncoding)?,
    );
    if encoded.len() + 1 > MAX_IDENTITY_BYTES {
        return Err(NodeError::IdentityTooLarge);
    }

    match create_private_file(path) {
        Ok(mut file) => {
            file.write_all(&[IDENTITY_VERSION])?;
            file.write_all(encoded.as_slice())?;
            file.sync_all()?;
            Ok(identity)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => read_identity(path),
        Err(error) => Err(NodeError::Io(error)),
    }
}

fn read_identity(path: &Path) -> Result<Keypair, NodeError> {
    verify_private_permissions(path)?;
    let file = File::open(path)?;
    let mut record = Zeroizing::new(Vec::new());
    file.take((MAX_IDENTITY_BYTES + 1) as u64)
        .read_to_end(&mut record)?;
    if record.len() < 2 || record.len() > MAX_IDENTITY_BYTES {
        return Err(NodeError::IdentityRecordInvalid);
    }
    if record[0] != IDENTITY_VERSION {
        return Err(NodeError::IdentityRecordInvalid);
    }
    Keypair::from_protobuf_encoding(&record[1..]).map_err(NodeError::IdentityDecoding)
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_private_file(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

#[cfg(unix)]
fn verify_private_permissions(path: &Path) -> Result<(), NodeError> {
    use std::os::unix::fs::PermissionsExt;

    let permissions = fs::metadata(path)?.permissions().mode();
    if permissions & 0o077 != 0 {
        return Err(NodeError::IdentityPermissions);
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_private_permissions(_path: &Path) -> Result<(), NodeError> {
    Ok(())
}

#[derive(Debug, Error)]
enum NodeError {
    #[error("node identity file operation failed")]
    Io(#[from] io::Error),
    #[error("node identity could not be encoded")]
    IdentityEncoding(libp2p::identity::DecodingError),
    #[error("node identity could not be decoded")]
    IdentityDecoding(libp2p::identity::DecodingError),
    #[error("node identity record is invalid")]
    IdentityRecordInvalid,
    #[error("node identity record exceeds its size limit")]
    IdentityTooLarge,
    #[cfg(unix)]
    #[error("node identity file must not be accessible by group or other users")]
    IdentityPermissions,
    #[error("blocked peer list could not be read")]
    BlockedPeersIo(io::Error),
    #[error("blocked peer list exceeds its size limit")]
    BlockedPeersTooLarge,
    #[error("blocked peer list line {line} is not a peer ID")]
    BlockedPeerInvalid { line: usize },
    #[error("relay limits must be 1 to 32 circuits and 1 to 32 MiB per circuit")]
    RelayLimitsInvalid,
    #[error("bootstrap addresses must end in /p2p/<peer-id> after a dialable address")]
    BootstrapInvalid,
    #[error("at most 16 bootstrap addresses are allowed")]
    BootstrapTooMany,
    #[error("network operation failed")]
    Network(#[from] charp2p_network::NetworkError),
    #[error("operator signal handler failed")]
    ShutdownSignal(io::Error),
}

#[cfg(test)]
mod tests {
    use std::{io::Write, path::Path};

    use tempfile::tempdir;

    use charp2p_network::RelayLimits;
    use clap::Parser;
    use libp2p::identity::Keypair;

    use super::{
        Config, MAX_BLOCKED_PEERS, MAX_BOOTSTRAP_PEERS, NodeError, blocked_peer_changes,
        create_private_file, load_or_create_identity, parse_blocked_peers, read_blocked_peers,
        read_identity,
    };

    fn write_private(path: &Path, bytes: &[u8]) {
        let mut file = create_private_file(path).unwrap();
        file.write_all(bytes).unwrap();
    }

    #[test]
    fn generated_identity_survives_restart() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("node.key");

        let created = load_or_create_identity(&path).unwrap();
        let restored = load_or_create_identity(&path).unwrap();

        assert_eq!(
            created.public().to_peer_id(),
            restored.public().to_peer_id()
        );
    }

    #[test]
    fn malformed_or_oversized_identity_is_rejected() {
        let directory = tempdir().unwrap();
        let malformed = directory.path().join("malformed.key");
        write_private(&malformed, &[1, 2, 3]);
        assert!(matches!(
            read_identity(&malformed),
            Err(NodeError::IdentityDecoding(_))
        ));

        let oversized = directory.path().join("oversized.key");
        write_private(&oversized, &vec![0; 513]);
        assert!(matches!(
            read_identity(&oversized),
            Err(NodeError::IdentityRecordInvalid)
        ));
    }

    #[test]
    fn blocked_peer_list_skips_comments_and_duplicates() {
        let first = Keypair::generate_ed25519().public().to_peer_id();
        let second = Keypair::generate_ed25519().public().to_peer_id();
        let text = format!("# abusive peers\n\n{first}\n  {second}  \n{first}\n");

        assert_eq!(parse_blocked_peers(&text).unwrap(), vec![first, second]);
        assert!(parse_blocked_peers("").unwrap().is_empty());
    }

    #[test]
    fn blocked_peer_list_rejects_invalid_or_excessive_entries() {
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        assert!(matches!(
            parse_blocked_peers(&format!("{peer}\nnot-a-peer\n")),
            Err(NodeError::BlockedPeerInvalid { line: 2 })
        ));

        let excessive = (0..=MAX_BLOCKED_PEERS)
            .map(|_| {
                Keypair::generate_ed25519()
                    .public()
                    .to_peer_id()
                    .to_string()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(matches!(
            parse_blocked_peers(&excessive),
            Err(NodeError::BlockedPeersTooLarge)
        ));

        let directory = tempdir().unwrap();
        let oversized = directory.path().join("blocked.txt");
        std::fs::write(&oversized, vec![b'#'; 256 * 1024 + 1]).unwrap();
        assert!(matches!(
            read_blocked_peers(&oversized),
            Err(NodeError::BlockedPeersTooLarge)
        ));
        assert!(matches!(
            read_blocked_peers(&directory.path().join("missing.txt")),
            Err(NodeError::BlockedPeersIo(_))
        ));
    }

    #[test]
    fn blocked_peer_reload_applies_only_changes() {
        let [kept, dropped, added] =
            std::array::from_fn(|_| Keypair::generate_ed25519().public().to_peer_id());

        let (newly_blocked, unblocked) = blocked_peer_changes(&[kept, dropped], &[added, kept]);
        assert_eq!(newly_blocked, vec![added]);
        assert_eq!(unblocked, vec![dropped]);

        let (newly_blocked, unblocked) = blocked_peer_changes(&[kept], &[kept]);
        assert!(newly_blocked.is_empty() && unblocked.is_empty());
        assert_eq!(blocked_peer_changes(&[kept], &[]), (vec![], vec![kept]));
    }

    #[test]
    fn relay_limits_default_to_the_maximum_and_follow_operator_choices() {
        let default = Config::try_parse_from(["charp2p-node"]).unwrap();
        assert_eq!(
            default.relay_limits().unwrap(),
            Some(RelayLimits::maximum())
        );

        let reduced = Config::try_parse_from([
            "charp2p-node",
            "--relay-max-circuits",
            "4",
            "--relay-max-circuit-mib",
            "8",
        ])
        .unwrap();
        assert_eq!(
            reduced.relay_limits().unwrap(),
            Some(RelayLimits::new(4, 8).unwrap())
        );

        let disabled = Config::try_parse_from(["charp2p-node", "--disable-relay"]).unwrap();
        assert_eq!(disabled.relay_limits().unwrap(), None);
    }

    #[test]
    fn relay_limits_outside_the_fixed_bounds_are_rejected() {
        for args in [
            ["charp2p-node", "--relay-max-circuits", "0"],
            ["charp2p-node", "--relay-max-circuits", "33"],
            ["charp2p-node", "--relay-max-circuit-mib", "0"],
            ["charp2p-node", "--relay-max-circuit-mib", "33"],
        ] {
            let config = Config::try_parse_from(args).unwrap();
            assert!(matches!(
                config.relay_limits(),
                Err(NodeError::RelayLimitsInvalid)
            ));
        }
    }

    #[test]
    fn listen_addresses_default_to_ipv4_and_accept_several_addresses() {
        let default = Config::try_parse_from(["charp2p-node"]).unwrap();
        assert_eq!(
            default.listen,
            ["/ip4/0.0.0.0/udp/4001/quic-v1".parse().unwrap()]
        );
        assert_eq!(
            default.listen_tcp,
            ["/ip4/0.0.0.0/tcp/4001".parse().unwrap()]
        );

        let dual_stack = Config::try_parse_from([
            "charp2p-node",
            "--listen",
            "/ip4/0.0.0.0/udp/4001/quic-v1",
            "--listen",
            "/ip6/::/udp/4001/quic-v1",
            "--listen-tcp",
            "/ip4/0.0.0.0/tcp/4001,/ip6/::/tcp/4001",
        ])
        .unwrap();
        assert_eq!(dual_stack.listen.len(), 2);
        assert_eq!(
            dual_stack.listen_tcp,
            [
                "/ip4/0.0.0.0/tcp/4001".parse().unwrap(),
                "/ip6/::/tcp/4001".parse().unwrap()
            ]
        );
        assert!(Config::try_parse_from(["charp2p-node", "--listen", "not-an-address"]).is_err());
    }

    #[test]
    fn bootstrap_addresses_split_peer_ids_and_skip_duplicates_and_self() {
        let own = Keypair::generate_ed25519().public().to_peer_id();
        let other = Keypair::generate_ed25519().public().to_peer_id();
        let none = Config::try_parse_from(["charp2p-node"]).unwrap();
        assert!(none.bootstrap_peers(own).unwrap().is_empty());

        let first = format!("/dns4/node.example/udp/4001/quic-v1/p2p/{other}");
        let config = Config::try_parse_from([
            "charp2p-node".to_owned(),
            "--bootstrap".to_owned(),
            format!("{first},/ip4/192.0.2.1/tcp/4001/p2p/{own}"),
            "--bootstrap".to_owned(),
            first,
        ])
        .unwrap();
        assert_eq!(
            config.bootstrap_peers(own).unwrap(),
            [(
                other,
                "/dns4/node.example/udp/4001/quic-v1".parse().unwrap()
            )]
        );
    }

    #[test]
    fn bootstrap_addresses_without_peer_id_or_beyond_the_limit_are_rejected() {
        let own = Keypair::generate_ed25519().public().to_peer_id();
        let other = Keypair::generate_ed25519().public().to_peer_id();
        for address in [
            "/ip4/192.0.2.1/tcp/4001".to_owned(),
            format!("/p2p/{other}"),
        ] {
            let config = Config::try_parse_from(["charp2p-node", "--bootstrap", &address]).unwrap();
            assert!(matches!(
                config.bootstrap_peers(own),
                Err(NodeError::BootstrapInvalid)
            ));
        }

        let excessive = (0..=MAX_BOOTSTRAP_PEERS)
            .map(|index| format!("/ip4/192.0.2.{index}/tcp/4001/p2p/{other}"))
            .collect::<Vec<_>>()
            .join(",");
        let config = Config::try_parse_from(["charp2p-node", "--bootstrap", &excessive]).unwrap();
        assert!(matches!(
            config.bootstrap_peers(own),
            Err(NodeError::BootstrapTooMany)
        ));
    }
}
