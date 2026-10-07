#![forbid(unsafe_code)]

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use charp2p_core::{JoinRejectReason, SyncRejectReason};
use charp2p_network::{DiscoveryOperation, NetworkEvent, NetworkNode};
use clap::Parser;
use libp2p::{Multiaddr, PeerId, identity::Keypair};
use thiserror::Error;
use zeroize::Zeroizing;

const IDENTITY_VERSION: u8 = 1;
const MAX_IDENTITY_BYTES: usize = 512;
const MAX_BLOCKED_PEERS_BYTES: u64 = 256 * 1024;
const MAX_BLOCKED_PEERS: usize = 4_096;

#[derive(Debug, Parser)]
#[command(
    name = "charp2p-node",
    about = "CharP2P community bootstrap and routing node"
)]
struct Config {
    /// QUIC address on which the routing node accepts peer connections.
    #[arg(
        long,
        env = "CHARP2P_NODE_LISTEN",
        default_value = "/ip4/0.0.0.0/udp/4001/quic-v1"
    )]
    listen: Multiaddr,

    /// File containing this node's persistent libp2p identity.
    #[arg(
        long,
        env = "CHARP2P_NODE_IDENTITY",
        default_value = "data/node-identity.key"
    )]
    identity: PathBuf,

    /// Optional file listing peer IDs this node refuses, one per line.
    /// Blank lines and lines starting with `#` are ignored.
    #[arg(long, env = "CHARP2P_NODE_BLOCKED_PEERS")]
    blocked_peers: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), NodeError> {
    let config = Config::parse();
    let identity = load_or_create_identity(&config.identity)?;
    let blocked_peers = match &config.blocked_peers {
        Some(path) => read_blocked_peers(path)?,
        None => Vec::new(),
    };
    let mut node = NetworkNode::new_routing(identity);
    for blocked_peer in &blocked_peers {
        node.block_peer(*blocked_peer);
    }
    let peer_id = node.peer_id();
    node.listen_on(config.listen)?;

    println!("CharP2P routing node");
    println!("Peer ID: {peer_id}");
    if !blocked_peers.is_empty() {
        println!("Blocked peer identities: {}", blocked_peers.len());
    }

    loop {
        tokio::select! {
            event = node.next_event() => match event {
                NetworkEvent::Listening { address } => {
                    println!("Listening: {address}/p2p/{peer_id}");
                }
                NetworkEvent::SyncRequestReceived { request_id, .. } => {
                    node.reject_sync_request(request_id, SyncRejectReason::Unauthorized)?;
                }
                NetworkEvent::JoinRequestReceived { request_id, .. } => {
                    node.reject_join_request(request_id, JoinRejectReason::Unauthorized)?;
                }
                NetworkEvent::DiscoveryFailed { operation, .. } => {
                    eprintln!("DHT {} operation failed", operation_name(operation));
                }
                _ => {}
            },
            result = tokio::signal::ctrl_c() => {
                result.map_err(NodeError::ShutdownSignal)?;
                println!("Stopping CharP2P routing node");
                return Ok(());
            }
        }
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
    #[error("network operation failed")]
    Network(#[from] charp2p_network::NetworkError),
    #[error("shutdown signal handler failed")]
    ShutdownSignal(io::Error),
}

#[cfg(test)]
mod tests {
    use std::{io::Write, path::Path};

    use tempfile::tempdir;

    use libp2p::identity::Keypair;

    use super::{
        MAX_BLOCKED_PEERS, NodeError, create_private_file, load_or_create_identity,
        parse_blocked_peers, read_blocked_peers, read_identity,
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
}
