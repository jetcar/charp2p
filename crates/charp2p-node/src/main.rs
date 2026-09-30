#![forbid(unsafe_code)]

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use charp2p_core::{JoinRejectReason, SyncRejectReason};
use charp2p_network::{DiscoveryOperation, NetworkEvent, NetworkNode};
use clap::Parser;
use libp2p::{Multiaddr, identity::Keypair};
use thiserror::Error;
use zeroize::Zeroizing;

const IDENTITY_VERSION: u8 = 1;
const MAX_IDENTITY_BYTES: usize = 512;

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
}

#[tokio::main]
async fn main() -> Result<(), NodeError> {
    let config = Config::parse();
    let identity = load_or_create_identity(&config.identity)?;
    let mut node = NetworkNode::new_routing(identity);
    let peer_id = node.peer_id();
    node.listen_on(config.listen)?;

    println!("CharP2P routing node");
    println!("Peer ID: {peer_id}");

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
    #[error("network operation failed")]
    Network(#[from] charp2p_network::NetworkError),
    #[error("shutdown signal handler failed")]
    ShutdownSignal(io::Error),
}

#[cfg(test)]
mod tests {
    use std::{io::Write, path::Path};

    use tempfile::tempdir;

    use super::{NodeError, create_private_file, load_or_create_identity, read_identity};

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
}
