//! Fixed MLS profile vectors (technical-design implementation gate 4).
//!
//! These pin the CharP2P bytes carried inside MLS structures: the Basic
//! Credential identity binding a leaf to a device, and the ADR-051 removal
//! cut-off authenticated data. A failing vector means the encoding changed,
//! which needs a new version rather than an updated constant.

use charp2p_core::PeerId;
use charp2p_mls::{RemovalCutoff, device_credential, device_id_from_credential};
use openmls::prelude::{BasicCredential, Credential};

/// Device peer ID of the Ed25519 seed `[0x11; 32]`, as in the core vectors.
const DEVICE_PEER_ID: &str = "12D3KooWPqT2nMDSiXUSx5D7fasaxhxKigVhcqfkKqrLghCq9jxz";

/// `"charp2p-device-credential\0"`, version `1` (u16 BE), peer ID bytes.
const DEVICE_CREDENTIAL_IDENTITY: &str = "636861727032702d6465766963652d63726564656e7469616c000001002408011220d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";

/// `"charp2p-removal-cutoff\0"`, version `1` (u16 BE), cut-off sequence `42`
/// (u64 BE), removed device peer ID bytes.
const REMOVAL_CUTOFF_AAD: &str = "636861727032702d72656d6f76616c2d6375746f6666000001000000000000002a002408011220d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("valid hex"))
        .collect()
}

fn device_peer() -> PeerId {
    DEVICE_PEER_ID.parse().expect("valid peer ID")
}

#[test]
fn device_credential_identity_is_fixed() {
    let credential: Credential = device_credential(device_peer()).into();
    assert_eq!(
        hex(credential.serialized_content()),
        DEVICE_CREDENTIAL_IDENTITY
    );

    let decoded: Credential = BasicCredential::new(unhex(DEVICE_CREDENTIAL_IDENTITY)).into();
    assert_eq!(
        device_id_from_credential(&decoded).expect("vector credential decodes"),
        device_peer()
    );

    let mut other_version = unhex(DEVICE_CREDENTIAL_IDENTITY);
    other_version[b"charp2p-device-credential\0".len() + 1] = 2;
    let other_version: Credential = BasicCredential::new(other_version).into();
    assert!(device_id_from_credential(&other_version).is_err());
}

#[test]
fn removal_cutoff_authenticated_data_is_fixed() {
    let cutoff = RemovalCutoff {
        removed_peer: device_peer(),
        cutoff_sequence: 42,
    };
    assert_eq!(hex(&cutoff.encode()), REMOVAL_CUTOFF_AAD);
    assert_eq!(
        RemovalCutoff::decode(&unhex(REMOVAL_CUTOFF_AAD)),
        Some(cutoff)
    );

    let mut trailing = unhex(REMOVAL_CUTOFF_AAD);
    trailing.push(0);
    assert_eq!(RemovalCutoff::decode(&trailing), None);
}
