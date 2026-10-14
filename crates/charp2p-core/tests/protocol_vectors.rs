//! Fixed protocol test vectors (technical-design implementation gate 4).
//!
//! Each vector pins a canonical encoding or derivation produced from fixed
//! Ed25519 seeds. A failing vector means the wire format, a signing domain, or
//! a derivation changed, which needs a new protocol version rather than an
//! updated constant.

use charp2p_core::{
    DeviceIdentity, DeviceIdentitySecret, DiscoveryKey, EventId, EventKind, GroupIdentity,
    GroupIdentitySecret, GroupMetadata, HistoryPolicy, Invitation, InvitationError,
    InvitePermission, InviteRejectReason, InviteRequest, InviteResponse, JoinRejectReason,
    JoinRequest, JoinResponse, MAX_IDENTITY_BACKUP_BYTES, MessageBody, MessageDeletion,
    MessageEdit, SignedEvent, open_identity_backup,
};

/// Protobuf-encoded Ed25519 keypair from the seed `[0x11; 32]`.
const DEVICE_SECRET: &str = "080112401111111111111111111111111111111111111111111111111111111111111111d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
const DEVICE_PEER_ID: &str = "12D3KooWPqT2nMDSiXUSx5D7fasaxhxKigVhcqfkKqrLghCq9jxz";

/// Protobuf-encoded Ed25519 group-root keypair from the seed `[0x22; 32]`.
const GROUP_SECRET: &str = "080112402222222222222222222222222222222222222222222222222222222222222222a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0";
const GROUP_ID: &str = "12D3KooWLdJAwPtyQ5RFnr9wGXsQzpf3P2SeqFbYkqbfVehLu4Ns";

/// Discovery key for `GROUP_ID` and the discovery secret `[0x33; 32]`.
const DISCOVERY_KEY: &str = "eec7237569178463e15eb389f58d1b807ec4b3137804d476358ceb8d5ec1f890";

/// `MessageCreated` by the device: sequence 7, one parent `[0x44; 32]`,
/// created at 1_700_000_000_000 ms, payload `b"vector payload"`.
const EVENT: &str = "0126002408011220a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f02408011220d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c97787370701444444444444444444444444444444444444444444444444444444444444444480d095ffbc31090e766563746f72207061796c6f616440e4d50cc7a05dc50e1837d54c2e80081cf0282df2fff26f49dd95d93fe6fc13626301600c5e133e5876db81141125d2699f87090d14dd0f25f3ba7e4c3ef6250c";
const EVENT_ID: &str = "a4db3cf454a7898798e8f38dea9ecdb1a966eea13282c2acaa4e09d5f61e41f5";
const EVENT_PAYLOAD: &[u8] = b"vector payload";
const EVENT_CREATED_AT_UNIX_MS: u64 = 1_700_000_000_000;

/// Reusable invitation signed by the group root for the device, named
/// "Vector group" / "Vector owner", no history, expiring at 4_102_444_800.
const INVITATION: &str = "AiQIARIgoJql9HpnWYAv-VX43C0qFKXJnSO-l_hkEn_5ODRVpPAmACQIARIg0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzcSv8zhg7owtJbugQDSFGqQJ65c7_kUZDcso6aB-66-I6Zew6BIVVmY1k-4A3ym3wEMVmVjdG9yIGdyb3VwDFZlY3RvciBvd25lcoCumaQPAAFAU1E3gHb_VpYI_ntrufZK91T10k32lJCYWGHxoZVkthIGZsEN-AW2vR3s6qBcmLOWmzRY4MzFisBOBXF7k3NICQ";
const INVITATION_ID: &str = "a65ec3a048555998d64fb8037ca6df01";
const INVITATION_DISCOVERY_KEY: &str =
    "20147a358d72cbf42e7681aef7d752e658b2458ea59ee88c02749a529ccf250a";
const INVITATION_EXPIRES_AT_UNIX: u64 = 4_102_444_800;
const VERIFIED_AT_UNIX: u64 = 1_700_000_000;

/// Version 3 single-use invitation with history from the invitation and the
/// address hint `/ip4/192.0.2.1/udp/4001/quic-v1`, otherwise as above.
const HINTED_INVITATION: &str = "AyQIARIgoJql9HpnWYAv-VX43C0qFKXJnSO-l_hkEn_5ODRVpPAmACQIARIg0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzcgoJnJnHrPqmwmr9p2cQO9CVA3V16Nw_2QQPJbzzXsngMtewuGWGrRXxMv014baLsMVmVjdG9yIGdyb3VwDFZlY3RvciBvd25lcoCumaQPAQABCwTAAAIBkQIPoc0DQBMe9BHqMVwy0MYHQDNrqbU2AEQLcZeP174KY35ry5WqLW-oJCeZI4gNA8Biati15YeC6gAPpqR_T7RerRj8Wgg";
const HINTED_INVITATION_ID: &str = "032d7b0b86586ad15f132fd35e1b68bb";
const HINTED_INVITATION_DISCOVERY_KEY: &str =
    "8e19e8eb0c73bd3694ebcdb48ddee878edb8fca202cad06625608242f56a8128";
const HINTED_INVITATION_ADDRESS: &str = "/ip4/192.0.2.1/udp/4001/quic-v1";

/// Version 4 reusable invitation requiring owner approval, granting all
/// retained history, without address hints, otherwise as above.
const APPROVAL_INVITATION: &str = "BCQIARIgoJql9HpnWYAv-VX43C0qFKXJnSO-l_hkEn_5ODRVpPAmACQIARIg0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzehFgGQMilBxXuUkCd4vxk8TbZ-hg9gkf8tOMr0QQmhX1Kt0Abx9tnUDxAeEQh3PNgMVmVjdG9yIGdyb3VwDFZlY3RvciBvd25lcoCumaQPAgEAQDScjPDAkwYcHYvSFVPJna4JMC4zG_7BiZ5TM4M6gZmErTqTV9NgyvtmxFOSeXv8Prt-Pifu-yOv6rdF7v1aEQE";
const APPROVAL_INVITATION_ID: &str = "52add006f1f6d9d40f101e1108773cd8";
const APPROVAL_INVITATION_DISCOVERY_KEY: &str =
    "b40dcc0422787e96fd4c3cadab6dda95f00bd1591b0df6046b2ebead9c733bf4";

/// MLS-protected plaintexts. Targets are the event identifier `[0x55; 32]`.
const MESSAGE_TARGET: [u8; 32] = [0x55; 32];
/// Plain message text "Vector text" without a reply reference.
const MESSAGE_BODY_PLAIN: &str = "566563746f722074657874";
/// Structured reply body "Vector reply" behind the 0xff marker.
const MESSAGE_BODY_REPLY: &str = "ff0155555555555555555555555555555555555555555555555555555555555555550c566563746f72207265706c79";
/// Version 1 edit with replacement text "Vector edit".
const MESSAGE_EDIT: &str =
    "0155555555555555555555555555555555555555555555555555555555555555550b566563746f722065646974";
/// Version 1 deletion of the target event.
const MESSAGE_DELETION: &str = "015555555555555555555555555555555555555555555555555555555555555555";
/// Version 1 metadata naming "Vector group" without an icon.
const GROUP_METADATA_V1: &str = "010c566563746f722067726f7570";
/// Version 2 metadata naming "Vector group" with built-in icon 3.
const GROUP_METADATA_V2: &str = "020c566563746f722067726f757003";
/// Version 1 grant of the invite permission to the vector device.
const INVITE_PERMISSION: &str =
    "0126002408011220d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c977873701";

/// Length-prefixed protobuf encoding of `GROUP_ID` as framed by the join and
/// invite request codecs: big-endian `u16` length 38, then the identifier.
const FRAMED_GROUP_ID: &str =
    "0026002408011220a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0";
/// Big-endian `u16` length of `INVITATION` (298 Base64URL characters).
const FRAMED_INVITATION_LENGTH: &str = "012a";
/// Key package `[1, 2, 3]` behind a big-endian `u32` length, closing a join
/// request version 1 for `GROUP_ID` and `INVITATION`.
const JOIN_REQUEST_KEY_PACKAGE: &str = "00000003010203";
/// Join response version 1 accepting with the Welcome `[4, 5, 6]`.
const JOIN_RESPONSE_ACCEPTED: &str = "00010100000003040506";
/// Join response version 1 rejections in reason-code order.
const JOIN_RESPONSE_REJECTIONS: [(JoinRejectReason, &str); 4] = [
    (JoinRejectReason::Unauthorized, "00010201"),
    (JoinRejectReason::Busy, "00010202"),
    (JoinRejectReason::UnsupportedProfile, "00010203"),
    (JoinRejectReason::AwaitingApproval, "00010204"),
];
/// Invite request version 1 for `GROUP_ID` with a one-day lifetime.
const INVITE_REQUEST_LIFETIME: &str = "00015180";
/// Invite response version 1 rejections in reason-code order.
const INVITE_RESPONSE_REJECTIONS: [(InviteRejectReason, &str); 2] = [
    (InviteRejectReason::Unauthorized, "00010201"),
    (InviteRejectReason::Busy, "00010202"),
];
/// ADR-028 identity backup version 1 of the device key named "Vector device",
/// sealed with the passphrase `IDENTITY_BACKUP_PASSPHRASE`: the magic, version
/// 1, a 16-byte salt, a 24-byte nonce, then the XChaCha20-Poly1305 ciphertext
/// of the postcard plaintext with its 16-byte tag.
const IDENTITY_BACKUP: &str = "636861727032702d6964656e746974792d6261636b757001b2669ae4651557ffc0ecb2eb1eeae00016786574740e0846adc50c3369bc08f7edbdb127fb0dd7cfce2efdb4ac542260d6f6ebad780db01bea98e5b4499eedc08db3b3843a41cd12ac09db2d1ee2772ea6797a4fe403c5f3ac6eb55ce6630e277dfd1e3aa942f413bbd7ff7a258d499a4733b88f248c8352cfba75bd701ae58b4dfa0077a84e6f970117b6";
const IDENTITY_BACKUP_PASSPHRASE: &str = "vector passphrase";
const IDENTITY_BACKUP_MAGIC: &[u8] = b"charp2p-identity-backup";

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("valid hex"))
        .collect()
}

fn device() -> DeviceIdentity {
    DeviceIdentity::from_persisted_secret(&DeviceIdentitySecret::from_protected_bytes(unhex(
        DEVICE_SECRET,
    )))
    .expect("device vector secret")
}

fn group() -> GroupIdentity {
    GroupIdentity::from_persisted_secret(&GroupIdentitySecret::from_protected_bytes(unhex(
        GROUP_SECRET,
    )))
    .expect("group vector secret")
}

#[test]
fn identities_derive_fixed_peer_ids() {
    assert_eq!(device().peer_id().to_string(), DEVICE_PEER_ID);
    assert_eq!(group().group_id().to_string(), GROUP_ID);
}

#[test]
fn discovery_key_derivation_is_fixed() {
    let key = DiscoveryKey::derive(group().group_id(), &[0x33; 32]);
    assert_eq!(hex(key.as_bytes()), DISCOVERY_KEY);
    let other_group = DiscoveryKey::derive(device().peer_id(), &[0x33; 32]);
    assert_ne!(hex(other_group.as_bytes()), DISCOVERY_KEY);
}

#[test]
fn signed_event_encoding_and_id_are_fixed() {
    let parents = [EventId::from_bytes([0x44; 32])];
    let event = SignedEvent::create(
        &device(),
        charp2p_core::EventSpec {
            group_id: group().group_id(),
            author_sequence: 7,
            causal_parents: &parents,
            created_at_unix_ms: EVENT_CREATED_AT_UNIX_MS,
            kind: EventKind::MessageCreated,
            protected_payload: EVENT_PAYLOAD,
        },
    )
    .expect("event vector");
    assert_eq!(hex(&event.encode().expect("encode")), EVENT);
    assert_eq!(hex(event.id().as_bytes()), EVENT_ID);
}

#[test]
fn fixed_event_decodes_and_verifies() {
    let event = SignedEvent::decode(&unhex(EVENT)).expect("vector verifies");
    assert_eq!(hex(event.id().as_bytes()), EVENT_ID);
    assert_eq!(event.author_id().to_string(), DEVICE_PEER_ID);
    assert_eq!(event.group_id().to_string(), GROUP_ID);
    assert_eq!(event.author_sequence(), 7);
    assert_eq!(event.causal_parents(), &[EventId::from_bytes([0x44; 32])]);
    assert_eq!(event.created_at_unix_ms(), EVENT_CREATED_AT_UNIX_MS);
    assert_eq!(event.kind(), EventKind::MessageCreated);
    assert_eq!(event.protected_payload(), EVENT_PAYLOAD);
}

#[test]
fn fixed_event_rejects_any_tampered_body_or_signature_byte() {
    let encoded = unhex(EVENT);
    for index in 0..encoded.len() {
        let mut tampered = encoded.clone();
        tampered[index] ^= 0x01;
        assert!(
            SignedEvent::decode(&tampered).is_err(),
            "byte {index} changed without detection"
        );
    }
}

#[test]
fn fixed_invitation_decodes_and_verifies() {
    let invitation = Invitation::decode(INVITATION, VERIFIED_AT_UNIX).expect("vector verifies");
    assert_eq!(invitation.group_id().to_string(), GROUP_ID);
    assert_eq!(invitation.inviter_device_id().to_string(), DEVICE_PEER_ID);
    assert_eq!(invitation.group_name(), "Vector group");
    assert_eq!(invitation.inviter_name(), "Vector owner");
    assert_eq!(invitation.expires_at_unix(), INVITATION_EXPIRES_AT_UNIX);
    assert_eq!(invitation.history_policy(), HistoryPolicy::None);
    assert!(invitation.is_reusable());
    assert_eq!(hex(invitation.invitation_id().as_bytes()), INVITATION_ID);
    assert_eq!(
        hex(DiscoveryKey::from_invitation(&invitation).as_bytes()),
        INVITATION_DISCOVERY_KEY
    );
    assert_eq!(invitation.encode().expect("re-encode"), INVITATION);
    assert_eq!(
        invitation.custom_uri().expect("custom uri"),
        format!("charp2p://join/{INVITATION}")
    );
    let from_link = Invitation::decode_input(
        &invitation.https_link().expect("https link"),
        VERIFIED_AT_UNIX,
    )
    .expect("link decodes");
    assert_eq!(from_link.invitation_id(), invitation.invitation_id());
}

#[test]
fn fixed_invitation_is_rejected_at_expiry() {
    assert!(matches!(
        Invitation::decode(INVITATION, INVITATION_EXPIRES_AT_UNIX),
        Err(InvitationError::Expired)
    ));
}

#[test]
fn fixed_invitation_rejects_a_tampered_signature() {
    let mut chars: Vec<char> = INVITATION.chars().collect();
    let last = chars.len() - 2;
    chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
    let tampered: String = chars.into_iter().collect();
    assert!(Invitation::decode(&tampered, VERIFIED_AT_UNIX).is_err());
}

#[test]
fn fixed_hinted_invitation_decodes_and_verifies() {
    let invitation =
        Invitation::decode(HINTED_INVITATION, VERIFIED_AT_UNIX).expect("vector verifies");
    assert_eq!(invitation.group_id().to_string(), GROUP_ID);
    assert_eq!(invitation.inviter_device_id().to_string(), DEVICE_PEER_ID);
    assert_eq!(invitation.history_policy(), HistoryPolicy::FromInvitation);
    assert!(!invitation.is_reusable());
    assert!(!invitation.requires_owner_approval());
    let hints: Vec<String> = invitation
        .address_hints()
        .iter()
        .map(ToString::to_string)
        .collect();
    assert_eq!(hints, [HINTED_INVITATION_ADDRESS]);
    assert_eq!(
        hex(invitation.invitation_id().as_bytes()),
        HINTED_INVITATION_ID
    );
    assert_eq!(
        hex(DiscoveryKey::from_invitation(&invitation).as_bytes()),
        HINTED_INVITATION_DISCOVERY_KEY
    );
    assert_eq!(invitation.encode().expect("re-encode"), HINTED_INVITATION);
}

#[test]
fn fixed_approval_invitation_decodes_and_verifies() {
    let invitation =
        Invitation::decode(APPROVAL_INVITATION, VERIFIED_AT_UNIX).expect("vector verifies");
    assert_eq!(invitation.group_id().to_string(), GROUP_ID);
    assert_eq!(invitation.inviter_device_id().to_string(), DEVICE_PEER_ID);
    assert_eq!(invitation.history_policy(), HistoryPolicy::AllRetained);
    assert!(invitation.is_reusable());
    assert!(invitation.requires_owner_approval());
    assert!(invitation.address_hints().is_empty());
    assert_eq!(
        hex(invitation.invitation_id().as_bytes()),
        APPROVAL_INVITATION_ID
    );
    assert_eq!(
        hex(DiscoveryKey::from_invitation(&invitation).as_bytes()),
        APPROVAL_INVITATION_DISCOVERY_KEY
    );
    assert_eq!(invitation.encode().expect("re-encode"), APPROVAL_INVITATION);
}

#[test]
fn invitation_versions_are_bound_to_their_signing_domain() {
    // Every vector continues with the byte 0x24 after its version, so the
    // first two Base64 characters encode version 2, 3 or 4 respectively.
    // Relabelling a signed invitation as another version must fail.
    const VERSION_PREFIXES: [&str; 3] = ["Ai", "Ay", "BC"];
    for vector in [INVITATION, HINTED_INVITATION, APPROVAL_INVITATION] {
        for prefix in VERSION_PREFIXES {
            if vector.starts_with(prefix) {
                continue;
            }
            let relabelled = format!("{prefix}{}", &vector[2..]);
            assert!(
                Invitation::decode(&relabelled, VERIFIED_AT_UNIX).is_err(),
                "{prefix} relabelling of a vector verified"
            );
        }
    }
}

#[test]
fn message_plaintext_encodings_are_fixed() {
    let plain = MessageBody::new("Vector text", None).expect("plain body");
    assert_eq!(hex(&plain.encode().expect("encode")), MESSAGE_BODY_PLAIN);
    assert_eq!(
        MessageBody::decode(&unhex(MESSAGE_BODY_PLAIN)).expect("decode"),
        plain
    );

    let reply = MessageBody::new("Vector reply", Some(MESSAGE_TARGET)).expect("reply body");
    assert_eq!(hex(&reply.encode().expect("encode")), MESSAGE_BODY_REPLY);
    let decoded = MessageBody::decode(&unhex(MESSAGE_BODY_REPLY)).expect("decode");
    assert_eq!(decoded.reply_to(), Some(&MESSAGE_TARGET));
    assert_eq!(decoded.text(), "Vector reply");

    let edit = MessageEdit::new(MESSAGE_TARGET, "Vector edit").expect("edit");
    assert_eq!(hex(&edit.encode().expect("encode")), MESSAGE_EDIT);
    assert_eq!(
        MessageEdit::decode(&unhex(MESSAGE_EDIT)).expect("decode"),
        edit
    );

    let deletion = MessageDeletion::new(MESSAGE_TARGET);
    assert_eq!(hex(&deletion.encode().expect("encode")), MESSAGE_DELETION);
    assert_eq!(
        MessageDeletion::decode(&unhex(MESSAGE_DELETION)).expect("decode"),
        deletion
    );
}

#[test]
fn group_plaintext_encodings_are_fixed() {
    let v1 = GroupMetadata::new("Vector group").expect("metadata");
    assert_eq!(hex(&v1.encode().expect("encode")), GROUP_METADATA_V1);
    assert_eq!(
        GroupMetadata::decode(&unhex(GROUP_METADATA_V1)).expect("decode"),
        v1
    );

    let v2 = v1.with_icon(3).expect("icon");
    assert_eq!(hex(&v2.encode().expect("encode")), GROUP_METADATA_V2);
    assert_eq!(
        GroupMetadata::decode(&unhex(GROUP_METADATA_V2))
            .expect("decode")
            .icon(),
        Some(3)
    );

    let permission = InvitePermission::new(device().peer_id(), true);
    assert_eq!(
        hex(&permission.encode().expect("encode")),
        INVITE_PERMISSION
    );
    let decoded = InvitePermission::decode(&unhex(INVITE_PERMISSION)).expect("decode");
    assert_eq!(decoded.device_id().to_string(), DEVICE_PEER_ID);
    assert!(decoded.granted());
}

#[test]
fn versioned_plaintexts_reject_an_unknown_version() {
    let bump = |vector: &str, version_index: usize| {
        let mut bytes = unhex(vector);
        bytes[version_index] = 0x7f;
        bytes
    };
    assert!(MessageBody::decode(&bump(MESSAGE_BODY_REPLY, 1)).is_err());
    assert!(MessageEdit::decode(&bump(MESSAGE_EDIT, 0)).is_err());
    assert!(MessageDeletion::decode(&bump(MESSAGE_DELETION, 0)).is_err());
    assert!(GroupMetadata::decode(&bump(GROUP_METADATA_V1, 0)).is_err());
    assert!(InvitePermission::decode(&bump(INVITE_PERMISSION, 0)).is_err());
}

#[test]
fn join_wire_encodings_are_fixed() {
    let invitation = Invitation::decode(INVITATION, VERIFIED_AT_UNIX).expect("vector verifies");
    let request = JoinRequest::from_invitation(&invitation, vec![1, 2, 3]).expect("request");
    let expected = format!(
        "0001{FRAMED_GROUP_ID}{FRAMED_INVITATION_LENGTH}{}{JOIN_REQUEST_KEY_PACKAGE}",
        hex(INVITATION.as_bytes())
    );
    assert_eq!(hex(&request.encode().expect("encode")), expected);
    let decoded = JoinRequest::decode(&unhex(&expected)).expect("decode");
    assert_eq!(decoded.group_id().to_string(), GROUP_ID);
    assert_eq!(decoded.invitation(), INVITATION);
    assert_eq!(decoded.key_package(), &[1, 2, 3]);

    let accepted = JoinResponse::accepted(vec![4, 5, 6]).expect("accepted");
    assert_eq!(
        hex(&accepted.encode().expect("encode")),
        JOIN_RESPONSE_ACCEPTED
    );
    let decoded = JoinResponse::decode(&unhex(JOIN_RESPONSE_ACCEPTED)).expect("decode");
    assert_eq!(decoded.welcome(), Some([4, 5, 6].as_slice()));

    for (reason, vector) in JOIN_RESPONSE_REJECTIONS {
        let rejected = JoinResponse::rejected(reason);
        assert_eq!(hex(&rejected.encode().expect("encode")), vector);
        let decoded = JoinResponse::decode(&unhex(vector)).expect("decode");
        assert_eq!(decoded.rejection(), Some(reason));
    }
}

#[test]
fn invite_wire_encodings_are_fixed() {
    let request = InviteRequest::new(group().group_id(), 86_400).expect("request");
    let expected = format!("0001{FRAMED_GROUP_ID}{INVITE_REQUEST_LIFETIME}");
    assert_eq!(hex(&request.encode()), expected);
    let decoded = InviteRequest::decode(&unhex(&expected)).expect("decode");
    assert_eq!(decoded, request);

    let invitation = Invitation::decode(INVITATION, VERIFIED_AT_UNIX).expect("vector verifies");
    let issued = InviteResponse::issued(&invitation).expect("issued");
    let expected = format!(
        "000101{FRAMED_INVITATION_LENGTH}{}",
        hex(INVITATION.as_bytes())
    );
    assert_eq!(hex(&issued.encode()), expected);
    let decoded = InviteResponse::decode(&unhex(&expected)).expect("decode");
    assert_eq!(decoded.invitation(), Some(INVITATION));

    for (reason, vector) in INVITE_RESPONSE_REJECTIONS {
        assert_eq!(hex(&InviteResponse::rejected(reason).encode()), vector);
        let decoded = InviteResponse::decode(&unhex(vector)).expect("decode");
        assert_eq!(decoded.rejection(), Some(reason));
    }
}

#[test]
fn join_and_invite_wire_codecs_reject_an_unknown_version() {
    let mut join = unhex(JOIN_RESPONSE_ACCEPTED);
    join[1] = 2;
    assert!(JoinResponse::decode(&join).is_err());
    let mut invite = unhex(INVITE_RESPONSE_REJECTIONS[0].1);
    invite[1] = 2;
    assert!(InviteResponse::decode(&invite).is_err());
    let mut request = unhex(&format!("0001{FRAMED_GROUP_ID}{INVITE_REQUEST_LIFETIME}"));
    request[1] = 2;
    assert!(InviteRequest::decode(&request).is_err());
}

#[test]
fn fixed_identity_backup_opens_with_the_version_1_key_derivation() {
    let backup = unhex(IDENTITY_BACKUP);
    // Magic, version, salt and nonce; then the 83-byte plaintext and its tag.
    assert_eq!(
        &backup[..IDENTITY_BACKUP_MAGIC.len()],
        IDENTITY_BACKUP_MAGIC
    );
    assert_eq!(backup[IDENTITY_BACKUP_MAGIC.len()], 1);
    assert_eq!(
        backup.len(),
        IDENTITY_BACKUP_MAGIC.len() + 1 + 16 + 24 + 83 + 16
    );
    assert!(backup.len() <= MAX_IDENTITY_BACKUP_BYTES);

    // Runs the real 64 MiB, 3-pass Argon2id derivation, unlike the unit tests.
    let restored =
        open_identity_backup(&backup, IDENTITY_BACKUP_PASSPHRASE).expect("backup vector opens");

    assert_eq!(restored.device_name, "Vector device");
    assert_eq!(
        hex(restored.secret.expose_for_protected_storage()),
        DEVICE_SECRET
    );
}
