use std::{
    path::Path,
    sync::{Arc, Mutex},
};

use charp2p_core::{GroupIdentity, GroupIdentitySecret, HistoryPolicy, PeerId};
use charp2p_store::{EventStore, LocalGroupMetadata};
use keyring_core::Error as KeyringError;
use serde::Serialize;
use zeroize::Zeroizing;

use crate::identity::protected_entry;

const CREDENTIAL_PREFIX: &str = "group-identity-v1-";
const MAX_GROUP_NAME_CHARS: usize = 80;
const MAX_GROUP_NAME_BYTES: usize = 80;
const MAX_GROUP_SECRET_BYTES: usize = 512;
const ALLOWED_INVITATION_LIFETIMES: [u64; 4] = [86_400, 604_800, 1_209_600, 2_592_000];

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalGroup {
    pub group_id: String,
    pub group_name: String,
    pub icon: u8,
    pub history_policy: &'static str,
    pub approval_required: bool,
    pub invitation_lifetime_seconds: u64,
    pub reusable_invitation: bool,
}

pub struct CreateGroupSpec<'a> {
    pub group_name: &'a str,
    pub icon: u8,
    pub history_policy: &'a str,
    pub approval_required: bool,
    pub invitation_lifetime_seconds: u64,
    pub reusable_invitation: bool,
}

trait GroupSecretStore: Send + Sync {
    fn put(&self, group_id: PeerId, secret: &[u8]) -> Result<(), &'static str>;
    fn get(&self, group_id: PeerId) -> Result<GroupIdentitySecret, &'static str>;
}

struct PlatformGroupSecretStore;

impl GroupSecretStore for PlatformGroupSecretStore {
    fn put(&self, group_id: PeerId, secret: &[u8]) -> Result<(), &'static str> {
        protected_entry(&credential_user(group_id))?
            .set_secret(secret)
            .map_err(|_| "group_identity_store_unavailable")
    }

    fn get(&self, group_id: PeerId) -> Result<GroupIdentitySecret, &'static str> {
        let encoded = match protected_entry(&credential_user(group_id))?.get_secret() {
            Ok(encoded) => encoded,
            Err(KeyringError::NoEntry) => return Err("group_identity_missing"),
            Err(_) => return Err("group_identity_store_unavailable"),
        };
        let encoded = Zeroizing::new(encoded);
        if encoded.is_empty() || encoded.len() > MAX_GROUP_SECRET_BYTES {
            return Err("group_identity_record_invalid");
        }
        Ok(GroupIdentitySecret::from_protected_zeroizing(encoded))
    }
}

pub struct GroupService {
    operations: Arc<Mutex<()>>,
    metadata: Mutex<EventStore>,
    secrets: Box<dyn GroupSecretStore>,
}

impl GroupService {
    pub fn open(path: impl AsRef<Path>, operations: Arc<Mutex<()>>) -> Result<Self, &'static str> {
        Ok(Self {
            operations,
            metadata: Mutex::new(EventStore::open(path).map_err(|_| "group_store_unavailable")?),
            secrets: Box::new(PlatformGroupSecretStore),
        })
    }

    pub fn create(&self, spec: CreateGroupSpec<'_>) -> Result<LocalGroup, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "group_service_unavailable")?;
        let group_name = normalize_group_name(spec.group_name)?;
        if spec.icon > 4 {
            return Err("invalid_group_icon");
        }
        let history_policy = parse_history_policy(spec.history_policy)?;
        if !ALLOWED_INVITATION_LIFETIMES.contains(&spec.invitation_lifetime_seconds) {
            return Err("invalid_invitation_lifetime");
        }
        let mut store = self
            .metadata
            .lock()
            .map_err(|_| "group_service_unavailable")?;
        if !store
            .local_groups()
            .map_err(|_| "group_store_unavailable")?
            .is_empty()
        {
            return Err("group_already_exists");
        }

        let (identity, secret) =
            GroupIdentity::generate_persistable().map_err(|_| "group_creation_failed")?;
        if secret.expose_for_protected_storage().len() > MAX_GROUP_SECRET_BYTES {
            return Err("group_creation_failed");
        }
        let metadata = LocalGroupMetadata {
            group_id: identity.group_id(),
            group_name,
            icon: spec.icon,
            history_policy,
            approval_required: spec.approval_required,
            invitation_lifetime_seconds: spec.invitation_lifetime_seconds,
            reusable_invitation: spec.reusable_invitation,
        };

        store
            .put_local_group(&metadata)
            .map_err(|_| "group_store_unavailable")?;
        if let Err(error) = self
            .secrets
            .put(metadata.group_id, secret.expose_for_protected_storage())
        {
            store
                .remove_local_group(metadata.group_id)
                .map_err(|_| "group_store_unavailable")?;
            return Err(error);
        }
        Ok(metadata.into())
    }

    pub fn list(&self) -> Result<Vec<LocalGroup>, &'static str> {
        let _operation = self
            .operations
            .lock()
            .map_err(|_| "group_service_unavailable")?;
        let mut store = self
            .metadata
            .lock()
            .map_err(|_| "group_service_unavailable")?;
        let metadata = store
            .local_groups()
            .map_err(|_| "group_store_unavailable")?;
        let mut groups = Vec::with_capacity(metadata.len());
        for stored in metadata {
            let secret = match self.secrets.get(stored.group_id) {
                Ok(secret) => secret,
                Err("group_identity_missing") => {
                    store
                        .remove_local_group(stored.group_id)
                        .map_err(|_| "group_store_unavailable")?;
                    continue;
                }
                Err(error) => return Err(error),
            };
            if secret.expose_for_protected_storage().is_empty()
                || secret.expose_for_protected_storage().len() > MAX_GROUP_SECRET_BYTES
            {
                return Err("group_identity_record_invalid");
            }
            let identity = GroupIdentity::from_persisted_secret(&secret)
                .map_err(|_| "group_identity_record_invalid")?;
            if identity.group_id() != stored.group_id {
                return Err("group_identity_record_invalid");
            }
            groups.push(stored.into());
        }
        Ok(groups)
    }
}

impl From<LocalGroupMetadata> for LocalGroup {
    fn from(metadata: LocalGroupMetadata) -> Self {
        Self {
            group_id: metadata.group_id.to_string(),
            group_name: metadata.group_name,
            icon: metadata.icon,
            history_policy: history_policy_name(metadata.history_policy),
            approval_required: metadata.approval_required,
            invitation_lifetime_seconds: metadata.invitation_lifetime_seconds,
            reusable_invitation: metadata.reusable_invitation,
        }
    }
}

fn credential_user(group_id: PeerId) -> String {
    format!("{CREDENTIAL_PREFIX}{group_id}")
}

fn normalize_group_name(requested: &str) -> Result<String, &'static str> {
    let name = requested.trim();
    if name.is_empty()
        || name.chars().count() > MAX_GROUP_NAME_CHARS
        || name.len() > MAX_GROUP_NAME_BYTES
        || name.chars().any(char::is_control)
    {
        return Err("invalid_group_name");
    }
    Ok(name.to_owned())
}

fn parse_history_policy(value: &str) -> Result<HistoryPolicy, &'static str> {
    match value {
        "none" => Ok(HistoryPolicy::None),
        "fromInvitation" => Ok(HistoryPolicy::FromInvitation),
        "allRetained" => Ok(HistoryPolicy::AllRetained),
        _ => Err("invalid_history_policy"),
    }
}

fn history_policy_name(policy: HistoryPolicy) -> &'static str {
    match policy {
        HistoryPolicy::None => "none",
        HistoryPolicy::FromInvitation => "fromInvitation",
        HistoryPolicy::AllRetained => "allRetained",
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use charp2p_core::{GroupIdentity, GroupIdentitySecret, HistoryPolicy, PeerId};
    use charp2p_store::{EventStore, LocalGroupMetadata};

    use super::{CreateGroupSpec, GroupSecretStore, GroupService};

    #[derive(Default)]
    struct MemorySecretStore {
        saved: Mutex<Vec<(PeerId, Vec<u8>)>>,
    }

    struct FailingSecretStore;

    impl GroupSecretStore for FailingSecretStore {
        fn put(&self, _group_id: PeerId, _secret: &[u8]) -> Result<(), &'static str> {
            Err("group_identity_store_unavailable")
        }

        fn get(&self, _group_id: PeerId) -> Result<GroupIdentitySecret, &'static str> {
            Err("group_identity_missing")
        }
    }

    impl GroupSecretStore for MemorySecretStore {
        fn put(&self, group_id: PeerId, secret: &[u8]) -> Result<(), &'static str> {
            self.saved.lock().unwrap().push((group_id, secret.to_vec()));
            Ok(())
        }

        fn get(&self, group_id: PeerId) -> Result<GroupIdentitySecret, &'static str> {
            self.saved
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find(|(saved_id, _)| *saved_id == group_id)
                .map(|(_, secret)| GroupIdentitySecret::from_protected_bytes(secret.clone()))
                .ok_or("group_identity_missing")
        }
    }

    fn service() -> GroupService {
        GroupService {
            operations: Arc::new(Mutex::new(())),
            metadata: Mutex::new(EventStore::in_memory().unwrap()),
            secrets: Box::new(MemorySecretStore::default()),
        }
    }

    fn spec<'a>(name: &'a str) -> CreateGroupSpec<'a> {
        CreateGroupSpec {
            group_name: name,
            icon: 1,
            history_policy: "fromInvitation",
            approval_required: false,
            invitation_lifetime_seconds: 604_800,
            reusable_invitation: false,
        }
    }

    #[test]
    fn created_group_restores_with_the_same_protected_root() {
        let service = service();
        let created = service.create(spec(" Project Atlas ")).unwrap();
        let restored = service.list().unwrap();

        assert_eq!(restored, vec![created]);
        assert_eq!(restored[0].group_name, "Project Atlas");
        assert_eq!(
            service.create(spec("Hidden second group")).unwrap_err(),
            "group_already_exists"
        );
    }

    #[test]
    fn invalid_group_defaults_are_rejected_before_key_creation() {
        let service = service();
        assert_eq!(
            service.create(spec("\n")).unwrap_err(),
            "invalid_group_name"
        );
        assert_eq!(
            service.create(spec(&"😀".repeat(21))).unwrap_err(),
            "invalid_group_name"
        );

        let mut invalid = spec("Atlas");
        invalid.invitation_lifetime_seconds = 42;
        assert_eq!(
            service.create(invalid).unwrap_err(),
            "invalid_invitation_lifetime"
        );
        assert!(service.list().unwrap().is_empty());
    }

    #[test]
    fn mismatched_root_identity_is_rejected_on_load() {
        let service = service();
        let created = service.create(spec("Atlas")).unwrap();
        let wrong = GroupIdentity::generate_persistable().unwrap().1;
        service
            .secrets
            .put(
                created.group_id.parse().unwrap(),
                wrong.expose_for_protected_storage(),
            )
            .unwrap();

        assert_eq!(service.list().unwrap_err(), "group_identity_record_invalid");
    }

    #[test]
    fn failed_protected_write_rolls_back_sqlite_metadata() {
        let service = GroupService {
            operations: Arc::new(Mutex::new(())),
            metadata: Mutex::new(EventStore::in_memory().unwrap()),
            secrets: Box::new(FailingSecretStore),
        };

        assert_eq!(
            service.create(spec("Atlas")).unwrap_err(),
            "group_identity_store_unavailable"
        );
        assert!(service
            .metadata
            .lock()
            .unwrap()
            .local_groups()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn incomplete_group_creation_is_removed_during_recovery() {
        let mut metadata = EventStore::in_memory().unwrap();
        metadata
            .put_local_group(&LocalGroupMetadata {
                group_id: GroupIdentity::generate().group_id(),
                group_name: "Interrupted".to_owned(),
                icon: 0,
                history_policy: HistoryPolicy::None,
                approval_required: false,
                invitation_lifetime_seconds: 604_800,
                reusable_invitation: false,
            })
            .unwrap();
        let service = GroupService {
            operations: Arc::new(Mutex::new(())),
            metadata: Mutex::new(metadata),
            secrets: Box::new(MemorySecretStore::default()),
        };

        assert!(service.list().unwrap().is_empty());
        assert!(service
            .metadata
            .lock()
            .unwrap()
            .local_groups()
            .unwrap()
            .is_empty());
    }
}
