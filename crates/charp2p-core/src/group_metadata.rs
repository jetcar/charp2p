use serde::{Deserialize, Serialize};
use thiserror::Error;

const GROUP_METADATA_VERSION: u16 = 1;
/// Largest group display name accepted in a metadata change.
pub const MAX_GROUP_NAME_BYTES: usize = 80;
const MAX_GROUP_METADATA_BYTES: usize = 128;

/// Authenticated display metadata carried inside the end-to-end protected
/// payload of a `GroupMetadataChanged` event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupMetadata {
    group_name: String,
}

impl GroupMetadata {
    /// Creates metadata after validating the display name.
    pub fn new(group_name: &str) -> Result<Self, GroupMetadataError> {
        validate_group_name(group_name)?;
        Ok(Self {
            group_name: group_name.to_owned(),
        })
    }

    /// Returns the group display name.
    pub fn group_name(&self) -> &str {
        &self.group_name
    }

    /// Encodes the metadata as versioned plaintext for MLS protection.
    pub fn encode(&self) -> Result<Vec<u8>, GroupMetadataError> {
        Ok(postcard::to_allocvec(&GroupMetadataWire {
            version: GROUP_METADATA_VERSION,
            group_name: self.group_name.clone(),
        })?)
    }

    /// Decodes and validates decrypted metadata plaintext.
    pub fn decode(encoded: &[u8]) -> Result<Self, GroupMetadataError> {
        if encoded.is_empty() || encoded.len() > MAX_GROUP_METADATA_BYTES {
            return Err(GroupMetadataError::InvalidSize);
        }
        let (wire, remaining): (GroupMetadataWire, _) = postcard::take_from_bytes(encoded)?;
        if !remaining.is_empty() {
            return Err(GroupMetadataError::InvalidSize);
        }
        if wire.version != GROUP_METADATA_VERSION {
            return Err(GroupMetadataError::UnsupportedVersion(wire.version));
        }
        Self::new(&wire.group_name)
    }
}

/// Errors returned for invalid group metadata.
#[derive(Debug, Error)]
pub enum GroupMetadataError {
    /// The payload is empty, too large, or has trailing bytes.
    #[error("group metadata has an invalid size")]
    InvalidSize,
    /// Binary serialization or deserialization failed.
    #[error("group metadata binary payload is malformed")]
    Serialization(#[from] postcard::Error),
    /// The metadata version is unsupported.
    #[error("unsupported group metadata version {0}")]
    UnsupportedVersion(u16),
    /// The group name violates protocol limits.
    #[error("group name is invalid")]
    InvalidGroupName,
}

#[derive(Deserialize, Serialize)]
struct GroupMetadataWire {
    version: u16,
    group_name: String,
}

fn validate_group_name(value: &str) -> Result<(), GroupMetadataError> {
    if value.is_empty()
        || value.len() > MAX_GROUP_NAME_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(GroupMetadataError::InvalidGroupName);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{GroupMetadata, GroupMetadataError, GroupMetadataWire};

    #[test]
    fn metadata_round_trips() {
        let metadata = GroupMetadata::new("Design Crew").expect("valid metadata");
        let decoded =
            GroupMetadata::decode(&metadata.encode().expect("encode")).expect("decode metadata");
        assert_eq!(decoded, metadata);
        assert_eq!(decoded.group_name(), "Design Crew");
    }

    #[test]
    fn invalid_names_are_rejected() {
        for name in ["", " padded", "line\nbreak", &"x".repeat(81)] {
            assert!(matches!(
                GroupMetadata::new(name),
                Err(GroupMetadataError::InvalidGroupName)
            ));
        }
    }

    #[test]
    fn malformed_payloads_are_rejected() {
        let mut encoded = GroupMetadata::new("Crew")
            .expect("valid metadata")
            .encode()
            .expect("encode");
        encoded.push(0);
        assert!(matches!(
            GroupMetadata::decode(&encoded),
            Err(GroupMetadataError::InvalidSize)
        ));
        let future = postcard::to_allocvec(&GroupMetadataWire {
            version: 2,
            group_name: "Crew".to_owned(),
        })
        .expect("encode");
        assert!(matches!(
            GroupMetadata::decode(&future),
            Err(GroupMetadataError::UnsupportedVersion(2))
        ));
        let invalid = postcard::to_allocvec(&GroupMetadataWire {
            version: 1,
            group_name: " Crew".to_owned(),
        })
        .expect("encode");
        assert!(matches!(
            GroupMetadata::decode(&invalid),
            Err(GroupMetadataError::InvalidGroupName)
        ));
        assert!(GroupMetadata::decode(&[]).is_err());
    }
}
