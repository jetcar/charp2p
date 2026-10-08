use serde::{Deserialize, Serialize};
use thiserror::Error;

const GROUP_METADATA_VERSION: u16 = 1;
const GROUP_METADATA_ICON_VERSION: u16 = 2;
/// Largest group display name accepted in a metadata change.
pub const MAX_GROUP_NAME_BYTES: usize = 80;
/// Highest built-in group icon index accepted in a metadata change.
pub const MAX_GROUP_ICON: u8 = 4;
const MAX_GROUP_METADATA_BYTES: usize = 128;

/// Authenticated display metadata carried inside the end-to-end protected
/// payload of a `GroupMetadataChanged` event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupMetadata {
    group_name: String,
    icon: Option<u8>,
}

impl GroupMetadata {
    /// Creates metadata after validating the display name.
    pub fn new(group_name: &str) -> Result<Self, GroupMetadataError> {
        validate_group_name(group_name)?;
        Ok(Self {
            group_name: group_name.to_owned(),
            icon: None,
        })
    }

    /// Adds a built-in group icon index after validating it.
    pub fn with_icon(mut self, icon: u8) -> Result<Self, GroupMetadataError> {
        if icon > MAX_GROUP_ICON {
            return Err(GroupMetadataError::InvalidIcon);
        }
        self.icon = Some(icon);
        Ok(self)
    }

    /// Returns the group display name.
    pub fn group_name(&self) -> &str {
        &self.group_name
    }

    /// Returns the built-in group icon index, absent in version 1 metadata.
    pub fn icon(&self) -> Option<u8> {
        self.icon
    }

    /// Encodes the metadata as versioned plaintext for MLS protection.
    ///
    /// Metadata without an icon keeps the version 1 encoding.
    pub fn encode(&self) -> Result<Vec<u8>, GroupMetadataError> {
        Ok(match self.icon {
            None => postcard::to_allocvec(&GroupMetadataWire {
                version: GROUP_METADATA_VERSION,
                group_name: self.group_name.clone(),
            })?,
            Some(icon) => postcard::to_allocvec(&GroupMetadataIconWire {
                version: GROUP_METADATA_ICON_VERSION,
                group_name: self.group_name.clone(),
                icon,
            })?,
        })
    }

    /// Decodes and validates decrypted metadata plaintext.
    pub fn decode(encoded: &[u8]) -> Result<Self, GroupMetadataError> {
        if encoded.is_empty() || encoded.len() > MAX_GROUP_METADATA_BYTES {
            return Err(GroupMetadataError::InvalidSize);
        }
        let (version, _): (u16, _) = postcard::take_from_bytes(encoded)?;
        match version {
            GROUP_METADATA_VERSION => {
                let wire: GroupMetadataWire = take_exact(encoded)?;
                Self::new(&wire.group_name)
            }
            GROUP_METADATA_ICON_VERSION => {
                let wire: GroupMetadataIconWire = take_exact(encoded)?;
                Self::new(&wire.group_name)?.with_icon(wire.icon)
            }
            _ => Err(GroupMetadataError::UnsupportedVersion(version)),
        }
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
    /// The group icon is not a built-in icon index.
    #[error("group icon is invalid")]
    InvalidIcon,
}

#[derive(Deserialize, Serialize)]
struct GroupMetadataWire {
    version: u16,
    group_name: String,
}

#[derive(Deserialize, Serialize)]
struct GroupMetadataIconWire {
    version: u16,
    group_name: String,
    icon: u8,
}

fn take_exact<'a, T: Deserialize<'a>>(encoded: &'a [u8]) -> Result<T, GroupMetadataError> {
    let (wire, remaining) = postcard::take_from_bytes(encoded)?;
    if !remaining.is_empty() {
        return Err(GroupMetadataError::InvalidSize);
    }
    Ok(wire)
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
    use super::{GroupMetadata, GroupMetadataError, GroupMetadataIconWire, GroupMetadataWire};

    #[test]
    fn metadata_round_trips() {
        let metadata = GroupMetadata::new("Design Crew").expect("valid metadata");
        let decoded =
            GroupMetadata::decode(&metadata.encode().expect("encode")).expect("decode metadata");
        assert_eq!(decoded, metadata);
        assert_eq!(decoded.group_name(), "Design Crew");
        assert_eq!(decoded.icon(), None);
        assert_eq!(metadata.encode().expect("encode")[0], 1);
    }

    #[test]
    fn metadata_with_icon_round_trips_as_version_two() {
        let metadata = GroupMetadata::new("Design Crew")
            .and_then(|metadata| metadata.with_icon(3))
            .expect("valid metadata");
        let encoded = metadata.encode().expect("encode");
        assert_eq!(encoded[0], 2);
        let decoded = GroupMetadata::decode(&encoded).expect("decode metadata");
        assert_eq!(decoded, metadata);
        assert_eq!(decoded.icon(), Some(3));
    }

    #[test]
    fn invalid_icons_are_rejected() {
        let metadata = GroupMetadata::new("Crew").expect("valid metadata");
        assert!(matches!(
            metadata.with_icon(5),
            Err(GroupMetadataError::InvalidIcon)
        ));
        let invalid = postcard::to_allocvec(&GroupMetadataIconWire {
            version: 2,
            group_name: "Crew".to_owned(),
            icon: 9,
        })
        .expect("encode");
        assert!(matches!(
            GroupMetadata::decode(&invalid),
            Err(GroupMetadataError::InvalidIcon)
        ));
        let mut trailing = GroupMetadata::new("Crew")
            .and_then(|metadata| metadata.with_icon(1))
            .and_then(|metadata| metadata.encode())
            .expect("encode");
        trailing.push(0);
        assert!(matches!(
            GroupMetadata::decode(&trailing),
            Err(GroupMetadataError::InvalidSize)
        ));
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
            version: 3,
            group_name: "Crew".to_owned(),
        })
        .expect("encode");
        assert!(matches!(
            GroupMetadata::decode(&future),
            Err(GroupMetadataError::UnsupportedVersion(3))
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
