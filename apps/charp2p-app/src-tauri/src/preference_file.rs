use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Serialize;

/// Larger preference files are rejected rather than parsed.
const MAX_PREFERENCE_FILE_BYTES: u64 = 4 * 1024;

#[derive(Debug, Eq, PartialEq)]
pub enum PreferenceReadError {
    Unavailable,
    Invalid,
}

/// Reads a small device-local JSON preference. A missing file is `None`; an
/// oversized or unparsable file is reported instead of being replaced.
pub fn read<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, PreferenceReadError> {
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(PreferenceReadError::Unavailable),
    };
    let mut bytes = Vec::new();
    file.take(MAX_PREFERENCE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| PreferenceReadError::Unavailable)?;
    if bytes.len() as u64 > MAX_PREFERENCE_FILE_BYTES {
        return Err(PreferenceReadError::Invalid);
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| PreferenceReadError::Invalid)
}

/// Replaces the file through a temporary sibling so a crash never leaves
/// a partially written preference.
pub fn write<T: Serialize>(path: &Path, preference: &T) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec(preference).map_err(io::Error::other)?;
    let mut temporary = path.as_os_str().to_owned();
    temporary.push(".tmp");
    let temporary = PathBuf::from(temporary);
    std::fs::write(&temporary, bytes)?;
    std::fs::rename(&temporary, path)
}
