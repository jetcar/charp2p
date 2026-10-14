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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_reads_as_none() {
        let directory = tempfile::tempdir().expect("temporary directory is available");

        let read = read::<serde_json::Value>(&directory.path().join("missing.json"));

        assert_eq!(read, Ok(None));
    }

    #[test]
    fn write_creates_parent_directories_and_reads_back() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let path = directory.path().join("nested").join("preference.json");

        write(&path, &vec![1_u32, 2, 3]).expect("preference is written");

        assert_eq!(read::<Vec<u32>>(&path), Ok(Some(vec![1, 2, 3])));
        let mut temporary = path.as_os_str().to_owned();
        temporary.push(".tmp");
        assert!(!PathBuf::from(temporary).exists());
    }

    #[test]
    fn write_replaces_an_existing_preference() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let path = directory.path().join("preference.json");

        write(&path, &"first").expect("first preference is written");
        write(&path, &"second").expect("second preference is written");

        assert_eq!(read::<String>(&path), Ok(Some("second".to_owned())));
    }

    #[test]
    fn file_at_the_size_limit_is_parsed() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let path = directory.path().join("preference.json");
        let value = "a".repeat(MAX_PREFERENCE_FILE_BYTES as usize - 2);
        std::fs::write(&path, format!("\"{value}\"")).expect("file is written");

        assert_eq!(read::<String>(&path), Ok(Some(value)));
    }

    #[test]
    fn file_over_the_size_limit_is_invalid() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let path = directory.path().join("preference.json");
        let value = "a".repeat(MAX_PREFERENCE_FILE_BYTES as usize - 1);
        std::fs::write(&path, format!("\"{value}\"")).expect("file is written");

        assert_eq!(read::<String>(&path), Err(PreferenceReadError::Invalid));
    }

    #[test]
    fn unparsable_file_is_invalid_and_kept() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let path = directory.path().join("preference.json");
        std::fs::write(&path, b"{not json").expect("file is written");

        assert_eq!(
            read::<serde_json::Value>(&path),
            Err(PreferenceReadError::Invalid)
        );
        assert_eq!(std::fs::read(&path).expect("file remains"), b"{not json");
    }
}
