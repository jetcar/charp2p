use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;

/// Files under the application data directory that hold local state. SQLite
/// write-ahead and shared-memory files count toward storage use.
const STORAGE_FILE_SUFFIXES: [&str; 3] = ["", "-wal", "-shm"];

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInformation {
    pub app_version: &'static str,
    pub os: &'static str,
    pub arch: &'static str,
    pub storage: StorageUse,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageUse {
    pub database_bytes: u64,
}

/// Reports version and local storage use for the Settings page. Reads only
/// file sizes, never file contents or paths.
pub struct SettingsService {
    database_path: PathBuf,
}

impl SettingsService {
    pub fn new(database_path: PathBuf) -> Self {
        Self { database_path }
    }

    pub fn information(&self) -> Result<AppInformation, &'static str> {
        Ok(AppInformation {
            app_version: env!("CARGO_PKG_VERSION"),
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            storage: StorageUse {
                database_bytes: database_bytes(&self.database_path)
                    .map_err(|_| "storage_use_unavailable")?,
            },
        })
    }
}

fn database_bytes(database_path: &Path) -> io::Result<u64> {
    let mut total = 0u64;
    for suffix in STORAGE_FILE_SUFFIXES {
        let mut path = database_path.as_os_str().to_owned();
        path.push(suffix);
        match std::fs::metadata(&path) {
            Ok(metadata) => total = total.saturating_add(metadata.len()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_use_sums_database_and_journal_files() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let database_path = directory.path().join("charp2p.sqlite3");
        std::fs::write(&database_path, [0u8; 4096]).expect("database file is written");
        std::fs::write(directory.path().join("charp2p.sqlite3-wal"), [0u8; 100])
            .expect("journal file is written");
        std::fs::write(directory.path().join("unrelated.txt"), [0u8; 7])
            .expect("unrelated file is written");

        let information = SettingsService::new(database_path)
            .information()
            .expect("information is available");

        assert_eq!(information.storage.database_bytes, 4196);
        assert_eq!(information.app_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn missing_database_reports_zero_bytes() {
        let directory = tempfile::tempdir().expect("temporary directory is available");

        let information = SettingsService::new(directory.path().join("charp2p.sqlite3"))
            .information()
            .expect("information is available");

        assert_eq!(information.storage.database_bytes, 0);
    }
}
