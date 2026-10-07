use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::preference_file::{self, PreferenceReadError};

/// Shortest and longest accepted message retention (ADR-035).
pub const MIN_RETENTION_DAYS: u32 = 1;
pub const MAX_RETENTION_DAYS: u32 = 3650;
const MILLISECONDS_PER_DAY: u64 = 24 * 60 * 60 * 1000;

/// Device-local message retention (ADR-035). Holds no secrets and is never
/// synchronized.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetentionPreference {
    /// `None` keeps readable message copies until deleted by the user.
    pub keep_messages_days: Option<u32>,
}

impl RetentionPreference {
    pub fn validate(&self) -> Result<(), &'static str> {
        match self.keep_messages_days {
            Some(days) if !(MIN_RETENTION_DAYS..=MAX_RETENTION_DAYS).contains(&days) => {
                Err("retention_preference_invalid")
            }
            _ => Ok(()),
        }
    }

    /// Messages created before this time are removed; `None` keeps all.
    pub fn cutoff_unix_ms(&self, now_unix_ms: u64) -> Option<u64> {
        self.keep_messages_days
            .map(|days| now_unix_ms.saturating_sub(u64::from(days) * MILLISECONDS_PER_DAY))
    }
}

/// Stores the retention preference next to the database.
pub struct RetentionService {
    path: PathBuf,
}

impl RetentionService {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// A missing file keeps every message; an unreadable or invalid file is
    /// reported so retention never removes messages under a guessed policy.
    pub fn preference(&self) -> Result<RetentionPreference, &'static str> {
        let preference = match preference_file::read::<RetentionPreference>(&self.path) {
            Ok(preference) => preference.unwrap_or_default(),
            Err(PreferenceReadError::Unavailable) => {
                return Err("retention_preference_unavailable")
            }
            Err(PreferenceReadError::Invalid) => return Err("retention_preference_invalid"),
        };
        preference.validate()?;
        Ok(preference)
    }

    pub fn set(&self, preference: RetentionPreference) -> Result<(), &'static str> {
        preference.validate()?;
        preference_file::write(&self.path, &preference)
            .map_err(|_| "retention_preference_unavailable")
    }

    /// Cutoff for the stored preference now; `None` when every message is
    /// kept or the preference cannot be read.
    pub fn current_cutoff_unix_ms(&self) -> Option<u64> {
        let now_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())?;
        self.preference().ok()?.cutoff_unix_ms(now_unix_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_preference_keeps_every_message() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let service = RetentionService::new(directory.path().join("retention.json"));

        assert_eq!(service.preference(), Ok(RetentionPreference::default()));
        assert_eq!(service.current_cutoff_unix_ms(), None);
    }

    #[test]
    fn stored_preference_sets_a_cutoff_in_days() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let service = RetentionService::new(directory.path().join("retention.json"));
        let preference = RetentionPreference {
            keep_messages_days: Some(30),
        };

        service.set(preference).expect("preference is stored");

        assert_eq!(service.preference(), Ok(preference));
        assert_eq!(
            preference.cutoff_unix_ms(31 * MILLISECONDS_PER_DAY),
            Some(MILLISECONDS_PER_DAY)
        );
        assert_eq!(preference.cutoff_unix_ms(1_000), Some(0));
        assert!(service.current_cutoff_unix_ms().is_some());
    }

    #[test]
    fn out_of_range_preferences_are_rejected() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let service = RetentionService::new(directory.path().join("retention.json"));

        for days in [0, MAX_RETENTION_DAYS + 1] {
            assert_eq!(
                service.set(RetentionPreference {
                    keep_messages_days: Some(days),
                }),
                Err("retention_preference_invalid")
            );
        }
        assert_eq!(service.preference(), Ok(RetentionPreference::default()));
    }

    #[test]
    fn invalid_file_is_reported_and_removes_nothing() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let path = directory.path().join("retention.json");
        std::fs::write(&path, br#"{"keepMessagesDays":0}"#).expect("file is written");
        let service = RetentionService::new(path.clone());

        assert_eq!(service.preference(), Err("retention_preference_invalid"));
        assert_eq!(service.current_cutoff_unix_ms(), None);

        std::fs::write(&path, b"not json").expect("file is written");
        assert_eq!(service.preference(), Err("retention_preference_invalid"));
    }
}
