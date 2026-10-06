use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::preference_file::{self, PreferenceReadError};

/// Passed by the operating system login entry so a launch at login can start
/// with the window hidden.
pub const LOGIN_LAUNCH_ARGUMENT: &str = "--launched-at-login";

/// Device-local background behavior (ADR-032). Holds no secrets and is never
/// synchronized.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BackgroundPreference {
    /// Closing the window hides it and keeps advertising and synchronizing
    /// until the user quits or launches the app again to show it.
    pub keep_running_when_closed: bool,
    /// The operating system starts the app when the user signs in. Missing in
    /// files written before this option existed.
    #[serde(default)]
    pub launch_at_login: bool,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackgroundStatus {
    /// False on builds where the operating system decides background work
    /// (Android) or where a hidden window could not be shown again.
    pub available: bool,
    pub preference: BackgroundPreference,
}

/// Stores the background preference in a small file next to the database.
pub struct BackgroundService {
    path: PathBuf,
    available: bool,
    lock: Mutex<()>,
}

impl BackgroundService {
    /// Only Windows builds keep running hidden: a second launch reaches the
    /// running instance and shows its window again.
    pub fn new(path: PathBuf) -> Self {
        Self::with_availability(path, cfg!(windows))
    }

    fn with_availability(path: PathBuf, available: bool) -> Self {
        Self {
            path,
            available,
            lock: Mutex::new(()),
        }
    }

    pub fn is_available(&self) -> bool {
        self.available
    }

    pub fn status(&self) -> Result<BackgroundStatus, &'static str> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| "background_preference_unavailable")?;
        let preference = if self.available {
            self.read()?
        } else {
            BackgroundPreference::default()
        };
        Ok(BackgroundStatus {
            available: self.available,
            preference,
        })
    }

    pub fn set(&self, preference: BackgroundPreference) -> Result<BackgroundStatus, &'static str> {
        if !self.available {
            return Err("background_unavailable");
        }
        let _guard = self
            .lock
            .lock()
            .map_err(|_| "background_preference_unavailable")?;
        preference_file::write(&self.path, &preference)
            .map_err(|_| "background_preference_unavailable")?;
        Ok(BackgroundStatus {
            available: self.available,
            preference,
        })
    }

    /// Whether a window close request should hide the window instead. Any
    /// unreadable preference closes normally.
    pub fn keeps_running_when_closed(&self) -> bool {
        self.status()
            .is_ok_and(|status| status.preference.keep_running_when_closed)
    }

    /// Whether a launch at login should start with the window hidden: only
    /// when closing the window would also keep the app running, so a hidden
    /// start never leaves an app the user cannot reach by its window.
    pub fn starts_hidden(&self, launched_at_login: bool) -> bool {
        launched_at_login
            && self.status().is_ok_and(|status| {
                status.preference.launch_at_login && status.preference.keep_running_when_closed
            })
    }

    /// A missing file means the app exits when its window closes; an
    /// unreadable or invalid file is reported instead of enabling anything.
    fn read(&self) -> Result<BackgroundPreference, &'static str> {
        Ok(preference_file::read(&self.path)
            .map_err(|error| match error {
                PreferenceReadError::Unavailable => "background_preference_unavailable",
                PreferenceReadError::Invalid => "background_preference_invalid",
            })?
            .unwrap_or_default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service(directory: &tempfile::TempDir) -> BackgroundService {
        BackgroundService::with_availability(directory.path().join("background.json"), true)
    }

    #[test]
    fn window_close_exits_without_a_stored_preference() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let service = service(&directory);

        let status = service.status().expect("status is available");

        assert!(status.available);
        assert_eq!(status.preference, BackgroundPreference::default());
        assert!(!service.keeps_running_when_closed());
    }

    #[test]
    fn preference_persists_across_reopening() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let preference = BackgroundPreference {
            keep_running_when_closed: true,
            launch_at_login: true,
        };

        let stored = service(&directory)
            .set(preference)
            .expect("preference is stored");
        let reopened = service(&directory);

        assert_eq!(stored, reopened.status().expect("status is available"));
        assert!(reopened.keeps_running_when_closed());
        assert!(!directory.path().join("background.json.tmp").exists());
    }

    #[test]
    fn invalid_stored_preference_is_reported_not_enabled() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let path = directory.path().join("background.json");

        std::fs::write(&path, br#"{"keepRunningWhenClosed":true,"extra":1}"#)
            .expect("file is written");
        assert_eq!(
            service(&directory).status(),
            Err("background_preference_invalid")
        );
        assert!(!service(&directory).keeps_running_when_closed());

        std::fs::write(&path, vec![b' '; 5000]).expect("file is written");
        assert_eq!(
            service(&directory).status(),
            Err("background_preference_invalid")
        );
    }

    #[test]
    fn unavailable_builds_refuse_background_running() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let path = directory.path().join("background.json");
        std::fs::write(&path, br#"{"keepRunningWhenClosed":true}"#).expect("file is written");
        let service = BackgroundService::with_availability(path, false);

        let status = service.status().expect("status is available");

        assert!(!status.available);
        assert_eq!(status.preference, BackgroundPreference::default());
        assert!(!service.keeps_running_when_closed());
        assert!(!service.starts_hidden(true));
        assert_eq!(
            service.set(BackgroundPreference {
                keep_running_when_closed: true,
                launch_at_login: true,
            }),
            Err("background_unavailable")
        );
    }

    #[test]
    fn preference_without_launch_at_login_reads_as_disabled() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        std::fs::write(
            directory.path().join("background.json"),
            br#"{"keepRunningWhenClosed":true}"#,
        )
        .expect("file is written");

        let status = service(&directory).status().expect("status is available");

        assert_eq!(
            status.preference,
            BackgroundPreference {
                keep_running_when_closed: true,
                launch_at_login: false,
            }
        );
    }

    #[test]
    fn only_a_login_launch_with_background_running_starts_hidden() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let service = service(&directory);
        assert!(!service.starts_hidden(true));

        for (keep_running_when_closed, launch_at_login, launched_at_login, hidden) in [
            (true, true, true, true),
            (true, true, false, false),
            (false, true, true, false),
            (true, false, true, false),
        ] {
            service
                .set(BackgroundPreference {
                    keep_running_when_closed,
                    launch_at_login,
                })
                .expect("preference is stored");
            assert_eq!(service.starts_hidden(launched_at_login), hidden);
        }

        std::fs::write(directory.path().join("background.json"), b"{").expect("file is written");
        assert!(!service.starts_hidden(true));
    }
}
