use std::path::PathBuf;
use std::sync::Mutex;

use charp2p_network::RelayLimits;
use serde::{Deserialize, Serialize};

use crate::preference_file::{self, PreferenceReadError};

/// Device-local opt-in to routing and relay contribution (ADR-031). Holds no
/// secrets and is never synchronized.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContributionPreference {
    pub routing: bool,
    pub relay: Option<RelayPreference>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RelayPreference {
    pub max_circuits: u32,
    pub max_circuit_mib: u32,
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContributionStatus {
    /// False on builds that keep the light-peer role (Android).
    pub available: bool,
    pub preference: ContributionPreference,
    /// Most relayed bytes the relay limits allow per circuit duration.
    pub worst_case_relayed_bytes: u64,
    pub circuit_duration_seconds: u64,
}

impl ContributionPreference {
    /// Returns validated relay limits when relay contribution is enabled.
    /// Relay contribution requires routing contribution.
    pub fn relay_limits(&self) -> Result<Option<RelayLimits>, &'static str> {
        let Some(relay) = self.relay else {
            return Ok(None);
        };
        if !self.routing {
            return Err("relay_requires_routing");
        }
        RelayLimits::new(relay.max_circuits, relay.max_circuit_mib)
            .map(Some)
            .map_err(|_| "relay_limits_invalid")
    }
}

/// Stores the contribution preference in a small file next to the database.
pub struct ContributionService {
    path: PathBuf,
    available: bool,
    lock: Mutex<()>,
}

impl ContributionService {
    pub fn new(path: PathBuf) -> Self {
        Self::with_availability(path, cfg!(not(target_os = "android")))
    }

    fn with_availability(path: PathBuf, available: bool) -> Self {
        Self {
            path,
            available,
            lock: Mutex::new(()),
        }
    }

    pub fn status(&self) -> Result<ContributionStatus, &'static str> {
        let _guard = self
            .lock
            .lock()
            .map_err(|_| "contribution_preference_unavailable")?;
        let preference = if self.available {
            self.read()?
        } else {
            ContributionPreference::default()
        };
        Ok(self.describe(preference))
    }

    pub fn set(
        &self,
        preference: ContributionPreference,
    ) -> Result<ContributionStatus, &'static str> {
        if !self.available {
            return Err("contribution_unavailable");
        }
        preference.relay_limits()?;
        let _guard = self
            .lock
            .lock()
            .map_err(|_| "contribution_preference_unavailable")?;
        self.write(&preference)
            .map_err(|_| "contribution_preference_unavailable")?;
        Ok(self.describe(preference))
    }

    fn describe(&self, preference: ContributionPreference) -> ContributionStatus {
        let worst_case_relayed_bytes = preference
            .relay_limits()
            .ok()
            .flatten()
            .map_or(0, |limits| limits.max_bytes_per_circuit_period());
        ContributionStatus {
            available: self.available,
            preference,
            worst_case_relayed_bytes,
            circuit_duration_seconds: RelayLimits::circuit_duration().as_secs(),
        }
    }

    /// Reads the stored preference. A missing file means contribution is off;
    /// an unreadable or invalid file is reported instead of enabling anything.
    fn read(&self) -> Result<ContributionPreference, &'static str> {
        let preference: ContributionPreference = preference_file::read(&self.path)
            .map_err(|error| match error {
                PreferenceReadError::Unavailable => "contribution_preference_unavailable",
                PreferenceReadError::Invalid => "contribution_preference_invalid",
            })?
            .unwrap_or_default();
        preference
            .relay_limits()
            .map_err(|_| "contribution_preference_invalid")?;
        Ok(preference)
    }

    fn write(&self, preference: &ContributionPreference) -> std::io::Result<()> {
        preference_file::write(&self.path, preference)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service(directory: &tempfile::TempDir) -> ContributionService {
        ContributionService::with_availability(directory.path().join("contribution.json"), true)
    }

    #[test]
    fn contribution_is_off_without_a_stored_preference() {
        let directory = tempfile::tempdir().expect("temporary directory is available");

        let status = service(&directory).status().expect("status is available");

        assert!(status.available);
        assert_eq!(status.preference, ContributionPreference::default());
        assert_eq!(status.worst_case_relayed_bytes, 0);
        assert_eq!(status.circuit_duration_seconds, 300);
    }

    #[test]
    fn preference_persists_and_reports_worst_case_volume() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let preference = ContributionPreference {
            routing: true,
            relay: Some(RelayPreference {
                max_circuits: 4,
                max_circuit_mib: 8,
            }),
        };

        let stored = service(&directory)
            .set(preference)
            .expect("preference is stored");
        let reopened = service(&directory).status().expect("status is available");

        assert_eq!(stored, reopened);
        assert_eq!(reopened.preference, preference);
        assert_eq!(reopened.worst_case_relayed_bytes, 32 * 1024 * 1024);
        assert!(!directory.path().join("contribution.json.tmp").exists());
    }

    #[test]
    fn relay_requires_routing_and_bounded_limits() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let service = service(&directory);
        let relay = |max_circuits, max_circuit_mib| ContributionPreference {
            routing: true,
            relay: Some(RelayPreference {
                max_circuits,
                max_circuit_mib,
            }),
        };

        assert_eq!(
            service.set(ContributionPreference {
                routing: false,
                ..relay(4, 8)
            }),
            Err("relay_requires_routing")
        );
        assert_eq!(service.set(relay(0, 8)), Err("relay_limits_invalid"));
        assert_eq!(service.set(relay(33, 8)), Err("relay_limits_invalid"));
        assert_eq!(service.set(relay(4, 0)), Err("relay_limits_invalid"));
        assert_eq!(service.set(relay(4, 33)), Err("relay_limits_invalid"));
        assert!(!directory.path().join("contribution.json").exists());
    }

    #[test]
    fn invalid_stored_preference_is_reported_not_enabled() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let path = directory.path().join("contribution.json");

        std::fs::write(
            &path,
            br#"{"routing":false,"relay":{"maxCircuits":4,"maxCircuitMib":8}}"#,
        )
        .expect("file is written");
        assert_eq!(
            service(&directory).status(),
            Err("contribution_preference_invalid")
        );

        std::fs::write(&path, vec![b' '; 5000]).expect("file is written");
        assert_eq!(
            service(&directory).status(),
            Err("contribution_preference_invalid")
        );
    }

    #[test]
    fn unavailable_builds_refuse_contribution() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let service = ContributionService::with_availability(
            directory.path().join("contribution.json"),
            false,
        );

        let status = service.status().expect("status is available");

        assert!(!status.available);
        assert_eq!(status.preference, ContributionPreference::default());
        assert_eq!(
            service.set(ContributionPreference {
                routing: true,
                relay: None,
            }),
            Err("contribution_unavailable")
        );
    }
}
