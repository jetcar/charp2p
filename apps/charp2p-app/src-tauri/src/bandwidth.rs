use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::preference_file::{self, PreferenceReadError};

/// Smallest and largest accepted synchronization data limit (ADR-033).
pub const MIN_SYNC_LIMIT_MIB_PER_HOUR: u32 = 1;
pub const MAX_SYNC_LIMIT_MIB_PER_HOUR: u32 = 1024;
const BYTES_PER_MIB: u64 = 1024 * 1024;
const BUDGET_PERIOD: Duration = Duration::from_secs(60 * 60);

/// Device-local synchronization data limit (ADR-033). Holds no secrets and is
/// never synchronized.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BandwidthPreference {
    /// `None` leaves client synchronization unlimited.
    pub sync_limit_mib_per_hour: Option<u32>,
}

impl BandwidthPreference {
    pub fn validate(&self) -> Result<(), &'static str> {
        match self.sync_limit_mib_per_hour {
            Some(limit)
                if !(MIN_SYNC_LIMIT_MIB_PER_HOUR..=MAX_SYNC_LIMIT_MIB_PER_HOUR)
                    .contains(&limit) =>
            {
                Err("bandwidth_limit_invalid")
            }
            _ => Ok(()),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BandwidthStatus {
    pub preference: BandwidthPreference,
    /// Synchronization bytes still allowed now; `None` when unlimited.
    pub remaining_sync_bytes: Option<u64>,
}

/// Token bucket holding one hour of the limit and refilling continuously.
/// Charges may drive it below zero by the bytes of one bounded exchange.
#[derive(Debug)]
struct SyncBudget {
    limit_bytes: u64,
    available: i128,
    updated: Instant,
}

impl SyncBudget {
    fn new(limit_mib_per_hour: u32, now: Instant) -> Self {
        let limit_bytes = u64::from(limit_mib_per_hour) * BYTES_PER_MIB;
        Self {
            limit_bytes,
            available: i128::from(limit_bytes),
            updated: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.updated);
        let refilled = i128::from(self.limit_bytes) * elapsed.as_millis() as i128
            / BUDGET_PERIOD.as_millis() as i128;
        if refilled > 0 {
            self.available = (self.available + refilled).min(i128::from(self.limit_bytes));
            self.updated = now;
        }
    }

    fn remaining(&mut self, now: Instant) -> u64 {
        self.refill(now);
        u64::try_from(self.available.max(0)).unwrap_or(0)
    }

    fn charge(&mut self, bytes: u64, now: Instant) {
        self.refill(now);
        self.available -= i128::from(bytes);
    }
}

/// Stores the bandwidth preference next to the database and meters client
/// synchronization against it.
pub struct BandwidthService {
    path: PathBuf,
    state: Mutex<BandwidthState>,
}

#[derive(Default)]
struct BandwidthState {
    /// Budget for the limit currently stored; rebuilt when the limit changes.
    budget: Option<(u32, SyncBudget)>,
}

impl BandwidthService {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            state: Mutex::new(BandwidthState::default()),
        }
    }

    pub fn status(&self) -> Result<BandwidthStatus, &'static str> {
        self.status_at(Instant::now())
    }

    pub fn set(&self, preference: BandwidthPreference) -> Result<BandwidthStatus, &'static str> {
        preference.validate()?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| "bandwidth_preference_unavailable")?;
        preference_file::write(&self.path, &preference)
            .map_err(|_| "bandwidth_preference_unavailable")?;
        let now = Instant::now();
        let remaining_sync_bytes = Self::remaining(&mut state, preference, now);
        Ok(BandwidthStatus {
            preference,
            remaining_sync_bytes,
        })
    }

    /// Refuses to start a synchronization exchange when the budget is spent
    /// or the stored preference cannot be read.
    pub fn ensure_sync_budget(&self) -> Result<(), &'static str> {
        match self.status()?.remaining_sync_bytes {
            Some(0) => Err("synchronization_bandwidth_limited"),
            _ => Ok(()),
        }
    }

    /// Charges bytes transferred by one completed synchronization exchange.
    pub fn charge_sync_bytes(&self, bytes: u64) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if let Some((_, budget)) = state.budget.as_mut() {
            budget.charge(bytes, Instant::now());
        }
    }

    fn status_at(&self, now: Instant) -> Result<BandwidthStatus, &'static str> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "bandwidth_preference_unavailable")?;
        let preference = self.read()?;
        let remaining_sync_bytes = Self::remaining(&mut state, preference, now);
        Ok(BandwidthStatus {
            preference,
            remaining_sync_bytes,
        })
    }

    fn remaining(
        state: &mut BandwidthState,
        preference: BandwidthPreference,
        now: Instant,
    ) -> Option<u64> {
        let Some(limit) = preference.sync_limit_mib_per_hour else {
            state.budget = None;
            return None;
        };
        match state.budget.as_mut() {
            Some((current, budget)) if *current == limit => Some(budget.remaining(now)),
            _ => {
                let mut budget = SyncBudget::new(limit, now);
                let remaining = budget.remaining(now);
                state.budget = Some((limit, budget));
                Some(remaining)
            }
        }
    }

    /// A missing file means no limit; an unreadable or invalid file is
    /// reported instead of lifting a limit.
    fn read(&self) -> Result<BandwidthPreference, &'static str> {
        let preference = preference_file::read::<BandwidthPreference>(&self.path)
            .map_err(|error| match error {
                PreferenceReadError::Unavailable => "bandwidth_preference_unavailable",
                PreferenceReadError::Invalid => "bandwidth_preference_invalid",
            })?
            .unwrap_or_default();
        preference
            .validate()
            .map_err(|_| "bandwidth_preference_invalid")?;
        Ok(preference)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service(directory: &tempfile::TempDir) -> BandwidthService {
        BandwidthService::new(directory.path().join("bandwidth.json"))
    }

    fn limited(mib: u32) -> BandwidthPreference {
        BandwidthPreference {
            sync_limit_mib_per_hour: Some(mib),
        }
    }

    #[test]
    fn synchronization_is_unlimited_without_a_stored_preference() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let service = service(&directory);

        let status = service.status().expect("status is available");

        assert_eq!(status.preference, BandwidthPreference::default());
        assert_eq!(status.remaining_sync_bytes, None);
        service.charge_sync_bytes(u64::MAX);
        assert_eq!(service.ensure_sync_budget(), Ok(()));
    }

    #[test]
    fn limit_outside_bounds_is_refused() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let service = service(&directory);

        for limit in [0, MAX_SYNC_LIMIT_MIB_PER_HOUR + 1] {
            assert_eq!(service.set(limited(limit)), Err("bandwidth_limit_invalid"));
        }
        assert!(!directory.path().join("bandwidth.json").exists());
    }

    #[test]
    fn preference_persists_and_spent_budget_refuses_synchronization() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let stored = service(&directory)
            .set(limited(2))
            .expect("preference is stored");
        assert_eq!(stored.remaining_sync_bytes, Some(2 * BYTES_PER_MIB));

        let reopened = service(&directory);
        assert_eq!(
            reopened.status().expect("status is available").preference,
            limited(2)
        );
        reopened.charge_sync_bytes(BYTES_PER_MIB);
        assert_eq!(reopened.ensure_sync_budget(), Ok(()));
        reopened.charge_sync_bytes(3 * BYTES_PER_MIB);
        assert_eq!(
            reopened.ensure_sync_budget(),
            Err("synchronization_bandwidth_limited")
        );

        reopened
            .set(BandwidthPreference::default())
            .expect("limit is removed");
        assert_eq!(reopened.ensure_sync_budget(), Ok(()));
    }

    #[test]
    fn changing_the_limit_starts_a_full_budget() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let service = service(&directory);
        service.set(limited(1)).expect("preference is stored");
        service.charge_sync_bytes(5 * BYTES_PER_MIB);

        let status = service.set(limited(4)).expect("preference is stored");

        assert_eq!(status.remaining_sync_bytes, Some(4 * BYTES_PER_MIB));
    }

    #[test]
    fn budget_refills_continuously_up_to_one_hour_of_the_limit() {
        let start = Instant::now();
        let mut budget = SyncBudget::new(60, start);
        budget.charge(70 * BYTES_PER_MIB, start);
        assert_eq!(budget.remaining(start), 0);

        // 60 MiB per hour refills 1 MiB per minute, from the 10 MiB overshoot.
        assert_eq!(budget.remaining(start + Duration::from_secs(5 * 60)), 0);
        assert_eq!(
            budget.remaining(start + Duration::from_secs(15 * 60)),
            5 * BYTES_PER_MIB
        );
        assert_eq!(
            budget.remaining(start + Duration::from_secs(3 * 60 * 60)),
            60 * BYTES_PER_MIB
        );
    }

    #[test]
    fn invalid_stored_preference_refuses_synchronization() {
        let directory = tempfile::tempdir().expect("temporary directory is available");
        let path = directory.path().join("bandwidth.json");

        for contents in [
            br#"{"syncLimitMibPerHour":0}"#.as_slice(),
            br#"{"syncLimitMibPerHour":5,"extra":1}"#.as_slice(),
            b"{".as_slice(),
        ] {
            std::fs::write(&path, contents).expect("file is written");
            assert_eq!(
                service(&directory).status(),
                Err("bandwidth_preference_invalid")
            );
            assert_eq!(
                service(&directory).ensure_sync_budget(),
                Err("bandwidth_preference_invalid")
            );
        }
    }
}
