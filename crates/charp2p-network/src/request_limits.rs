//! Bounds the rate of inbound CharP2P requests each remote peer may make.

use std::{collections::HashMap, time::Instant};

use libp2p::PeerId;

/// Per-peer token bucket shared by the join, invitation, and synchronization
/// protocols. A peer may send a burst of `burst` requests and then one request
/// per `1 / per_second` seconds; requests beyond that are answered `busy`
/// without reaching the application. A bucket is forgotten when the peer's
/// last connection closes, so state stays within the connection bounds.
pub(crate) struct PeerRequestLimiter {
    burst: f64,
    per_second: f64,
    buckets: HashMap<PeerId, Bucket>,
}

struct Bucket {
    tokens: f64,
    updated: Instant,
}

impl PeerRequestLimiter {
    pub(crate) fn new(burst: u32, per_second: u32) -> Self {
        Self {
            burst: f64::from(burst),
            per_second: f64::from(per_second),
            buckets: HashMap::new(),
        }
    }

    /// Takes one request from the peer's bucket, returning `false` when the
    /// peer has exhausted it.
    pub(crate) fn allow(&mut self, peer: PeerId, now: Instant) -> bool {
        let bucket = self.buckets.entry(peer).or_insert(Bucket {
            tokens: self.burst,
            updated: now,
        });
        let elapsed = now.saturating_duration_since(bucket.updated).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.per_second).min(self.burst);
        bucket.updated = now;
        if bucket.tokens < 1.0 {
            return false;
        }
        bucket.tokens -= 1.0;
        true
    }

    /// Drops the peer's bucket once it has no remaining connections.
    pub(crate) fn forget(&mut self, peer: &PeerId) {
        self.buckets.remove(peer);
    }

    #[cfg(test)]
    fn tracked_peers(&self) -> usize {
        self.buckets.len()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn allows_a_burst_then_refills_over_time() {
        let mut limiter = PeerRequestLimiter::new(3, 2);
        let peer = PeerId::random();
        let start = Instant::now();

        assert!((0..3).all(|_| limiter.allow(peer, start)));
        assert!(!limiter.allow(peer, start));

        // Half a second refills one request at two per second.
        let later = start + Duration::from_millis(500);
        assert!(limiter.allow(peer, later));
        assert!(!limiter.allow(peer, later));

        // A long pause refills only up to the burst.
        let much_later = later + Duration::from_secs(60);
        assert!((0..3).all(|_| limiter.allow(peer, much_later)));
        assert!(!limiter.allow(peer, much_later));
    }

    #[test]
    fn peers_have_independent_buckets_and_are_forgotten() {
        let mut limiter = PeerRequestLimiter::new(1, 1);
        let first = PeerId::random();
        let second = PeerId::random();
        let now = Instant::now();

        assert!(limiter.allow(first, now));
        assert!(!limiter.allow(first, now));
        assert!(limiter.allow(second, now));
        assert_eq!(limiter.tracked_peers(), 2);

        limiter.forget(&first);
        assert_eq!(limiter.tracked_peers(), 1);
        assert!(limiter.allow(first, now));
    }
}
