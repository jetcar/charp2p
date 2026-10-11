//! Bounds the rate at which serving nodes read bytes from each remote peer and
//! remote IP address.

use std::{
    collections::HashMap,
    future::Future,
    hash::Hash,
    io,
    net::IpAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
    time::{Duration, Instant},
};

use futures::{AsyncRead, AsyncWrite};
use libp2p::{
    PeerId,
    core::{
        ConnectedPoint,
        muxing::{StreamMuxer, StreamMuxerEvent},
    },
};

use crate::ip_limits::direct_ip;

/// A throttled read waits until at least this many bytes, or the whole
/// requested read when smaller, are available instead of waking per byte.
const MIN_THROTTLED_READ_BYTES: f64 = 16.0 * 1024.0;

/// Token bucket parameters in bytes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct ByteRate {
    pub(crate) burst: u64,
    pub(crate) per_second: u64,
}

/// Byte buckets shared by every direct connection of a serving node. All
/// connections to one peer share that peer's bucket and all direct
/// connections from one remote IP address share that address's bucket; a read
/// proceeds only while both have bytes left. Relayed connections are not
/// wrapped, because their bytes are bounded by the relay's own circuit
/// limits. A bucket is forgotten when its last connection closes, so state
/// stays within the connection bounds.
#[derive(Clone)]
pub(crate) struct InboundByteLimiter {
    state: Arc<Mutex<State>>,
}

struct State {
    peers: Buckets<PeerId>,
    ips: Buckets<IpAddr>,
}

struct Buckets<K> {
    rate: ByteRate,
    entries: HashMap<K, Bucket>,
}

struct Bucket {
    tokens: f64,
    updated: Instant,
    connections: usize,
}

impl<K: Eq + Hash + Copy> Buckets<K> {
    fn new(rate: ByteRate) -> Self {
        Self {
            rate,
            entries: HashMap::new(),
        }
    }

    fn attach(&mut self, key: K, now: Instant) {
        self.entries
            .entry(key)
            .or_insert(Bucket {
                tokens: self.rate.burst as f64,
                updated: now,
                connections: 0,
            })
            .connections += 1;
    }

    fn detach(&mut self, key: &K) {
        if let Some(bucket) = self.entries.get_mut(key) {
            bucket.connections = bucket.connections.saturating_sub(1);
            if bucket.connections == 0 {
                self.entries.remove(key);
            }
        }
    }

    /// Refills the key's bucket and returns its bytes, which are negative
    /// while concurrent reads have overdrawn it.
    fn refill(&mut self, key: &K, now: Instant) -> f64 {
        let Some(bucket) = self.entries.get_mut(key) else {
            return f64::INFINITY;
        };
        let elapsed = now.saturating_duration_since(bucket.updated).as_secs_f64();
        bucket.tokens =
            (bucket.tokens + elapsed * self.rate.per_second as f64).min(self.rate.burst as f64);
        bucket.updated = now;
        bucket.tokens
    }

    fn take(&mut self, key: &K, bytes: f64) {
        if let Some(bucket) = self.entries.get_mut(key) {
            bucket.tokens -= bytes;
        }
    }

    /// Time until the key's bucket holds `wanted` bytes, capped by its burst.
    fn wait(&self, key: &K, wanted: f64) -> Duration {
        let Some(bucket) = self.entries.get(key) else {
            return Duration::ZERO;
        };
        let missing = wanted.min(self.rate.burst as f64) - bucket.tokens;
        if missing <= 0.0 {
            return Duration::ZERO;
        }
        if self.rate.per_second == 0 {
            return Duration::MAX;
        }
        Duration::from_secs_f64(missing / self.rate.per_second as f64)
    }
}

impl InboundByteLimiter {
    pub(crate) fn new(per_peer: ByteRate, per_ip: ByteRate) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                peers: Buckets::new(per_peer),
                ips: Buckets::new(per_ip),
            })),
        }
    }

    /// Registers a new connection to `peer`, counted against `ip` when it is
    /// a direct connection.
    pub(crate) fn connection(&self, peer: PeerId, ip: Option<IpAddr>) -> ConnectionBudget {
        let now = Instant::now();
        let mut state = self.lock();
        state.peers.attach(peer, now);
        if let Some(ip) = ip {
            state.ips.attach(ip, now);
        }
        ConnectionBudget {
            limiter: self.clone(),
            peer,
            ip,
        }
    }

    /// Wraps an authenticated connection's muxer so its substream reads draw
    /// from the peer's and remote IP address's buckets.
    pub(crate) fn wrap<M>(
        &self,
        peer: PeerId,
        endpoint: &ConnectedPoint,
        muxer: M,
    ) -> ThrottledMuxer<M> {
        let remote = match endpoint {
            ConnectedPoint::Dialer { address, .. } => address,
            ConnectedPoint::Listener { send_back_addr, .. } => send_back_addr,
        };
        ThrottledMuxer {
            inner: muxer,
            budget: Arc::new(self.connection(peer, direct_ip(remote))),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[cfg(test)]
    fn tracked(&self) -> (usize, usize) {
        let state = self.lock();
        (state.peers.entries.len(), state.ips.entries.len())
    }
}

/// One connection's share of the peer and IP buckets; dropping the last
/// handle of a connection releases it.
pub(crate) struct ConnectionBudget {
    limiter: InboundByteLimiter,
    peer: PeerId,
    ip: Option<IpAddr>,
}

impl ConnectionBudget {
    /// Returns how many of `wanted` bytes may be read now, or how long to
    /// wait before asking again.
    pub(crate) fn reserve(&self, wanted: usize, now: Instant) -> Result<usize, Duration> {
        let mut state = self.limiter.lock();
        let mut available = state.peers.refill(&self.peer, now);
        if let Some(ip) = &self.ip {
            available = available.min(state.ips.refill(ip, now));
        }
        if available >= 1.0 {
            return Ok(wanted.min(available as usize));
        }
        let wanted = (wanted as f64).min(MIN_THROTTLED_READ_BYTES);
        let mut wait = state.peers.wait(&self.peer, wanted);
        if let Some(ip) = &self.ip {
            wait = wait.max(state.ips.wait(ip, wanted));
        }
        Err(wait.max(Duration::from_millis(1)))
    }

    /// Takes bytes actually read from both buckets.
    pub(crate) fn consume(&self, bytes: usize) {
        let mut state = self.limiter.lock();
        state.peers.take(&self.peer, bytes as f64);
        if let Some(ip) = &self.ip {
            state.ips.take(ip, bytes as f64);
        }
    }
}

impl Drop for ConnectionBudget {
    fn drop(&mut self) {
        let mut state = self.limiter.lock();
        state.peers.detach(&self.peer);
        if let Some(ip) = &self.ip {
            state.ips.detach(ip);
        }
    }
}

/// Stream muxer whose substreams read within a connection budget.
pub(crate) struct ThrottledMuxer<M> {
    inner: M,
    budget: Arc<ConnectionBudget>,
}

impl<M> StreamMuxer for ThrottledMuxer<M>
where
    M: StreamMuxer + Unpin,
    M::Substream: Unpin,
{
    type Substream = ThrottledStream<M::Substream>;
    type Error = M::Error;

    fn poll_inbound(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        let this = self.get_mut();
        let stream = ready!(Pin::new(&mut this.inner).poll_inbound(cx))?;
        Poll::Ready(Ok(ThrottledStream::new(stream, this.budget.clone())))
    }

    fn poll_outbound(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::Substream, Self::Error>> {
        let this = self.get_mut();
        let stream = ready!(Pin::new(&mut this.inner).poll_outbound(cx))?;
        Poll::Ready(Ok(ThrottledStream::new(stream, this.budget.clone())))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }

    fn poll(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<StreamMuxerEvent, Self::Error>> {
        Pin::new(&mut self.get_mut().inner).poll(cx)
    }
}

/// Substream that delays reads while its connection budget is exhausted.
/// Unread bytes stay in the muxer's receive window, so the remote peer is
/// slowed down by flow control rather than buffered without bound.
pub(crate) struct ThrottledStream<S> {
    inner: S,
    budget: Arc<ConnectionBudget>,
    delay: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<S> ThrottledStream<S> {
    pub(crate) fn new(inner: S, budget: Arc<ConnectionBudget>) -> Self {
        Self {
            inner,
            budget,
            delay: None,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ThrottledStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }
        loop {
            if let Some(delay) = this.delay.as_mut() {
                ready!(delay.as_mut().poll(cx));
                this.delay = None;
            }
            match this.budget.reserve(buf.len(), Instant::now()) {
                Ok(allowed) => {
                    let read =
                        ready!(Pin::new(&mut this.inner).poll_read(cx, &mut buf[..allowed]))?;
                    this.budget.consume(read);
                    return Poll::Ready(Ok(read));
                }
                Err(wait) => this.delay = Some(Box::pin(tokio::time::sleep(wait))),
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ThrottledStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use futures::{AsyncReadExt, io::Cursor};

    use super::*;

    fn rate(burst: u64, per_second: u64) -> ByteRate {
        ByteRate { burst, per_second }
    }

    #[test]
    fn peer_bucket_allows_a_burst_then_refills_over_time() {
        let limiter = InboundByteLimiter::new(rate(100, 50), rate(1_000, 1_000));
        let budget = limiter.connection(PeerId::random(), None);
        let start = Instant::now();

        assert_eq!(budget.reserve(60, start), Ok(60));
        budget.consume(60);
        assert_eq!(budget.reserve(60, start), Ok(40));
        budget.consume(40);
        // An empty bucket at 50 bytes per second needs a second for 50 bytes.
        assert_eq!(budget.reserve(50, start), Err(Duration::from_secs(1)));

        let later = start + Duration::from_millis(200);
        assert_eq!(budget.reserve(60, later), Ok(10));
        // A long pause refills only up to the burst.
        assert_eq!(
            budget.reserve(500, later + Duration::from_secs(60)),
            Ok(100)
        );
    }

    #[test]
    fn connections_from_one_ip_share_its_bucket_but_not_peer_buckets() {
        let limiter = InboundByteLimiter::new(rate(100, 0), rate(150, 0));
        let ip = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)));
        let first = limiter.connection(PeerId::random(), ip);
        let second = limiter.connection(PeerId::random(), ip);
        let relayed = limiter.connection(PeerId::random(), None);
        let now = Instant::now();

        assert_eq!(first.reserve(100, now), Ok(100));
        first.consume(100);
        assert_eq!(second.reserve(100, now), Ok(50));
        second.consume(50);
        assert_eq!(second.reserve(1, now), Err(Duration::MAX));
        assert_eq!(relayed.reserve(100, now), Ok(100));
    }

    #[test]
    fn connections_to_one_peer_share_its_bucket_until_the_last_one_closes() {
        let limiter = InboundByteLimiter::new(rate(100, 0), rate(1_000, 0));
        let peer = PeerId::random();
        let ip = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8)));
        let first = limiter.connection(peer, ip);
        let second = limiter.connection(peer, None);
        let now = Instant::now();

        first.consume(100);
        assert!(second.reserve(1, now).is_err());
        drop(first);
        assert_eq!(limiter.tracked(), (1, 0));
        assert!(second.reserve(1, now).is_err());
        drop(second);
        assert_eq!(limiter.tracked(), (0, 0));

        let reconnected = limiter.connection(peer, None);
        assert_eq!(reconnected.reserve(100, now), Ok(100));
    }

    #[tokio::test]
    async fn throttled_stream_delays_reads_beyond_the_budget() {
        let limiter = InboundByteLimiter::new(rate(10, 200), rate(1_000, 1_000));
        let budget = Arc::new(limiter.connection(PeerId::random(), None));
        let mut stream = ThrottledStream::new(Cursor::new(vec![7_u8; 30]), budget);
        let started = Instant::now();

        let mut received = Vec::new();
        stream
            .read_to_end(&mut received)
            .await
            .expect("cursor reads succeed");

        assert_eq!(received, vec![7_u8; 30]);
        // Ten bytes come from the burst; the other twenty refill at 200 bytes
        // per second.
        assert!(started.elapsed() >= Duration::from_millis(90));
    }
}
