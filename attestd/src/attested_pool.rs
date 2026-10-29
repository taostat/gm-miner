//! Reusable HTTP/1 connections that were attested on their live TLS session.

use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::{Body, Bytes};
use chrono::{DateTime, Utc};
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use hyper::client::conn::http1::SendRequest;
use tokio::task::JoinHandle;
use tokio::time::Instant;

pub const MAX_AGE: Duration = Duration::from_secs(10 * 60);
pub const MAX_IDLE_AGE: Duration = Duration::from_secs(90);
pub const MAX_REQUESTS: usize = 100;
pub const MAX_IDLE: usize = 8;

#[derive(Clone, Copy, Debug)]
pub struct PoolLimits {
    pub age: Duration,
    pub idle_age: Option<Duration>,
    pub requests: usize,
    pub idle: usize,
}

impl Default for PoolLimits {
    fn default() -> Self {
        Self {
            age: MAX_AGE,
            idle_age: Some(MAX_IDLE_AGE),
            requests: MAX_REQUESTS,
            idle: MAX_IDLE,
        }
    }
}

pub struct Attested {
    pub sender: SendRequest<Body>,
    pub driver: JoinHandle<Result<(), hyper::Error>>,
    pub attested_at: Instant,
    pub idle_since: Option<Instant>,
    pub expires_at: Option<DateTime<Utc>>,
    pub requests: usize,
}

impl Attested {
    fn usable(&self, limits: PoolLimits) -> bool {
        self.usable_at(limits, Utc::now())
    }

    fn usable_at(&self, limits: PoolLimits, now: DateTime<Utc>) -> bool {
        self.expires_at.is_none_or(|deadline| now < deadline)
            && self.attested_at.elapsed() < limits.age
            && self.idle_since.is_none_or(|idle_since| {
                limits
                    .idle_age
                    .is_none_or(|max_idle_age| idle_since.elapsed() < max_idle_age)
            })
            && self.requests < limits.requests
            && !self.sender.is_closed()
            && !self.driver.is_finished()
    }

    pub fn retire(self) {
        drop(self);
    }
}

impl Drop for Attested {
    fn drop(&mut self) {
        // Dropping a JoinHandle detaches its task. Cancellation must close the
        // transport even while a request body or response headers are pending.
        self.driver.abort();
    }
}

impl std::fmt::Debug for Attested {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Attested")
            .field("attested_at", &self.attested_at)
            .field("idle_since", &self.idle_since)
            .field("expires_at", &self.expires_at)
            .field("requests", &self.requests)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Default)]
pub struct Pool {
    idle: Mutex<Vec<Attested>>,
    limits: PoolLimits,
}

impl Pool {
    #[must_use]
    pub fn new(limits: PoolLimits) -> Self {
        Self {
            idle: Mutex::new(Vec::new()),
            limits,
        }
    }

    pub fn take(&self) -> Option<Attested> {
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        // Sweep the whole pool so a frequently reused entry cannot keep
        // older, closed transports occupying the remaining idle slots.
        idle.retain(|connection| connection.usable(self.limits));
        idle.pop()
    }

    pub fn give_back(&self, mut connection: Attested) {
        connection.idle_since = Some(Instant::now());
        if !connection.usable(self.limits) {
            connection.retire();
            return;
        }
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        idle.retain(|connection| connection.usable(self.limits));
        if idle.len() < self.limits.idle {
            idle.push(connection);
        } else {
            drop(idle);
            connection.retire();
        }
    }

    #[must_use]
    pub fn usable(&self, connection: &Attested) -> bool {
        connection.usable(self.limits)
    }

    #[must_use]
    pub fn idle(&self) -> usize {
        self.idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

pub struct Lease {
    body: Body,
    connection: Option<Attested>,
    pool: Arc<Pool>,
}

impl Lease {
    #[must_use]
    pub fn new(body: Body, connection: Attested, pool: Arc<Pool>) -> Self {
        let mut lease = Self {
            body,
            connection: Some(connection),
            pool,
        };
        lease.give_back_if_read();
        lease
    }

    fn give_back_if_read(&mut self) {
        // HTTP servers may stop polling after the final frame, without a
        // subsequent poll returning None.
        if self.body.is_end_stream() {
            if let Some(connection) = self.connection.take() {
                self.pool.give_back(connection);
            }
        }
    }
}

impl HttpBody for Lease {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.body).poll_frame(context);
        match &polled {
            Poll::Ready(None) => {
                if let Some(connection) = this.connection.take() {
                    this.pool.give_back(connection);
                }
            }
            Poll::Ready(Some(Err(_))) => {
                if let Some(connection) = this.connection.take() {
                    connection.retire();
                }
            }
            Poll::Ready(Some(Ok(_))) => this.give_back_if_read(),
            Poll::Pending => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test values are known to be valid")]
mod tests {
    use super::*;

    async fn connection(expires_at: Option<DateTime<Utc>>) -> (Attested, tokio::io::DuplexStream) {
        let (client, peer) = tokio::io::duplex(1024);
        let (sender, driver) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(client))
                .await
                .unwrap();
        (
            Attested {
                sender,
                driver: tokio::spawn(driver),
                attested_at: Instant::now(),
                idle_since: None,
                expires_at,
                requests: 0,
            },
            peer,
        )
    }

    #[tokio::test]
    async fn an_expiry_deadline_is_enforced_at_checkout_and_return() {
        let deadline = Utc::now() + chrono::Duration::hours(1);
        let (pooled, _peer) = connection(Some(deadline)).await;
        let pool = Pool::default();
        pool.give_back(pooled);
        assert_eq!(pool.idle(), 1);
        pool.idle.lock().unwrap()[0].expires_at = Some(Utc::now() - chrono::Duration::seconds(1));
        assert!(pool.take().is_none());
        assert_eq!(pool.idle(), 0);

        let (expired, _peer) = connection(Some(Utc::now() - chrono::Duration::seconds(1))).await;
        pool.give_back(expired);
        assert_eq!(pool.idle(), 0);
    }

    #[tokio::test]
    async fn an_expiry_deadline_is_exact_and_survives_reuse() {
        let deadline = "2099-01-01T00:00:00.123456789Z"
            .parse::<DateTime<Utc>>()
            .unwrap();
        let (attested, _peer) = connection(Some(deadline)).await;
        let limits = PoolLimits::default();
        assert!(attested.usable_at(limits, deadline - chrono::Duration::nanoseconds(1)));
        assert!(!attested.usable_at(limits, deadline));
        assert!(!attested.usable_at(limits, deadline + chrono::Duration::nanoseconds(1)));
        attested.retire();

        let pool = Pool::default();
        let (connection, _peer) = connection(Some(deadline)).await;
        pool.give_back(connection);
        let reused = pool.take().unwrap();
        assert_eq!(reused.expires_at, Some(deadline));
        assert!(!reused.usable_at(limits, deadline));
        reused.retire();
    }

    #[tokio::test]
    async fn max_age_and_request_count_are_enforced() {
        let (mut connection, _peer) = connection(None).await;
        let limits = PoolLimits::default();
        assert!(connection.usable_at(limits, Utc::now()));
        connection.requests = limits.requests;
        assert!(!connection.usable_at(limits, Utc::now()));
        connection.requests = 0;
        connection.attested_at = Instant::now().checked_sub(limits.age).unwrap();
        assert!(!connection.usable_at(limits, Utc::now()));
        connection.retire();
    }

    async fn assert_closed(mut peer: tokio::io::DuplexStream) {
        use tokio::io::AsyncReadExt as _;
        let error = tokio::time::timeout(Duration::from_secs(1), peer.read_u8())
            .await
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test(start_paused = true)]
    async fn checkout_sweeps_expired_entries_behind_a_fresh_one() {
        let pool = Pool::default();
        let (old, old_peer) = connection(None).await;
        pool.give_back(old);
        let (fresh, _fresh_peer) = connection(None).await;
        pool.give_back(fresh);
        assert_eq!(pool.idle(), 2);
        pool.idle.lock().unwrap()[0].attested_at = Instant::now().checked_sub(MAX_AGE).unwrap();
        let fresh = pool.take().unwrap();
        assert!(pool.usable(&fresh));
        assert_eq!(pool.idle(), 0);
        assert_closed(old_peer).await;
    }

    #[tokio::test(start_paused = true)]
    async fn kubetee_keeps_its_existing_idle_reuse_window() {
        let pool = Pool::new(crate::kubetee_verify::pool::Limits::default().pool_limits());
        let (connection, peer) = connection(None).await;
        pool.give_back(connection);
        tokio::time::advance(MAX_IDLE_AGE).await;
        let reused = pool.take().unwrap();
        assert!(pool.usable(&reused));
        pool.give_back(reused);
        tokio::time::advance(MAX_AGE.checked_sub(MAX_IDLE_AGE).unwrap()).await;
        assert!(pool.take().is_none());
        assert_closed(peer).await;
    }

    #[tokio::test]
    async fn checkout_rejects_a_connection_at_the_request_limit() {
        let pool = Pool::default();
        let (connection, peer) = connection(None).await;
        pool.give_back(connection);
        pool.idle.lock().unwrap()[0].requests = MAX_REQUESTS;
        assert!(pool.take().is_none());
        assert_closed(peer).await;
    }

    #[tokio::test(start_paused = true)]
    async fn checkout_retires_a_connection_after_its_idle_limit() {
        let pool = Pool::default();
        let (connection, peer) = connection(None).await;
        pool.give_back(connection);
        tokio::time::advance(MAX_IDLE_AGE).await;
        assert!(pool.take().is_none());
        assert_eq!(pool.idle(), 0);
        assert_closed(peer).await;
    }

    #[tokio::test(start_paused = true)]
    async fn returning_a_connection_reclaims_expired_idle_slots() {
        let pool = Pool::new(PoolLimits {
            idle: 1,
            ..PoolLimits::default()
        });
        let (old, old_peer) = connection(None).await;
        pool.give_back(old);
        tokio::time::advance(MAX_AGE).await;
        let (fresh, _peer) = connection(None).await;
        pool.give_back(fresh);
        assert_eq!(pool.idle(), 1);
        assert!(pool.take().is_some());
        assert_closed(old_peer).await;
    }

    #[tokio::test]
    async fn the_idle_cap_and_pool_drop_close_transports() {
        let pool = Pool::default();
        let mut peers = Vec::new();
        for _ in 0..MAX_IDLE {
            let (connection, peer) = connection(None).await;
            pool.give_back(connection);
            peers.push(peer);
        }
        let (extra, peer) = connection(None).await;
        pool.give_back(extra);
        assert_eq!(pool.idle(), MAX_IDLE);
        assert_closed(peer).await;
        drop(pool);
        for peer in peers {
            assert_closed(peer).await;
        }
    }

    #[tokio::test]
    async fn dropping_an_owner_aborts_even_a_busy_driver() {
        let (mut connection, _peer) = connection(None).await;
        connection.driver.abort();
        connection.driver = tokio::spawn(std::future::pending());
        let driver = connection.driver.abort_handle();
        drop(connection);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !driver.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}
