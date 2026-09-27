//! Attested keep-alive connections to `llm.kubetee.ai`, one request in
//! flight on each.
//!
//! A connection enters the pool only after its attestation verified, and
//! goes back after a response body has been read to its end. It is retired
//! when it reaches its maximum age or request count, fails, or closes.

use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use hyper::body::{Body as HttpBody, Frame, Incoming, SizeHint};
use hyper::client::conn::http1::SendRequest;
use tokio::task::JoinHandle;

/// How long an attested connection may be used before it is renewed.
pub const MAX_AGE: Duration = Duration::from_secs(10 * 60);
/// How many requests one attested connection carries before it is renewed.
pub const MAX_REQUESTS: usize = 100;
/// How many idle attested connections are kept for reuse.
pub const MAX_IDLE: usize = 8;

/// The limits a pool enforces.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_age: Duration,
    pub max_requests: usize,
    pub max_idle: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_age: MAX_AGE,
            max_requests: MAX_REQUESTS,
            max_idle: MAX_IDLE,
        }
    }
}

/// An attested connection.
pub struct Attested {
    pub sender: SendRequest<Body>,
    pub driver: JoinHandle<Result<(), hyper::Error>>,
    pub attested_at: Instant,
    pub requests: usize,
}

impl Attested {
    fn usable(&self, limits: Limits) -> bool {
        self.attested_at.elapsed() < limits.max_age
            && self.requests < limits.max_requests
            && !self.sender.is_closed()
            && !self.driver.is_finished()
    }

    /// Close the connection.
    pub fn retire(self) {
        self.driver.abort();
    }
}

/// Idle attested connections.
#[derive(Debug, Default)]
pub struct Pool {
    idle: Mutex<Vec<Attested>>,
    limits: Limits,
}

impl std::fmt::Debug for Attested {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Attested")
            .field("attested_at", &self.attested_at)
            .field("requests", &self.requests)
            .finish_non_exhaustive()
    }
}

impl Pool {
    /// An empty pool enforcing `limits`.
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self {
            idle: Mutex::new(Vec::new()),
            limits,
        }
    }

    /// The most recently used idle connection still within its limits.
    /// Connections past their limits are retired on the way.
    pub fn take(&self) -> Option<Attested> {
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        while let Some(connection) = idle.pop() {
            if connection.usable(self.limits) {
                return Some(connection);
            }
            connection.retire();
        }
        None
    }

    /// Return a connection whose response was read to its end. It is kept
    /// when it is within its limits and the pool has room, else retired.
    pub fn give_back(&self, connection: Attested) {
        if !connection.usable(self.limits) {
            connection.retire();
            return;
        }
        let mut idle = self.idle.lock().unwrap_or_else(PoisonError::into_inner);
        if idle.len() < self.limits.max_idle {
            idle.push(connection);
        } else {
            drop(idle);
            connection.retire();
        }
    }

    /// Whether `connection` is still within the pool's limits.
    #[must_use]
    pub fn usable(&self, connection: &Attested) -> bool {
        connection.usable(self.limits)
    }

    /// How many idle connections the pool holds.
    #[must_use]
    pub fn idle(&self) -> usize {
        self.idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

/// A response body that returns its connection to the pool once it has been
/// read to its end, and closes the connection if it is dropped earlier or
/// fails.
pub struct Lease {
    body: Incoming,
    connection: Option<Attested>,
    pool: Arc<Pool>,
}

impl Lease {
    /// Tie `connection` to the response `body` it is carrying.
    #[must_use]
    pub fn new(body: Incoming, connection: Attested, pool: Arc<Pool>) -> Self {
        let mut lease = Self {
            body,
            connection: Some(connection),
            pool,
        };
        lease.give_back_if_read();
        lease
    }

    /// A server stops polling a body that reports its end, so the connection
    /// goes back as soon as the last frame has arrived.
    fn give_back_if_read(&mut self) {
        if self.body.is_end_stream() {
            if let Some(connection) = self.connection.take() {
                self.pool.give_back(connection);
            }
        }
    }
}

impl HttpBody for Lease {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut this.body)
            .poll_frame(context)
            .map_ok(strip_supplier_trailers);
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

/// Remove supplier fields from a trailers frame; data frames pass unchanged.
pub(crate) fn strip_supplier_trailers(frame: Frame<Bytes>) -> Frame<Bytes> {
    match frame.into_trailers() {
        Ok(mut trailers) => {
            super::strip_supplier_headers(&mut trailers);
            Frame::trailers(trailers)
        }
        Err(frame) => frame,
    }
}

impl Drop for Lease {
    fn drop(&mut self) {
        if let Some(connection) = self.connection.take() {
            connection.retire();
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "test values are known to be valid")]
mod tests {
    use super::*;

    #[test]
    fn supplier_trailers_are_removed_and_data_is_untouched() {
        let mut trailers = axum::http::HeaderMap::new();
        trailers.insert("x-kubetee-attestation-quote", "q".parse().unwrap());
        trailers.insert("x-litellm-key-spend", "0.14".parse().unwrap());
        trailers.insert("x-request-id", "m".parse().unwrap());
        let stripped = strip_supplier_trailers(Frame::trailers(trailers))
            .into_trailers()
            .unwrap();
        assert!(!stripped.contains_key("x-kubetee-attestation-quote"));
        assert!(!stripped.contains_key("x-litellm-key-spend"));
        assert!(stripped.contains_key("x-request-id"));
        let data = strip_supplier_trailers(Frame::data(Bytes::from_static(b"x-kubetee-")));
        assert_eq!(data.into_data().unwrap(), Bytes::from_static(b"x-kubetee-"));
    }
}
