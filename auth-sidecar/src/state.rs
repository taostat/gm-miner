//! Shared in-memory token cache.
//!
//! Each provider gets a [`ProviderState`]. The worker writes into it on
//! every successful refresh; the HTTP server reads from it on every
//! Envoy token query. Concurrent access is bounded — one writer (the
//! per-provider worker task) and many readers (each Envoy data-plane
//! request) — so an [`tokio::sync::RwLock`] models the access pattern
//! exactly. The lock is held for microseconds: read the current
//! [`TokenSnapshot`] and clone three `String`s out, then release.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::RwLock;

use crate::provider::OauthProvider;

/// Current OAuth token for one provider, plus a health bit.
///
/// `healthy = false` means the worker exhausted its retry budget and
/// the operator should expect 503s on this provider's Envoy route
/// until the next successful refresh (or an operator paste of a new
/// auth file).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct TokenSnapshot {
    pub access_token: String,
    pub expires_at: DateTime<Utc>,
    pub healthy: bool,
}

/// Per-provider state cell. Cloned freely — the inner `Arc<RwLock<_>>`
/// makes every clone point at the same lock.
#[derive(Debug, Clone)]
pub struct ProviderState {
    provider: OauthProvider,
    inner: Arc<RwLock<TokenSnapshot>>,
}

impl ProviderState {
    /// Seed the state with the initial access token / expiry the
    /// operator pasted at deploy. `healthy = true` until the worker
    /// observes its first refresh failure.
    #[must_use]
    pub fn new(
        provider: OauthProvider,
        initial_access_token: String,
        initial_expires_at: DateTime<Utc>,
    ) -> Self {
        Self {
            provider,
            inner: Arc::new(RwLock::new(TokenSnapshot {
                access_token: initial_access_token,
                expires_at: initial_expires_at,
                healthy: true,
            })),
        }
    }

    /// Which provider this cell tracks.
    #[must_use]
    pub fn provider(&self) -> OauthProvider {
        self.provider
    }

    /// Read the current snapshot. Cheap (one clone of three short
    /// strings, two timestamps, a bool).
    pub async fn snapshot(&self) -> TokenSnapshot {
        self.inner.read().await.clone()
    }

    /// Replace the token + expiry after a successful refresh and mark
    /// the provider healthy.
    pub async fn record_success(&self, access_token: String, expires_at: DateTime<Utc>) {
        let mut g = self.inner.write().await;
        g.access_token = access_token;
        g.expires_at = expires_at;
        g.healthy = true;
    }

    /// Mark the provider unhealthy without touching the token /
    /// expiry. Reads keep returning the last successful values so the
    /// data plane stays usable until they actually expire.
    pub async fn mark_unhealthy(&self) {
        self.inner.write().await.healthy = false;
    }
}

/// Aggregate state — a map from provider to per-provider cell. Lives
/// as long as the sidecar binary.
#[derive(Debug, Clone, Default)]
pub struct StateRegistry {
    by_provider: HashMap<OauthProvider, ProviderState>,
}

impl StateRegistry {
    /// Build a registry from a slice of pre-seeded provider cells.
    #[must_use]
    pub fn from_states(states: impl IntoIterator<Item = ProviderState>) -> Self {
        let mut by_provider = HashMap::new();
        for s in states {
            by_provider.insert(s.provider(), s);
        }
        Self { by_provider }
    }

    /// Look up the cell for one provider. Returns `None` for a
    /// provider running in api-key mode (no sidecar work to do).
    #[must_use]
    pub fn get(&self, provider: OauthProvider) -> Option<&ProviderState> {
        self.by_provider.get(&provider)
    }

    /// Iterate every registered cell.
    pub fn iter(&self) -> impl Iterator<Item = &ProviderState> {
        self.by_provider.values()
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "tests intentionally panic on unexpected values"
)]
mod tests {
    use super::*;

    fn ts(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    #[tokio::test]
    async fn initial_snapshot_is_healthy() {
        let s = ProviderState::new(
            OauthProvider::Openai,
            "at-1".into(),
            ts("2030-01-01T00:00:00Z"),
        );
        let snap = s.snapshot().await;
        assert_eq!(snap.access_token, "at-1");
        assert!(snap.healthy);
    }

    #[tokio::test]
    async fn record_success_replaces_token_and_marks_healthy() {
        let s = ProviderState::new(
            OauthProvider::Openai,
            "at-1".into(),
            ts("2030-01-01T00:00:00Z"),
        );
        s.mark_unhealthy().await;
        s.record_success("at-2".into(), ts("2030-01-02T00:00:00Z"))
            .await;
        let snap = s.snapshot().await;
        assert_eq!(snap.access_token, "at-2");
        assert_eq!(snap.expires_at, ts("2030-01-02T00:00:00Z"));
        assert!(snap.healthy);
    }

    #[tokio::test]
    async fn mark_unhealthy_keeps_token() {
        let s = ProviderState::new(
            OauthProvider::Anthropic,
            "at-1".into(),
            ts("2030-01-01T00:00:00Z"),
        );
        s.mark_unhealthy().await;
        let snap = s.snapshot().await;
        assert_eq!(snap.access_token, "at-1");
        assert!(!snap.healthy);
    }

    #[tokio::test]
    async fn registry_round_trips_lookup() {
        let s = ProviderState::new(
            OauthProvider::Openai,
            "at-1".into(),
            ts("2030-01-01T00:00:00Z"),
        );
        let r = StateRegistry::from_states([s]);
        assert!(r.get(OauthProvider::Openai).is_some());
        assert!(r.get(OauthProvider::Anthropic).is_none());
        assert_eq!(r.iter().count(), 1);
    }
}
