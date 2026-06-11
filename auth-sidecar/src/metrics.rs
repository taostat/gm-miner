//! Prometheus metric bundle for the sidecar.
//!
//! Metric names follow the same `gm_miner_*` convention as the rest of
//! the gm stack (envoy uses `envoy_*`; the miner's gm-specific series
//! all live under `gm_miner_*`). The naming is the contract the
//! gateway's capacity-aware router and the registry's control loop
//! agree on.

use std::time::SystemTime;

use prometheus::{Encoder, Gauge, GaugeVec, IntCounterVec, Opts, Registry, TextEncoder};
use thiserror::Error;

use crate::provider::OauthProvider;
use crate::refresh::FailureReason;

/// All metrics the sidecar emits. Owns its own [`Registry`] so the
/// `/metrics` endpoint encodes exactly the sidecar's series and
/// nothing else.
#[derive(Debug, Clone)]
pub struct Metrics {
    registry: Registry,
    /// Seconds until the current access token expires. Negative when
    /// the worker is wedged (token already expired and refresh has
    /// not landed).
    token_expires_in: GaugeVec,
    /// Total successful refreshes since boot.
    refresh_success: IntCounterVec,
    /// Total failed refreshes since boot, broken out by failure
    /// classification (`network` / `unauthorized` / `rate_limited` /
    /// `malformed`).
    refresh_failure: IntCounterVec,
    /// `1` when the worker has exhausted its retry budget and Envoy
    /// is expected to return 503 on this provider's route.
    provider_down: GaugeVec,
    /// Build / version of the sidecar binary. Constant — set once at
    /// startup. Lets scrapers diff sidecar versions across miners.
    build_info: Gauge,
}

/// Error type for the metrics initialiser. Prometheus's `register_*`
/// fns return `prometheus::Error`; wrap so the caller does not have
/// to depend on the prometheus crate's error type directly.
#[derive(Debug, Error)]
#[error("register prometheus metric: {0}")]
pub struct MetricsInitError(#[from] prometheus::Error);

impl Metrics {
    /// Construct the registry and register every series. Call once
    /// at startup.
    ///
    /// # Errors
    /// Returns an error if the underlying Prometheus crate refuses
    /// to register one of the series (e.g. a duplicate name — never
    /// expected in practice).
    pub fn new() -> Result<Self, MetricsInitError> {
        let registry = Registry::new();

        let token_expires_in = GaugeVec::new(
            Opts::new(
                "gm_miner_oauth_token_expires_in_seconds",
                "Seconds until the current OAuth access token expires; negative if it already has.",
            ),
            &["provider"],
        )?;
        registry.register(Box::new(token_expires_in.clone()))?;

        let refresh_success = IntCounterVec::new(
            Opts::new(
                "gm_miner_oauth_refresh_success_total",
                "Successful OAuth token refreshes since sidecar boot.",
            ),
            &["provider"],
        )?;
        registry.register(Box::new(refresh_success.clone()))?;

        let refresh_failure = IntCounterVec::new(
            Opts::new(
                "gm_miner_oauth_refresh_failure_total",
                "Failed OAuth token refreshes since sidecar boot, by failure classification.",
            ),
            &["provider", "reason"],
        )?;
        registry.register(Box::new(refresh_failure.clone()))?;

        let provider_down = GaugeVec::new(
            Opts::new(
                "gm_miner_provider_down",
                "1 if the OAuth subscription is unusable on this provider (Envoy returns 503).",
            ),
            &["provider"],
        )?;
        registry.register(Box::new(provider_down.clone()))?;

        let build_info = Gauge::with_opts(Opts::new(
            "gm_miner_auth_sidecar_build_info",
            "Always 1; the value carries no information — diff scrapers by labels.",
        ))?;
        build_info.set(1.0);
        registry.register(Box::new(build_info.clone()))?;

        // NB: `gm_miner_subscription_quota_remaining` is intentionally
        // omitted. Anthropic exposes per-call quota via
        // `anthropic-ratelimit-*` response headers; OpenAI does not
        // publish equivalent surface for subscription tokens. The
        // sidecar only sees the refresh exchange — it never sees the
        // inference call, so it cannot read those headers. Surfacing
        // a quota gauge from this layer would require Envoy to pump
        // the response headers back, which is Phase B. See the
        // research file (`docs/research/oauth-subscription-prior-
        // art.md`) for the underlying upstream surface.
        //
        // [NEEDS_OPERATOR]: confirm whether quota gauge should live
        // here or in Envoy's response-header tap.

        Ok(Self {
            registry,
            token_expires_in,
            refresh_success,
            refresh_failure,
            provider_down,
            build_info,
        })
    }

    /// Reference to the shared registry. The `/metrics` HTTP handler
    /// borrows this to encode the scrape response.
    #[must_use]
    pub fn registry(&self) -> &Registry {
        &self.registry
    }

    /// Initialise every provider's series so they appear in the
    /// scrape output as zero, before any refresh has run. Without
    /// this the scrape silently omits a provider's series until its
    /// first refresh — operators looking for the missing series read
    /// it as "the sidecar is broken" rather than "the sidecar is
    /// healthy and has not refreshed yet". Both labels exist for
    /// `refresh_failure` so dashboards can read every reason.
    pub fn seed_provider(&self, provider: OauthProvider) {
        let label = provider.as_str();
        self.token_expires_in.with_label_values(&[label]).set(0.0);
        self.refresh_success.with_label_values(&[label]).reset();
        for reason in [
            FailureReason::Network,
            FailureReason::Unauthorized,
            FailureReason::RateLimited,
            FailureReason::Malformed,
        ] {
            self.refresh_failure
                .with_label_values(&[label, reason.as_str()])
                .reset();
        }
        self.provider_down.with_label_values(&[label]).set(0.0);
    }

    /// Update the expiry countdown for a provider from an absolute
    /// expiry timestamp.
    pub fn observe_expires_at(
        &self,
        provider: OauthProvider,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) {
        let now_sys = SystemTime::now();
        let now_dt: chrono::DateTime<chrono::Utc> = now_sys.into();
        let delta = (expires_at - now_dt).num_seconds();
        #[expect(
            clippy::cast_precision_loss,
            reason = "Prometheus gauges are f64; the precision loss for an i64 seconds delta is below the 1-second resolution we care about"
        )]
        self.token_expires_in
            .with_label_values(&[provider.as_str()])
            .set(delta as f64);
    }

    pub fn record_refresh_success(&self, provider: OauthProvider) {
        self.refresh_success
            .with_label_values(&[provider.as_str()])
            .inc();
    }

    pub fn record_refresh_failure(&self, provider: OauthProvider, reason: FailureReason) {
        self.refresh_failure
            .with_label_values(&[provider.as_str(), reason.as_str()])
            .inc();
    }

    pub fn set_provider_down(&self, provider: OauthProvider, down: bool) {
        self.provider_down
            .with_label_values(&[provider.as_str()])
            .set(if down { 1.0 } else { 0.0 });
    }

    /// Re-set the build-info gauge to 1. Idempotent — exists so the
    /// startup log can confirm the metric is wired even when no
    /// scrape has happened.
    pub fn touch_build_info(&self) {
        self.build_info.set(1.0);
    }

    /// Encode the registry into the Prometheus text-exposition format.
    ///
    /// # Errors
    /// Returns an error if the encoder fails (in practice never — the
    /// text encoder writes into a `Vec<u8>`).
    pub fn encode(&self) -> Result<Vec<u8>, prometheus::Error> {
        let encoder = TextEncoder::new();
        let mut buf = Vec::new();
        encoder.encode(&self.registry.gather(), &mut buf)?;
        Ok(buf)
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "tests intentionally panic on unexpected values"
)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn build_registers_all_series_under_gm_miner_namespace() {
        let m = Metrics::new().unwrap();
        m.seed_provider(OauthProvider::Openai);
        m.seed_provider(OauthProvider::Anthropic);
        m.record_refresh_success(OauthProvider::Openai);
        m.record_refresh_failure(OauthProvider::Anthropic, FailureReason::RateLimited);
        m.set_provider_down(OauthProvider::Anthropic, true);
        m.observe_expires_at(
            OauthProvider::Openai,
            Utc::now() + chrono::Duration::seconds(1234),
        );
        let body = String::from_utf8(m.encode().unwrap()).unwrap();
        assert!(body.contains("gm_miner_oauth_token_expires_in_seconds"));
        assert!(body.contains("gm_miner_oauth_refresh_success_total"));
        assert!(body.contains("gm_miner_oauth_refresh_failure_total"));
        assert!(body.contains("gm_miner_provider_down"));
        assert!(body.contains("gm_miner_auth_sidecar_build_info"));
        // Sanity on label values landing in the scrape:
        assert!(body.contains(r#"provider="openai""#));
        assert!(body.contains(r#"provider="anthropic""#));
        assert!(body.contains(r#"reason="rate_limited""#));
    }

    #[test]
    fn seed_initialises_every_failure_reason_label() {
        let m = Metrics::new().unwrap();
        m.seed_provider(OauthProvider::Openai);
        let body = String::from_utf8(m.encode().unwrap()).unwrap();
        for r in ["network", "unauthorized", "rate_limited", "malformed"] {
            assert!(
                body.contains(&format!(r#"reason="{r}""#)),
                "missing reason={r} in:\n{body}",
            );
        }
    }
}
