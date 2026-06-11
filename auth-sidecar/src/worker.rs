//! Per-provider refresh worker.
//!
//! One task per enabled provider. Sleeps until `expires_at - skew`,
//! then runs [`refresh_once`]. On success: writes the new token into
//! the [`ProviderState`], records metrics, schedules the next sleep
//! from the new expiry. On failure: bumps the failure counter,
//! retries with exponential backoff + jitter up to a configured cap;
//! once the budget is exhausted the provider is marked unhealthy and
//! the worker keeps retrying on a slow cadence so the operator can
//! recover by pasting a new auth file (Phase A) or by Phase B's
//! in-CVM OAuth flow.

use std::time::Duration;

use chrono::{DateTime, Utc};
use rand::Rng;
use tokio_util::sync::CancellationToken;

use crate::metrics::Metrics;
use crate::provider::OauthProvider;
use crate::refresh::{refresh_once, RefreshError, RefreshOutcome};
use crate::state::ProviderState;

/// Knobs on the refresh schedule. Defaults match the Hermes / research
/// numbers (120s skew before expiry, max 3 retries on failure before
/// marking down).
#[derive(Debug, Clone, Copy)]
pub struct RetryPolicy {
    /// How long before access-token expiry to attempt a refresh.
    pub refresh_skew: Duration,
    /// First retry-backoff. Subsequent retries double up to
    /// `max_backoff`.
    pub initial_backoff: Duration,
    /// Upper bound on a single sleep between retries.
    pub max_backoff: Duration,
    /// Multiplicative jitter range — every backoff is multiplied by a
    /// random value in `1.0 - jitter ..= 1.0 + jitter`.
    pub jitter_ratio: f64,
    /// Max retries before marking the provider unhealthy. Once
    /// exhausted, the worker keeps retrying on the `unhealthy_*`
    /// cadence below.
    pub max_retries: usize,
    /// Sleep between probes once the provider has been marked
    /// unhealthy. Slow on purpose — the access token is dead, the
    /// data plane is failing, no point hammering the upstream.
    pub unhealthy_probe_interval: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            refresh_skew: Duration::from_secs(120),
            initial_backoff: Duration::from_secs(2),
            max_backoff: Duration::from_secs(60),
            jitter_ratio: 0.25,
            max_retries: 3,
            unhealthy_probe_interval: Duration::from_secs(300),
        }
    }
}

/// Spawn-friendly entry point: drives one provider's refresh forever.
///
/// `cancel` is the shutdown token — flipping it cancels the in-flight
/// sleep and the worker returns. The HTTP client is shared so the
/// connection pool serves every provider. Both Anthropic and `OpenAI`
/// (per the research file) rotate the refresh token on every refresh
/// — the rotated token lives in memory only for Phase A; a sidecar
/// restart picks up the original env-var token, still valid until the
/// next rotation lands.
pub async fn run_provider_worker(
    client: reqwest::Client,
    provider: OauthProvider,
    initial_refresh_token: String,
    state: ProviderState,
    metrics: Metrics,
    policy: RetryPolicy,
    cancel: CancellationToken,
) {
    let endpoints = provider.endpoints();
    let mut refresh_token = initial_refresh_token;
    metrics.seed_provider(provider);

    loop {
        let initial_expiry = state.snapshot().await.expires_at;
        metrics.observe_expires_at(provider, initial_expiry);
        let sleep_for = sleep_until_skew(initial_expiry, policy.refresh_skew, Utc::now());
        tracing::debug!(
            provider = %provider,
            sleep_seconds = sleep_for.as_secs(),
            expires_at = %initial_expiry,
            "worker sleeping until next refresh window",
        );
        if !sleep_or_cancel(sleep_for, &cancel).await {
            tracing::info!(provider = %provider, "worker shutting down");
            return;
        }

        let attempt_outcome = attempt_with_retries(
            &client,
            endpoints,
            &refresh_token,
            &metrics,
            policy,
            &cancel,
        )
        .await;

        match attempt_outcome {
            AttemptOutcome::Shutdown => {
                tracing::info!(provider = %provider, "worker shutting down");
                return;
            }
            AttemptOutcome::Success(outcome) => {
                let new_expiry = outcome.expires_at;
                state.record_success(outcome.access_token, new_expiry).await;
                if let Some(rotated) = outcome.rotated_refresh_token {
                    refresh_token = rotated;
                }
                metrics.record_refresh_success(provider);
                metrics.set_provider_down(provider, false);
                metrics.observe_expires_at(provider, new_expiry);
                tracing::info!(
                    provider = %provider,
                    next_expiry = %new_expiry,
                    "refresh succeeded",
                );
            }
            AttemptOutcome::Exhausted => {
                state.mark_unhealthy().await;
                metrics.set_provider_down(provider, true);
                tracing::warn!(
                    provider = %provider,
                    retries = policy.max_retries,
                    "refresh budget exhausted; provider marked down",
                );
                // Slow-probe until something works. Each probe pays
                // the full retry budget — if every retry inside also
                // fails, we sleep again. Phase B will swap this for a
                // re-auth trigger.
                if !sleep_or_cancel(policy.unhealthy_probe_interval, &cancel).await {
                    return;
                }
            }
        }
    }
}

enum AttemptOutcome {
    Success(RefreshOutcome),
    Exhausted,
    Shutdown,
}

/// Run up to `policy.max_retries + 1` refresh attempts, with backoff
/// + jitter between failed attempts.
///
/// Pulled out of [`run_provider_worker`] for readability — the
/// function is still under the workspace's complexity cap.
async fn attempt_with_retries(
    client: &reqwest::Client,
    endpoints: crate::provider::ProviderEndpoints,
    refresh_token: &str,
    metrics: &Metrics,
    policy: RetryPolicy,
    cancel: &CancellationToken,
) -> AttemptOutcome {
    let provider = endpoints.provider;
    let mut backoff = policy.initial_backoff;

    // `max_retries + 1` total attempts: the first attempt is not a
    // retry. A `max_retries == 0` policy gives one attempt and bails.
    for attempt in 0..=policy.max_retries {
        match refresh_once(client, endpoints, refresh_token).await {
            Ok(outcome) => return AttemptOutcome::Success(outcome),
            Err(RefreshError { reason, message }) => {
                metrics.record_refresh_failure(provider, reason);
                tracing::warn!(
                    provider = %provider,
                    attempt = attempt + 1,
                    max_attempts = policy.max_retries + 1,
                    reason = reason.as_str(),
                    message,
                    "refresh attempt failed",
                );
                if attempt == policy.max_retries {
                    break;
                }
                let with_jitter = apply_jitter(backoff, policy.jitter_ratio);
                if !sleep_or_cancel(with_jitter, cancel).await {
                    return AttemptOutcome::Shutdown;
                }
                backoff = (backoff * 2).min(policy.max_backoff);
            }
        }
    }
    AttemptOutcome::Exhausted
}

/// Compute the duration to sleep before the next refresh attempt
/// based on `expires_at - skew` and the current wall clock.
///
/// Returns [`Duration::ZERO`] when the skew window has already passed
/// (the worker should refresh immediately) or when the expiry is in
/// the past (the same — we are wedged and must retry now).
#[must_use]
pub fn sleep_until_skew(expires_at: DateTime<Utc>, skew: Duration, now: DateTime<Utc>) -> Duration {
    let skew_chrono = chrono::Duration::from_std(skew).unwrap_or_else(|_| chrono::Duration::zero());
    let refresh_at = expires_at - skew_chrono;
    let delta = refresh_at - now;
    if delta <= chrono::Duration::zero() {
        return Duration::ZERO;
    }
    delta.to_std().unwrap_or(Duration::ZERO)
}

/// Sleep for `duration` unless `cancel` flips first. Returns `false`
/// when the cancellation fired (the worker should exit).
async fn sleep_or_cancel(duration: Duration, cancel: &CancellationToken) -> bool {
    tokio::select! {
        () = tokio::time::sleep(duration) => true,
        () = cancel.cancelled() => false,
    }
}

/// Multiply `backoff` by a random factor in
/// `1.0 - jitter ..= 1.0 + jitter`. Bounded to non-negative.
#[must_use]
pub fn apply_jitter(backoff: Duration, jitter: f64) -> Duration {
    if jitter <= 0.0 {
        return backoff;
    }
    let jitter = jitter.clamp(0.0, 1.0);
    let mut rng = rand::thread_rng();
    let factor: f64 = rng.gen_range(1.0 - jitter..=1.0 + jitter);
    let scaled = backoff.as_secs_f64() * factor;
    if scaled <= 0.0 {
        return Duration::ZERO;
    }
    Duration::from_secs_f64(scaled)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sleep_until_skew_returns_positive_for_future_expiry() {
        let now = Utc::now();
        let expires = now + chrono::Duration::seconds(3600);
        let d = sleep_until_skew(expires, Duration::from_secs(120), now);
        // 3600 - 120 = 3480, allow ±2s drift for the test clock.
        assert!((3478..=3482).contains(&d.as_secs()), "got {d:?}");
    }

    #[test]
    fn sleep_until_skew_zero_for_past_expiry() {
        let now = Utc::now();
        let expires = now - chrono::Duration::seconds(10);
        let d = sleep_until_skew(expires, Duration::from_secs(120), now);
        assert_eq!(d, Duration::ZERO);
    }

    #[test]
    fn sleep_until_skew_zero_when_inside_skew_window() {
        let now = Utc::now();
        let expires = now + chrono::Duration::seconds(60); // < 120s skew
        let d = sleep_until_skew(expires, Duration::from_secs(120), now);
        assert_eq!(d, Duration::ZERO);
    }

    #[test]
    fn apply_jitter_is_bounded() {
        let base = Duration::from_secs(10);
        for _ in 0..200 {
            let j = apply_jitter(base, 0.25);
            let s = j.as_secs_f64();
            assert!((7.4..=12.6).contains(&s), "out of band: {s}");
        }
    }

    #[test]
    fn apply_jitter_zero_passes_through() {
        let base = Duration::from_secs(10);
        let j = apply_jitter(base, 0.0);
        assert_eq!(j, base);
    }

    #[tokio::test]
    async fn sleep_or_cancel_returns_false_on_cancel() {
        let cancel = CancellationToken::new();
        let c2 = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            c2.cancel();
        });
        let cont = sleep_or_cancel(Duration::from_secs(60), &cancel).await;
        assert!(!cont);
    }

    #[tokio::test]
    async fn sleep_or_cancel_returns_true_on_completion() {
        let cancel = CancellationToken::new();
        let cont = sleep_or_cancel(Duration::from_millis(5), &cancel).await;
        assert!(cont);
    }
}
