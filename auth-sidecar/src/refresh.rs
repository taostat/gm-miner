//! Single-shot OAuth token refresh against the upstream provider.
//!
//! Sends `grant_type=refresh_token` to the provider's token endpoint
//! and decodes the `{ access_token, expires_in, refresh_token? }`
//! envelope. `expires_in` is normalised to an absolute
//! `expires_at: DateTime<Utc>`.
//!
//! The HTTP call is taken via a [`reqwest::Client`] reference passed in
//! by the caller so tests can point the client at a wiremock server.

use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Deserialize;
use thiserror::Error;

use crate::provider::{ProviderEndpoints, RefreshEncoding};

/// Classification of why a refresh failed. Drives both backoff
/// behaviour and the Prometheus `reason` label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureReason {
    /// TCP / TLS error reaching the upstream — typically a transient.
    Network,
    /// Upstream answered 4xx with a body that names `invalid_grant`,
    /// `expired`, or `revoked` — the refresh token is dead and the
    /// operator must paste a new one.
    Unauthorized,
    /// Upstream answered 429 — back off and try again later.
    RateLimited,
    /// Upstream answered with a body the client could not decode.
    Malformed,
}

impl FailureReason {
    /// Lowercase wire identifier used as the Prometheus `reason` label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Unauthorized => "unauthorized",
            Self::RateLimited => "rate_limited",
            Self::Malformed => "malformed",
        }
    }
}

/// Refresh-step error. Carries a [`FailureReason`] so the metrics
/// label and the worker's backoff path can both inspect it.
#[derive(Debug, Error)]
#[error("{reason:?}: {message}")]
pub struct RefreshError {
    pub reason: FailureReason,
    pub message: String,
}

impl RefreshError {
    fn new(reason: FailureReason, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
        }
    }
}

/// Result of one successful refresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshOutcome {
    pub access_token: String,
    pub expires_at: DateTime<Utc>,
    /// Some providers (research: both) issue a new refresh token on
    /// every refresh — token rotation. When `Some`, the worker will
    /// rotate its stored token to this value for subsequent calls.
    /// Persisting the new token across sidecar restarts is Phase B;
    /// for Phase A the worker keeps the rotated token in memory and
    /// loses it on container restart, which falls back to the env
    /// var's original refresh token (still valid until the provider
    /// rotates it again).
    pub rotated_refresh_token: Option<String>,
}

/// Run one refresh exchange against `endpoints` using `refresh_token`.
///
/// `client` is an injected [`reqwest::Client`] so tests can point at
/// wiremock.
///
/// # Errors
/// See [`FailureReason`].
pub async fn refresh_once(
    client: &reqwest::Client,
    endpoints: ProviderEndpoints,
    refresh_token: &str,
) -> Result<RefreshOutcome, RefreshError> {
    let request_builder = build_refresh_request(client, endpoints, refresh_token);

    let response = request_builder
        .send()
        .await
        .map_err(|e| RefreshError::new(FailureReason::Network, e.to_string()))?;
    let status = response.status();

    let body_bytes = response
        .bytes()
        .await
        .map_err(|e| RefreshError::new(FailureReason::Network, format!("read body: {e}")))?;

    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        return Err(RefreshError::new(
            FailureReason::RateLimited,
            format!("upstream 429: {}", String::from_utf8_lossy(&body_bytes)),
        ));
    }

    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(RefreshError::new(
            FailureReason::Unauthorized,
            format!(
                "upstream {status}: {}",
                String::from_utf8_lossy(&body_bytes)
            ),
        ));
    }

    if !status.is_success() {
        let body_str = String::from_utf8_lossy(&body_bytes);
        let reason = classify_error_body(&body_str);
        return Err(RefreshError::new(
            reason,
            format!("upstream {status}: {body_str}"),
        ));
    }

    let parsed: RawRefreshResponse = serde_json::from_slice(&body_bytes).map_err(|e| {
        RefreshError::new(
            FailureReason::Malformed,
            format!(
                "decode upstream response: {e} (body: {})",
                String::from_utf8_lossy(&body_bytes),
            ),
        )
    })?;

    parsed.into_outcome(Utc::now())
}

/// Build the refresh HTTP request envelope per the provider's
/// encoding. Pulled out so `refresh_once` body fits in one screen.
fn build_refresh_request(
    client: &reqwest::Client,
    endpoints: ProviderEndpoints,
    refresh_token: &str,
) -> reqwest::RequestBuilder {
    let base = client
        .post(endpoints.refresh_url)
        // Cap each refresh attempt at 30s. The worker layer adds its
        // own outer retry budget; this is the per-attempt bound so a
        // hung connection cannot wedge the refresh task forever.
        .timeout(Duration::from_secs(30));

    match endpoints.encoding {
        RefreshEncoding::Form => base.form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", endpoints.client_id),
        ]),
        RefreshEncoding::Json => base.json(&serde_json::json!({
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": endpoints.client_id,
        })),
    }
}

/// Wire envelope returned by both providers' token endpoints.
///
/// `expires_in` is seconds-from-now (OAuth standard). Some providers
/// also issue `expires_at` directly — accepted defensively, but we
/// re-derive everything from `expires_in` when both are present, on
/// the principle that `expires_in` is what the server is asserting
/// right now (the clocks can drift).
#[derive(Debug, Deserialize)]
struct RawRefreshResponse {
    access_token: Option<String>,
    expires_in: Option<i64>,
    /// Anthropic includes an `expires_at` (ms) — accepted as a
    /// fallback when `expires_in` is missing.
    expires_at: Option<i64>,
    refresh_token: Option<String>,
}

impl RawRefreshResponse {
    fn into_outcome(self, now: DateTime<Utc>) -> Result<RefreshOutcome, RefreshError> {
        let Some(access_token) = self.access_token else {
            return Err(RefreshError::new(
                FailureReason::Malformed,
                "upstream response missing access_token",
            ));
        };
        if access_token.trim().is_empty() {
            return Err(RefreshError::new(
                FailureReason::Malformed,
                "upstream response has empty access_token",
            ));
        }

        let expires_at = match (self.expires_in, self.expires_at) {
            (Some(seconds), _) => now
                .checked_add_signed(chrono::Duration::seconds(seconds))
                .ok_or_else(|| {
                    RefreshError::new(
                        FailureReason::Malformed,
                        format!("expires_in out of range: {seconds}"),
                    )
                })?,
            (None, Some(epoch_ms)) => {
                DateTime::<Utc>::from_timestamp_millis(epoch_ms).ok_or_else(|| {
                    RefreshError::new(
                        FailureReason::Malformed,
                        format!("expires_at (ms) out of range: {epoch_ms}"),
                    )
                })?
            }
            (None, None) => {
                return Err(RefreshError::new(
                    FailureReason::Malformed,
                    "upstream response missing both expires_in and expires_at",
                ))
            }
        };

        Ok(RefreshOutcome {
            access_token,
            expires_at,
            rotated_refresh_token: self.refresh_token,
        })
    }
}

/// Classify a non-2xx response body that did not match a more specific
/// status code (e.g. 4xx with an OAuth error envelope).
fn classify_error_body(body: &str) -> FailureReason {
    let lower = body.to_ascii_lowercase();
    if lower.contains("invalid_grant")
        || lower.contains("invalid_token")
        || lower.contains("revoked")
        || lower.contains("expired")
    {
        FailureReason::Unauthorized
    } else if lower.contains("rate") {
        FailureReason::RateLimited
    } else {
        FailureReason::Malformed
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "tests intentionally panic on unexpected values"
)]
mod tests {
    use super::*;
    use crate::provider::OauthProvider;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn test_client() -> reqwest::Client {
        reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
    }

    fn ep_pointing_at(url: &str, encoding: RefreshEncoding) -> ProviderEndpoints {
        // The struct stores `'static` strings; tests build a
        // `Box::leak`ed clone so wiremock's per-test base URL works
        // without changing the prod signature.
        ProviderEndpoints {
            provider: OauthProvider::Openai,
            refresh_url: Box::leak(url.to_owned().into_boxed_str()),
            client_id: "test-client-id",
            encoding,
        }
    }

    #[tokio::test]
    async fn success_response_decodes_into_outcome() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(header("content-type", "application/x-www-form-urlencoded"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "new-at",
                "expires_in": 3600,
                "refresh_token": "rotated-rt",
            })))
            .mount(&mock)
            .await;

        let ep = ep_pointing_at(&format!("{}/token", mock.uri()), RefreshEncoding::Form);
        let outcome = refresh_once(&test_client(), ep, "old-rt").await.unwrap();
        assert_eq!(outcome.access_token, "new-at");
        assert_eq!(outcome.rotated_refresh_token.as_deref(), Some("rotated-rt"));
        // 3600 seconds in the future — allow a 60-second drift window
        // for the test runner.
        let drift = (outcome.expires_at - Utc::now()).num_seconds();
        assert!(
            (3540..=3660).contains(&drift),
            "expected ~3600s drift, got {drift}",
        );
    }

    #[tokio::test]
    async fn json_encoded_request_for_anthropic_shape() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(header("content-type", "application/json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "anth-at",
                "expires_in": 1800,
            })))
            .mount(&mock)
            .await;

        let ep = ep_pointing_at(&format!("{}/token", mock.uri()), RefreshEncoding::Json);
        let outcome = refresh_once(&test_client(), ep, "rt").await.unwrap();
        assert_eq!(outcome.access_token, "anth-at");
        assert!(outcome.rotated_refresh_token.is_none());
    }

    #[tokio::test]
    async fn upstream_401_maps_to_unauthorized() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(401)
                    .set_body_json(serde_json::json!({"error": "invalid_grant"})),
            )
            .mount(&mock)
            .await;

        let ep = ep_pointing_at(&format!("{}/token", mock.uri()), RefreshEncoding::Form);
        let err = refresh_once(&test_client(), ep, "rt").await.unwrap_err();
        assert_eq!(err.reason, FailureReason::Unauthorized);
    }

    #[tokio::test]
    async fn upstream_429_maps_to_rate_limited() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&mock)
            .await;

        let ep = ep_pointing_at(&format!("{}/token", mock.uri()), RefreshEncoding::Form);
        let err = refresh_once(&test_client(), ep, "rt").await.unwrap_err();
        assert_eq!(err.reason, FailureReason::RateLimited);
    }

    #[tokio::test]
    async fn malformed_response_body_is_classified() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&mock)
            .await;

        let ep = ep_pointing_at(&format!("{}/token", mock.uri()), RefreshEncoding::Form);
        let err = refresh_once(&test_client(), ep, "rt").await.unwrap_err();
        assert_eq!(err.reason, FailureReason::Malformed);
    }

    #[tokio::test]
    async fn body_invalid_grant_classified_as_unauthorized() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(400)
                    .set_body_json(serde_json::json!({"error": "invalid_grant"})),
            )
            .mount(&mock)
            .await;

        let ep = ep_pointing_at(&format!("{}/token", mock.uri()), RefreshEncoding::Form);
        let err = refresh_once(&test_client(), ep, "rt").await.unwrap_err();
        assert_eq!(err.reason, FailureReason::Unauthorized);
    }

    #[tokio::test]
    async fn empty_access_token_is_malformed() {
        let mock = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "  ",
                "expires_in": 3600,
            })))
            .mount(&mock)
            .await;

        let ep = ep_pointing_at(&format!("{}/token", mock.uri()), RefreshEncoding::Form);
        let err = refresh_once(&test_client(), ep, "rt").await.unwrap_err();
        assert_eq!(err.reason, FailureReason::Malformed);
    }

    #[tokio::test]
    async fn expires_in_missing_falls_back_to_expires_at_ms() {
        let mock = MockServer::start().await;
        let future_ms: i64 = 1_900_000_000_000;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "at",
                "expires_at": future_ms,
            })))
            .mount(&mock)
            .await;

        let ep = ep_pointing_at(&format!("{}/token", mock.uri()), RefreshEncoding::Form);
        let outcome = refresh_once(&test_client(), ep, "rt").await.unwrap();
        let expected = DateTime::<Utc>::from_timestamp_millis(future_ms).unwrap();
        assert_eq!(outcome.expires_at, expected);
    }
}
