//! HTTP servers — one on the token port, one on the metrics port.
//!
//! Both listeners bind loopback; the only callers are co-located
//! (Envoy on the token port, the registry's prometheus scrape on the
//! metrics port via Envoy's `metrics` listener — see `image/envoy.yaml`
//! for the loopback proxy hop).

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use axum::Router;
use serde::Serialize;

/// Liveness probe — always 200. Each router gets its own copy so the
/// axum type system can resolve the state-type parameter without
/// generics. Inlined; the body is trivial.
async fn healthz_token(State(_): State<TokenAppState>) -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn healthz_metrics(State(_): State<MetricsAppState>) -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

use crate::metrics::Metrics;
use crate::provider::OauthProvider;
use crate::state::{StateRegistry, TokenSnapshot};

/// Shared application state for the token-endpoint router.
#[derive(Clone)]
pub struct TokenAppState {
    pub registry: Arc<StateRegistry>,
}

/// Shared application state for the metrics-endpoint router.
#[derive(Clone)]
pub struct MetricsAppState {
    pub metrics: Metrics,
}

/// Build the axum router that serves the token endpoint Envoy queries
/// on every data-plane request.
pub fn build_token_router(state: TokenAppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz_token))
        .route("/token/{provider}", get(get_token))
        .with_state(state)
}

/// Build the axum router for the Prometheus scrape endpoint.
pub fn build_metrics_router(state: MetricsAppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz_metrics))
        .route("/metrics", get(get_metrics))
        .with_state(state)
}

/// Response body for `GET /token/{provider}`. Camel-case-free,
/// `snake_case` — Envoy's Lua reads it with `cjson.decode`, and the
/// downstream Rust callers do not care.
#[derive(Debug, Serialize)]
struct TokenResponse {
    access_token: String,
    expires_at: String,
    healthy: bool,
}

impl From<TokenSnapshot> for TokenResponse {
    fn from(s: TokenSnapshot) -> Self {
        Self {
            access_token: s.access_token,
            expires_at: s.expires_at.to_rfc3339(),
            healthy: s.healthy,
        }
    }
}

/// `GET /token/{provider}`. 200 with the current snapshot when the
/// provider is enabled and healthy; 503 when the worker has marked it
/// down; 404 when the provider is not enabled on this miner.
async fn get_token(
    State(state): State<TokenAppState>,
    Path(provider_label): Path<String>,
) -> Response {
    let Some(provider) = OauthProvider::from_wire_str(&provider_label) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "unknown provider"})),
        )
            .into_response();
    };
    let Some(cell) = state.registry.get(provider) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "provider not enabled in oauth_subscription mode on this miner",
            })),
        )
            .into_response();
    };
    let snapshot = cell.snapshot().await;
    let healthy = snapshot.healthy;
    // The `healthy` bit only tracks "the worker has not exhausted its
    // retry budget" — it does NOT track whether the token is still
    // valid right now. If the pasted initial token was already expired,
    // or the worker hasn't reached its first refresh yet, the snapshot
    // can be healthy AND carry a token that is past its expiry. Return
    // 503 in that case too — Envoy will surface the provider as down,
    // which is the right signal to the gateway's capacity router.
    let expired = snapshot.expires_at <= chrono::Utc::now();
    let body = TokenResponse::from(snapshot);
    if !healthy || expired {
        // Envoy maps 503 from the sidecar to 503 from its data plane
        // for that provider's route — the gateway's capacity router
        // and the registry's probe both already treat 503 from a
        // miner as "provider unavailable".
        return (StatusCode::SERVICE_UNAVAILABLE, Json(body)).into_response();
    }
    (StatusCode::OK, Json(body)).into_response()
}

/// `GET /metrics`. Prometheus text exposition.
async fn get_metrics(State(state): State<MetricsAppState>) -> Response {
    match state.metrics.encode() {
        Ok(body) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/plain; version=0.0.4")
            .body(Body::from(body))
            .unwrap_or_else(|_| {
                (StatusCode::INTERNAL_SERVER_ERROR, "build response failed").into_response()
            }),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("encode metrics: {e}"),
        )
            .into_response(),
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "tests intentionally panic on unexpected values"
)]
mod tests {
    use super::*;
    use crate::state::ProviderState;
    use axum::body::to_bytes;
    use axum::http::Request;
    use chrono::{Duration, Utc};
    use tower::ServiceExt;

    fn registry_with(provider: OauthProvider, mark_unhealthy: bool) -> Arc<StateRegistry> {
        let cell = ProviderState::new(
            provider,
            "at-1".into(),
            Utc::now() + Duration::seconds(3600),
        );
        if mark_unhealthy {
            // Block on the unhealthy mark synchronously inside a test
            // helper so the response-state assertions later run after
            // the flag is set.
            let cell_clone = cell.clone();
            tokio::runtime::Handle::current().block_on(async move {
                cell_clone.mark_unhealthy().await;
            });
        }
        Arc::new(StateRegistry::from_states([cell]))
    }

    async fn body_string(resp: Response) -> String {
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn healthy_provider_returns_200_with_token() {
        let router = build_token_router(TokenAppState {
            registry: registry_with(OauthProvider::Openai, false),
        });
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/token/openai")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains(r#""access_token":"at-1""#));
        assert!(body.contains(r#""healthy":true"#));
    }

    #[tokio::test]
    async fn unhealthy_provider_returns_503() {
        let registry = {
            let cell = ProviderState::new(
                OauthProvider::Openai,
                "at-1".into(),
                Utc::now() + Duration::seconds(3600),
            );
            cell.mark_unhealthy().await;
            Arc::new(StateRegistry::from_states([cell]))
        };
        let router = build_token_router(TokenAppState { registry });
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/token/openai")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = body_string(resp).await;
        assert!(body.contains(r#""healthy":false"#));
    }

    #[tokio::test]
    async fn unknown_provider_returns_404() {
        let router = build_token_router(TokenAppState {
            registry: registry_with(OauthProvider::Openai, false),
        });
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/token/gemini")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn disabled_provider_returns_404() {
        let router = build_token_router(TokenAppState {
            registry: registry_with(OauthProvider::Openai, false),
        });
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/token/anthropic")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn metrics_endpoint_returns_prometheus_body() {
        let metrics = Metrics::new().unwrap();
        metrics.seed_provider(OauthProvider::Openai);
        metrics.record_refresh_success(OauthProvider::Openai);
        let router = build_metrics_router(MetricsAppState { metrics });
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("gm_miner_oauth_refresh_success_total"));
    }

    #[tokio::test]
    async fn healthz_returns_200() {
        let metrics = Metrics::new().unwrap();
        let router = build_metrics_router(MetricsAppState { metrics });
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
