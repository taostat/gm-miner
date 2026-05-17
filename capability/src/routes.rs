//! Axum routers for the capability service.
//!
//! Two routers are created:
//!   `capability_router` — capability/health endpoints; auth middleware applied
//!   `metrics_router`    — /metrics endpoint; no auth (public read-only port)

use axum::{
    extract::State,
    http::StatusCode,
    middleware,
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use std::sync::Arc;

use crate::{
    auth::{require_bearer, BearerState},
    capability,
    metrics::{self, MinerMetrics},
};

/// Shared state for capability routes.
#[derive(Clone)]
struct CapState {
    client: reqwest::Client,
}

/// Build the router that serves `/health` and `/capability/*`.
///
/// # Panics
/// Panics if the underlying TLS stack cannot be initialized (extremely rare;
/// would indicate a system-level misconfiguration).
#[expect(
    clippy::expect_used,
    reason = "only fails on TLS init — system-level misconfiguration"
)]
pub fn capability_router(bearer_token: Option<String>, _registry: Arc<MinerMetrics>) -> Router {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .expect("build reqwest client — system TLS must be available");

    let state = CapState { client };

    let bearer_state = BearerState {
        token: bearer_token,
    };

    // Protected routes require bearer auth.
    let protected = Router::new()
        .route("/capability/anthropic", get(cap_anthropic))
        .route("/capability/openai", get(cap_openai))
        .route("/capability/gemini", get(cap_gemini))
        .layer(middleware::from_fn_with_state(bearer_state, require_bearer))
        .with_state(state.clone());

    // Health is unauthenticated (used by start.sh readiness check).
    let open = Router::new()
        .route("/health", get(health))
        .with_state(state);

    protected.merge(open)
}

/// Build the router that serves /metrics on the public port.
pub fn metrics_router(registry: Arc<MinerMetrics>) -> Router {
    Router::new()
        .route("/metrics", get(metrics_handler))
        .with_state(registry)
}

// ── Handlers ────────────────────────────────────────────────────────────

async fn health() -> impl IntoResponse {
    let version = std::env::var("GM_IMAGE_VERSION").unwrap_or_else(|_| "unknown".into());
    Json(serde_json::json!({
        "status": "ok",
        "image_version": version,
    }))
}

async fn cap_anthropic(State(st): State<CapState>) -> impl IntoResponse {
    let resp = capability::check_anthropic(&st.client).await;
    let status = if resp.upstream_ok || !resp.env_var_present {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(resp))
}

async fn cap_openai(State(st): State<CapState>) -> impl IntoResponse {
    let resp = capability::check_openai(&st.client).await;
    let status = if resp.upstream_ok || !resp.env_var_present {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(resp))
}

async fn cap_gemini(State(st): State<CapState>) -> impl IntoResponse {
    let resp = capability::check_gemini(&st.client).await;
    let status = if resp.upstream_ok || !resp.env_var_present {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(resp))
}

async fn metrics_handler(State(registry): State<Arc<MinerMetrics>>) -> Response {
    let body = metrics::render(&registry);
    (
        StatusCode::OK,
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
        .into_response()
}
