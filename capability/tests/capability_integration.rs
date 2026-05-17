//! Integration tests for the capability service.
//!
//! Verifies:
//!   - Missing env var → `env_var_present=false`, `upstream_ok=false`
//!   - Bearer auth enforced on capability endpoints
//!   - /health unauthenticated
//!   - `schema_version` is "1" on all responses
//!   - /metrics returns Prometheus text with the expected gauge names

#![expect(
    clippy::unwrap_used,
    reason = "test assertions intentionally panic on unexpected errors"
)]

use gm_miner_capability::{
    metrics::build_registry,
    routes::{capability_router, metrics_router},
};

use axum::{
    body::Body,
    http::{Request, StatusCode},
    response::Response,
};
use tower::ServiceExt;

#[tokio::test]
async fn health_is_unauthenticated() {
    let metrics = build_registry();
    let router = capability_router(Some("secret".to_string()), metrics);

    let req = Request::builder()
        .uri("/health")
        .body(Body::empty())
        .unwrap();

    let resp: Response = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn capability_requires_bearer() {
    let metrics = build_registry();
    let router = capability_router(Some("secret".to_string()), metrics);

    let req = Request::builder()
        .uri("/capability/anthropic")
        .body(Body::empty())
        .unwrap();

    let resp: Response = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn capability_wrong_bearer_rejected() {
    let metrics = build_registry();
    let router = capability_router(Some("correct".to_string()), metrics);

    let req = Request::builder()
        .uri("/capability/anthropic")
        .header("Authorization", "Bearer wrong")
        .body(Body::empty())
        .unwrap();

    let resp: Response = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn anthropic_missing_env_var_returns_env_var_present_false() {
    std::env::remove_var("ANTHROPIC_API_KEY");

    let metrics = build_registry();
    let router = capability_router(Some("secret".to_string()), metrics);

    let req = Request::builder()
        .uri("/capability/anthropic")
        .header("Authorization", "Bearer secret")
        .body(Body::empty())
        .unwrap();

    let resp: Response = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["env_var_present"], false);
    assert_eq!(json["upstream_ok"], false);
    assert_eq!(json["provider"], "anthropic");
    assert!(json["error"]
        .as_str()
        .unwrap()
        .contains("ANTHROPIC_API_KEY"));
}

#[tokio::test]
async fn openai_missing_env_var_returns_env_var_present_false() {
    std::env::remove_var("OPENAI_API_KEY");

    let metrics = build_registry();
    let router = capability_router(Some("secret".to_string()), metrics);

    let req = Request::builder()
        .uri("/capability/openai")
        .header("Authorization", "Bearer secret")
        .body(Body::empty())
        .unwrap();

    let resp: Response = router.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["env_var_present"], false);
    assert_eq!(json["provider"], "openai");
}

#[tokio::test]
async fn gemini_missing_env_var_returns_env_var_present_false() {
    std::env::remove_var("GOOGLE_API_KEY");

    let metrics = build_registry();
    let router = capability_router(Some("secret".to_string()), metrics);

    let req = Request::builder()
        .uri("/capability/gemini")
        .header("Authorization", "Bearer secret")
        .body(Body::empty())
        .unwrap();

    let resp: Response = router.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["env_var_present"], false);
    assert_eq!(json["provider"], "gemini");
}

#[tokio::test]
async fn metrics_endpoint_returns_prometheus_text() {
    let registry = build_registry();
    let router = metrics_router(registry);

    let req = Request::builder()
        .uri("/metrics")
        .body(Body::empty())
        .unwrap();

    let resp: Response = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let text = std::str::from_utf8(&body).unwrap();

    assert!(text.contains("gm_miner_inflight_requests"));
    assert!(text.contains("gm_miner_capacity_max"));
}

#[tokio::test]
async fn schema_version_is_1() {
    std::env::remove_var("ANTHROPIC_API_KEY");

    let metrics = build_registry();
    let router = capability_router(Some("tok".to_string()), metrics);

    let req = Request::builder()
        .uri("/capability/anthropic")
        .header("Authorization", "Bearer tok")
        .body(Body::empty())
        .unwrap();

    let resp: Response = router.oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json["schema_version"], "1");
}
