//! Tests for OAuth refresh-token support against a mocked token endpoint.
//!
//! Covered at the HTTP boundary (the auth-gateway token endpoint is a
//! `wiremock` mock):
//!   - the device-code flow captures `refresh_token` from the token response
//!   - a successful refresh yields a fresh access token
//!   - refresh-token rotation: a rotated `refresh_token` supersedes the old
//!     one, and an omitted one is replaced by the previously stored value
//!   - a rejected refresh (4xx / 5xx) reports `Rejected` so the caller can
//!     fall back to the full device flow rather than aborting

#![expect(
    clippy::expect_used,
    reason = "test assertions intentionally panic on unexpected values"
)]

use gm_miner_cli::auth::{self, RefreshOutcome, TokenResponse};
use wiremock::{
    matchers::{body_string_contains, method, path},
    Mock, MockServer, ResponseTemplate,
};

/// Unwrap a [`RefreshOutcome::Refreshed`], failing the test with a clear
/// message on any other variant.
fn expect_refreshed(outcome: RefreshOutcome) -> TokenResponse {
    match outcome {
        RefreshOutcome::Refreshed(token) => token,
        RefreshOutcome::Rejected => {
            unreachable!("expected RefreshOutcome::Refreshed, got Rejected")
        }
    }
}

// ── Device-code flow captures the refresh token ──────────────────────────────

/// The device-code flow must persist `refresh_token` from the token-endpoint
/// response. Before this change the field was discarded; the regression this
/// guards is a token response that carries a refresh token being parsed into
/// a `TokenResponse` with `refresh_token: None`.
#[tokio::test]
async fn device_flow_captures_refresh_token() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/device/code"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "device_code": "dev-code-1",
            "user_code": "WXYZ-1234",
            "verification_uri": "https://auth.example.com/device",
            "interval": 0,
            "expires_in": 900,
        })))
        .mount(&server)
        .await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "access-from-device-flow",
            "refresh_token": "refresh-from-device-flow",
            "token_type": "Bearer",
            "expires_in": 3180,
        })))
        .mount(&server)
        .await;

    let token = auth::device_login(
        &format!("{}/device/code", server.uri()),
        &format!("{}/token", server.uri()),
        "gm-miner-cli",
        &["openid".to_owned()],
        false,
    )
    .await
    .expect("device flow must complete against the mock");

    assert_eq!(token.access_token, "access-from-device-flow");
    assert_eq!(
        token.refresh_token.as_deref(),
        Some("refresh-from-device-flow"),
        "the refresh token must be captured, not discarded"
    );

    // `to_entry` is what `cmd_login` persists — the refresh token must
    // survive into the persisted `TokenEntry`.
    let entry = token.to_entry();
    assert_eq!(
        entry.refresh_token.as_deref(),
        Some("refresh-from-device-flow"),
        "the persisted TokenEntry must carry the refresh token"
    );
    assert_eq!(
        entry.access_token.as_deref(),
        Some("access-from-device-flow")
    );
    assert!(
        entry.token_expires_at.is_some(),
        "expires_in must be turned into a token_expires_at timestamp"
    );
}

// ── Successful refresh ───────────────────────────────────────────────────────

/// A `200` from the token endpoint for the `refresh_token` grant yields a
/// fresh access token. The request must be the standard OAuth form grant.
#[tokio::test]
async fn refresh_success_returns_new_access_token() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("grant_type=refresh_token"))
        .and(body_string_contains("refresh_token=stored-refresh"))
        .and(body_string_contains("client_id=gm-miner-cli"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "fresh-access-token",
            "refresh_token": "rotated-refresh-token",
            "token_type": "Bearer",
            "expires_in": 3180,
        })))
        .mount(&server)
        .await;

    let outcome = auth::refresh_token(
        &format!("{}/token", server.uri()),
        "gm-miner-cli",
        "stored-refresh",
    )
    .await
    .expect("a 200 refresh must not error");

    let token = expect_refreshed(outcome);
    assert_eq!(token.access_token, "fresh-access-token");

    let entry = token.to_entry();
    assert_eq!(entry.access_token.as_deref(), Some("fresh-access-token"));
    assert!(
        entry.token_expires_at.is_some(),
        "the refreshed token must carry a new expiry"
    );
}

// ── Refresh-token rotation ───────────────────────────────────────────────────

/// Many OAuth servers rotate the refresh token on every refresh. A rotated
/// `refresh_token` in the response must supersede the stored one.
#[tokio::test]
async fn refresh_rotation_persists_new_refresh_token() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "fresh-access-token",
            "refresh_token": "rotated-refresh-token",
            "token_type": "Bearer",
            "expires_in": 3180,
        })))
        .mount(&server)
        .await;

    let outcome = auth::refresh_token(
        &format!("{}/token", server.uri()),
        "gm-miner-cli",
        "old-refresh-token",
    )
    .await
    .expect("refresh must not error");

    let token = expect_refreshed(outcome);

    // `to_entry_keeping` is the persistence path used by `ensure_fresh_token`.
    // The rotated token must replace the stored one.
    let entry = token.to_entry_keeping(Some("old-refresh-token".to_owned()));
    assert_eq!(
        entry.refresh_token.as_deref(),
        Some("rotated-refresh-token"),
        "a rotated refresh token must replace the stored one"
    );
}

/// When the auth-gateway does not rotate the refresh token (no `refresh_token`
/// field in the response), the previously stored token must be kept — clearing
/// it would leave the next refresh with nothing to present.
#[tokio::test]
async fn refresh_without_rotation_keeps_stored_refresh_token() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "fresh-access-token",
            "token_type": "Bearer",
            "expires_in": 3180,
        })))
        .mount(&server)
        .await;

    let outcome = auth::refresh_token(
        &format!("{}/token", server.uri()),
        "gm-miner-cli",
        "stored-refresh-token",
    )
    .await
    .expect("refresh must not error");

    let token = expect_refreshed(outcome);
    assert_eq!(
        token.refresh_token, None,
        "the mock response carried no refresh_token"
    );

    let entry = token.to_entry_keeping(Some("stored-refresh-token".to_owned()));
    assert_eq!(
        entry.refresh_token.as_deref(),
        Some("stored-refresh-token"),
        "an un-rotated refresh must keep the previously stored token"
    );
}

// ── Refresh failure → device-flow fallback ───────────────────────────────────

/// A revoked / expired / invalid refresh token surfaces from the token
/// endpoint as `400 invalid_grant`. The CLI must treat this as `Rejected`
/// (a recoverable state — fall back to the device flow), not an `Err`.
#[tokio::test]
async fn refresh_rejected_on_invalid_grant() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "invalid_grant",
            "error_description": "Refresh token has been revoked",
        })))
        .mount(&server)
        .await;

    let outcome = auth::refresh_token(
        &format!("{}/token", server.uri()),
        "gm-miner-cli",
        "revoked-refresh-token",
    )
    .await
    .expect("a 400 must be a Rejected outcome, not a transport error");

    assert!(
        matches!(outcome, RefreshOutcome::Rejected),
        "a rejected refresh token must yield Rejected so the caller can \
         fall back to the device flow; got {outcome:?}"
    );
}

/// A client not permitted the `refresh_token` grant gets
/// `400 unsupported_grant_type` from the auth-gateway. This is the failure
/// mode if the `gm-miner-cli` OAuth client is not configured for refresh —
/// it must still degrade to the device flow rather than crash.
#[tokio::test]
async fn refresh_rejected_on_unsupported_grant_type() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "unsupported_grant_type",
            "error_description": "This client is not authorized for the requested grant_type",
        })))
        .mount(&server)
        .await;

    let outcome = auth::refresh_token(
        &format!("{}/token", server.uri()),
        "gm-miner-cli",
        "some-refresh-token",
    )
    .await
    .expect("unsupported_grant_type must be Rejected, not a transport error");

    assert!(
        matches!(outcome, RefreshOutcome::Rejected),
        "unsupported_grant_type must yield Rejected; got {outcome:?}"
    );
}

/// A `5xx` from the token endpoint is also `Rejected`: the device flow is the
/// only remaining path to a valid token, so the caller should fall back to it
/// rather than abort with a transport error.
#[tokio::test]
async fn refresh_rejected_on_server_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let outcome = auth::refresh_token(
        &format!("{}/token", server.uri()),
        "gm-miner-cli",
        "some-refresh-token",
    )
    .await
    .expect("a 503 must be a Rejected outcome");

    assert!(
        matches!(outcome, RefreshOutcome::Rejected),
        "a 5xx must yield Rejected; got {outcome:?}"
    );
}
